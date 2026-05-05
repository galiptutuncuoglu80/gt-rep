from __future__ import annotations

import csv
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.prompt import Confirm
from rich.table import Table

from .account import AccountSnapshot, PositionInfo, fetch_account, fetch_positions
from .config import CONFIG, SIGNAL_DIR
from .ibkr_client import IBKRClient
from .logger import get_logger
from .risk import RiskDecision, RiskGuard
from .strategy import Signal, build_strategy

log = get_logger(__name__)
console = Console()


def _signal_log_path() -> Path:
    return SIGNAL_DIR / f"signals-{datetime.now(timezone.utc):%Y%m%d}.csv"


def _append_signal_log(signal: Signal, decision: RiskDecision, status: str) -> None:
    path = _signal_log_path()
    write_header = not path.exists()
    with path.open("a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if write_header:
            w.writerow([
                "ts_utc", "symbol", "strategy", "side", "price", "stop", "tp",
                "reason", "allowed", "qty", "risk_per_share", "risk_dollars",
                "decision_reason", "status",
            ])
        w.writerow([
            signal.timestamp.isoformat(), signal.symbol, signal.strategy, signal.side,
            f"{signal.price:.4f}",
            f"{signal.stop:.4f}" if signal.stop else "",
            f"{signal.take_profit:.4f}" if signal.take_profit else "",
            signal.reason, decision.allowed, decision.suggested_qty,
            f"{decision.risk_per_share:.4f}", f"{decision.risk_dollars:.2f}",
            decision.reason, status,
        ])


def _render_summary(snap: AccountSnapshot, positions: list[PositionInfo]) -> None:
    t = Table(title="Hesap Özeti", show_lines=False)
    t.add_column("Alan"); t.add_column("Değer", justify="right")
    t.add_row("Hesap", snap.account or "-")
    t.add_row("NLV", f"${snap.net_liquidation:,.2f}")
    t.add_row("Nakit", f"${snap.cash:,.2f}")
    t.add_row("Alım Gücü", f"${snap.buying_power:,.2f}")
    t.add_row("Günlük PnL", f"${snap.total_pnl_day:,.2f} ({snap.total_pnl_day_pct:.2%})")
    t.add_row("Açık Pozisyon", str(len(positions)))
    console.print(t)

    if positions:
        pt = Table(title="Pozisyonlar")
        for col in ("Sembol", "Miktar", "Ortalama", "Son", "Piyasa Değeri", "PnL"):
            pt.add_column(col, justify="right" if col != "Sembol" else "left")
        for p in positions:
            pt.add_row(
                p.symbol, f"{p.quantity:g}", f"${p.avg_cost:.2f}",
                f"${p.market_price:.2f}", f"${p.market_value:,.2f}",
                f"${p.unrealized_pnl:,.2f}",
            )
        console.print(pt)


def run_signals(
    client: IBKRClient,
    strategy_name: str,
    symbols: tuple[str, ...] | None = None,
    auto_yes: bool = False,
) -> list[dict]:
    """Tek bir tarama çevrimi: hesap çek, her sembol için strateji + risk değerlendir,
    onaylı sinyalleri logla. Hiçbir emir göndermez — bu kasıtlı ve güvenlik için.
    """
    symbols = symbols or CONFIG.universe.symbols
    strategy = build_strategy(strategy_name)
    guard = RiskGuard()

    snap = fetch_account(client)
    positions = fetch_positions(client)
    _render_summary(snap, positions)

    if guard.daily_loss_breached(snap):
        console.print(
            f"[bold red]🛑 Günlük kayıp limiti aşıldı "
            f"({snap.total_pnl_day_pct:.2%}). Yeni sinyal değerlendirilmeyecek.[/]"
        )
        return []

    results: list[dict] = []
    for symbol in symbols:
        try:
            df = client.historical_bars(symbol, duration="180 D", bar_size="1 day")
        except Exception as e:
            log.warning(f"{symbol} veri hatası: {e}")
            continue
        if df is None or df.empty:
            log.warning(f"{symbol} için bar verisi yok, atlandı")
            continue

        signal = strategy.evaluate(symbol, df)
        decision = guard.assess(signal, snap, positions)

        if not signal.is_actionable():
            log.info(f"{symbol} HOLD ({signal.reason})")
            continue

        console.rule(f"[bold]{symbol} {signal.side}[/]")
        console.print(
            f"Strateji: [cyan]{signal.strategy}[/]  |  Fiyat: [bold]${signal.price:.2f}[/]  "
            f"Stop: {signal.stop and f'${signal.stop:.2f}'}  "
            f"Hedef: {signal.take_profit and f'${signal.take_profit:.2f}'}\n"
            f"Sebep: {signal.reason}\n"
            f"Risk: {decision.reason}"
        )

        status = "skipped"
        if decision.allowed:
            approve = auto_yes or Confirm.ask(
                f"[yellow]{symbol} {signal.side} {decision.suggested_qty} adet olarak loglansın mı?[/]",
                default=False,
            )
            status = "approved" if approve else "declined"
        else:
            console.print("[red]Risk reddetti — sinyal sadece kayda alınıyor.[/]")
            status = "rejected"

        _append_signal_log(signal, decision, status)
        results.append({"signal": asdict(signal), "decision": asdict(decision), "status": status})

    console.print(f"\n[dim]Sinyaller şuraya yazıldı:[/] {_signal_log_path()}")
    return results

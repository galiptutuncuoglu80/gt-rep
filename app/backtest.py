from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

import numpy as np
import pandas as pd
import yfinance as yf
from rich.console import Console
from rich.table import Table

from .config import CONFIG
from .logger import get_logger
from .strategy import Strategy, build_strategy

log = get_logger(__name__)
console = Console()


@dataclass
class Trade:
    symbol: str
    side: str
    entry_date: datetime
    entry_price: float
    exit_date: datetime
    exit_price: float
    qty: float
    pnl: float
    pnl_pct: float
    reason: str


@dataclass
class BacktestResult:
    symbol: str
    strategy: str
    start: datetime
    end: datetime
    trades: list[Trade] = field(default_factory=list)
    equity_curve: pd.Series | None = None
    starting_equity: float = 100_000.0

    @property
    def total_return_pct(self) -> float:
        if self.equity_curve is None or len(self.equity_curve) == 0:
            return 0.0
        return self.equity_curve.iloc[-1] / self.starting_equity - 1.0

    @property
    def win_rate(self) -> float:
        if not self.trades:
            return 0.0
        wins = sum(1 for t in self.trades if t.pnl > 0)
        return wins / len(self.trades)

    @property
    def profit_factor(self) -> float:
        gains = sum(t.pnl for t in self.trades if t.pnl > 0)
        losses = -sum(t.pnl for t in self.trades if t.pnl < 0)
        if losses <= 0:
            return float("inf") if gains > 0 else 0.0
        return gains / losses

    @property
    def max_drawdown_pct(self) -> float:
        if self.equity_curve is None or len(self.equity_curve) == 0:
            return 0.0
        eq = self.equity_curve
        peak = eq.cummax()
        dd = (eq - peak) / peak
        return float(dd.min())


def _download(symbol: str, start: str, end: str | None) -> pd.DataFrame:
    df = yf.download(symbol, start=start, end=end, auto_adjust=True, progress=False)
    if df.empty:
        return df
    if isinstance(df.columns, pd.MultiIndex):
        df.columns = df.columns.get_level_values(0)
    df = df.rename(columns=str.lower)
    return df[["open", "high", "low", "close", "volume"]].dropna()


def backtest_symbol(
    symbol: str,
    strategy_name: str,
    start: str,
    end: str | None = None,
    starting_equity: float = 100_000.0,
    risk_per_trade_pct: float = 0.005,
) -> BacktestResult:
    """Sadece long-only, tek pozisyon. Stop ve hedef ATR tabanlı (strategy belirler)."""
    df = _download(symbol, start, end)
    if df.empty:
        log.warning(f"{symbol}: veri yok")
        return BacktestResult(symbol, strategy_name, pd.Timestamp(start),
                              pd.Timestamp(end or start), [], None, starting_equity)

    strategy: Strategy = build_strategy(strategy_name)
    equity = starting_equity
    cash = starting_equity
    pos_qty = 0.0
    pos_entry = 0.0
    pos_stop = 0.0
    pos_tp = 0.0
    pos_entry_date: datetime | None = None
    trades: list[Trade] = []
    equity_curve: list[float] = []
    dates: list[datetime] = []

    # Sinyali her bar yeniden değerlendir; emirleri sonraki bar açılışında doldurmuş gibi modelle.
    min_lookback = max(CONFIG.strategy.sma_slow, CONFIG.strategy.rsi_period) + 2
    for i in range(min_lookback, len(df)):
        window = df.iloc[: i + 1]
        bar = df.iloc[i]
        next_open = df.iloc[i + 1]["open"] if i + 1 < len(df) else bar["close"]

        if pos_qty > 0:
            exit_price = None
            reason = ""
            if bar["low"] <= pos_stop:
                exit_price = pos_stop
                reason = "stop"
            elif bar["high"] >= pos_tp:
                exit_price = pos_tp
                reason = "hedef"
            if exit_price is not None:
                pnl = (exit_price - pos_entry) * pos_qty
                cash += pos_qty * exit_price
                trades.append(Trade(
                    symbol=symbol, side="LONG",
                    entry_date=pos_entry_date, entry_price=pos_entry,
                    exit_date=bar.name.to_pydatetime(), exit_price=float(exit_price),
                    qty=pos_qty, pnl=pnl, pnl_pct=pnl / (pos_entry * pos_qty),
                    reason=reason,
                ))
                pos_qty = 0.0

        signal = strategy.evaluate(symbol, window)
        if pos_qty == 0 and signal.side == "BUY" and signal.stop and signal.take_profit:
            risk_per_share = signal.price - signal.stop
            if risk_per_share > 0:
                risk_dollars = equity * risk_per_trade_pct
                qty = int(risk_dollars // risk_per_share)
                if qty > 0 and qty * next_open <= cash:
                    pos_qty = qty
                    pos_entry = float(next_open)
                    pos_stop = float(signal.stop)
                    pos_tp = float(signal.take_profit)
                    pos_entry_date = (
                        df.iloc[i + 1].name.to_pydatetime()
                        if i + 1 < len(df)
                        else bar.name.to_pydatetime()
                    )
                    cash -= pos_qty * pos_entry

        mark = pos_qty * float(bar["close"]) if pos_qty > 0 else 0.0
        equity = cash + mark
        equity_curve.append(equity)
        dates.append(bar.name.to_pydatetime())

    eq = pd.Series(equity_curve, index=pd.Index(dates, name="date"))
    return BacktestResult(
        symbol=symbol, strategy=strategy_name,
        start=df.index[0].to_pydatetime(), end=df.index[-1].to_pydatetime(),
        trades=trades, equity_curve=eq, starting_equity=starting_equity,
    )


def print_result(r: BacktestResult) -> None:
    t = Table(title=f"Backtest: {r.symbol} / {r.strategy}")
    t.add_column("Metrik"); t.add_column("Değer", justify="right")
    t.add_row("Aralık", f"{r.start:%Y-%m-%d} → {r.end:%Y-%m-%d}")
    t.add_row("İşlem", str(len(r.trades)))
    t.add_row("Kazanma Oranı", f"{r.win_rate:.1%}")
    t.add_row("Profit Factor", f"{r.profit_factor:.2f}" if np.isfinite(r.profit_factor) else "∞")
    t.add_row("Toplam Getiri", f"{r.total_return_pct:.2%}")
    t.add_row("Max Drawdown", f"{r.max_drawdown_pct:.2%}")
    console.print(t)

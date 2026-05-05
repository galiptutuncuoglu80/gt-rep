from __future__ import annotations

import click
from rich.console import Console

from .backtest import backtest_symbol, print_result
from .config import CONFIG
from .ibkr_client import ibkr_session
from .logger import get_logger
from .signal_runner import run_signals
from .strategy import STRATEGIES

console = Console()
log = get_logger(__name__)


@click.group()
def cli() -> None:
    """IBKR Sinyal & Risk Asistanı (paper-trading öncelikli, manuel onay)."""


@cli.command()
def monitor() -> None:
    """Hesap özeti ve mevcut pozisyonları göster."""
    from .account import fetch_account, fetch_positions
    from .signal_runner import _render_summary

    with ibkr_session() as client:
        snap = fetch_account(client)
        positions = fetch_positions(client)
        _render_summary(snap, positions)


@cli.command()
@click.option(
    "--strategy", "strategy_name",
    type=click.Choice(sorted(STRATEGIES)), default="sma_crossover", show_default=True,
)
@click.option("--symbols", default=None, help="Virgülle ayrılmış semboller (boşsa universe).")
@click.option("--yes", "auto_yes", is_flag=True, help="Tüm onayları otomatik kabul et (test için).")
def signal(strategy_name: str, symbols: str | None, auto_yes: bool) -> None:
    """Sinyal taraması çalıştır. Hiçbir emir göndermez — sadece logla + onay."""
    sym_tuple = tuple(s.strip().upper() for s in symbols.split(",")) if symbols else None
    with ibkr_session() as client:
        run_signals(client, strategy_name, symbols=sym_tuple, auto_yes=auto_yes)


@cli.command()
@click.argument("symbol")
@click.option(
    "--strategy", "strategy_name",
    type=click.Choice(sorted(STRATEGIES)), default="sma_crossover", show_default=True,
)
@click.option("--start", default="2022-01-01", show_default=True)
@click.option("--end", default=None)
@click.option("--equity", default=100_000.0, show_default=True)
def backtest(symbol: str, strategy_name: str, start: str, end: str | None, equity: float) -> None:
    """Tek sembol üzerinde backtest çalıştır (yfinance verisiyle)."""
    result = backtest_symbol(symbol.upper(), strategy_name, start, end, starting_equity=equity)
    print_result(result)


@cli.command()
def config_show() -> None:
    """Aktif konfigürasyonu yazdır."""
    console.print(CONFIG)


if __name__ == "__main__":
    cli()

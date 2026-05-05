from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

ROOT = Path(__file__).resolve().parent.parent
LOG_DIR = ROOT / "logs"
SIGNAL_DIR = ROOT / "signals"
LOG_DIR.mkdir(exist_ok=True)
SIGNAL_DIR.mkdir(exist_ok=True)


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "y", "on"}


@dataclass(frozen=True)
class IBKRConfig:
    host: str = os.getenv("IBKR_HOST", "127.0.0.1")
    # 7497 = TWS paper, 4002 = Gateway paper. Live ports (7496/4001) are intentionally
    # NOT defaulted — flipping to live must be a deliberate config change.
    port: int = int(os.getenv("IBKR_PORT", "7497"))
    client_id: int = int(os.getenv("IBKR_CLIENT_ID", "11"))
    account: str = os.getenv("IBKR_ACCOUNT", "")
    paper: bool = _env_bool("IBKR_PAPER", True)


@dataclass(frozen=True)
class RiskConfig:
    daily_loss_limit_pct: float = 0.02      # %2 günlük kayıp limiti — sert durdurma
    per_trade_risk_pct: float = 0.005       # işlem başına sermayenin %0.5'i risk
    max_open_positions: int = 5
    max_position_pct: float = 0.10          # tek pozisyon NLV'nin max %10'u
    min_cash_buffer_pct: float = 0.10       # nakit tamponu


@dataclass(frozen=True)
class UniverseConfig:
    # Başlangıç için likit US ETF/hisse sepeti. İstediğin gibi genişletebilirsin.
    symbols: tuple[str, ...] = (
        "SPY", "QQQ", "AAPL", "MSFT", "NVDA",
        "AMZN", "META", "GOOGL", "TSLA", "AMD",
    )
    exchange: str = "SMART"
    currency: str = "USD"


@dataclass(frozen=True)
class StrategyConfig:
    sma_fast: int = 20
    sma_slow: int = 50
    rsi_period: int = 14
    rsi_oversold: float = 30.0
    rsi_overbought: float = 70.0
    atr_period: int = 14
    atr_stop_mult: float = 2.0


@dataclass(frozen=True)
class AppConfig:
    ibkr: IBKRConfig = field(default_factory=IBKRConfig)
    risk: RiskConfig = field(default_factory=RiskConfig)
    universe: UniverseConfig = field(default_factory=UniverseConfig)
    strategy: StrategyConfig = field(default_factory=StrategyConfig)


CONFIG = AppConfig()

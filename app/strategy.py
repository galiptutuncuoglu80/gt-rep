from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import Literal

import pandas as pd

from .config import CONFIG, StrategyConfig
from .indicators import atr, rsi, sma

Side = Literal["BUY", "SELL", "HOLD"]


@dataclass
class Signal:
    symbol: str
    side: Side
    price: float
    stop: float | None
    take_profit: float | None
    reason: str
    strategy: str
    timestamp: datetime

    def is_actionable(self) -> bool:
        return self.side in ("BUY", "SELL")


class Strategy(ABC):
    name: str = "base"

    def __init__(self, cfg: StrategyConfig = CONFIG.strategy) -> None:
        self.cfg = cfg

    @abstractmethod
    def evaluate(self, symbol: str, df: pd.DataFrame) -> Signal:
        """Son baroyu baz alarak sinyal üret. df sütunları: open/high/low/close/volume, tarih index."""


class SMACrossoverStrategy(Strategy):
    """Klasik SMA hızlı/yavaş kırılımı; ATR tabanlı stop/hedef."""

    name = "sma_crossover"

    def evaluate(self, symbol: str, df: pd.DataFrame) -> Signal:
        cfg = self.cfg
        close = df["close"]
        fast = sma(close, cfg.sma_fast)
        slow = sma(close, cfg.sma_slow)
        atr_val = atr(df, cfg.atr_period)

        if len(df) < cfg.sma_slow + 2 or fast.iloc[-2:].isna().any() or slow.iloc[-2:].isna().any():
            return Signal(symbol, "HOLD", float(close.iloc[-1]), None, None,
                          "yetersiz veri", self.name, datetime.utcnow())

        prev_diff = fast.iloc[-2] - slow.iloc[-2]
        curr_diff = fast.iloc[-1] - slow.iloc[-1]
        price = float(close.iloc[-1])
        a = float(atr_val.iloc[-1]) if not pd.isna(atr_val.iloc[-1]) else 0.0

        if prev_diff <= 0 < curr_diff:
            stop = price - cfg.atr_stop_mult * a if a else None
            tp = price + 2 * cfg.atr_stop_mult * a if a else None
            return Signal(symbol, "BUY", price, stop, tp,
                          f"SMA{cfg.sma_fast} {cfg.sma_slow} üstüne kırıldı",
                          self.name, datetime.utcnow())
        if prev_diff >= 0 > curr_diff:
            stop = price + cfg.atr_stop_mult * a if a else None
            tp = price - 2 * cfg.atr_stop_mult * a if a else None
            return Signal(symbol, "SELL", price, stop, tp,
                          f"SMA{cfg.sma_fast} {cfg.sma_slow} altına kırıldı",
                          self.name, datetime.utcnow())
        return Signal(symbol, "HOLD", price, None, None,
                      f"fast-slow={curr_diff:.2f}", self.name, datetime.utcnow())


class RSIMeanReversionStrategy(Strategy):
    """RSI < oversold iken alım, > overbought iken satım sinyali."""

    name = "rsi_mean_reversion"

    def evaluate(self, symbol: str, df: pd.DataFrame) -> Signal:
        cfg = self.cfg
        close = df["close"]
        r = rsi(close, cfg.rsi_period)
        atr_val = atr(df, cfg.atr_period)

        if len(df) < cfg.rsi_period + 2 or pd.isna(r.iloc[-1]):
            return Signal(symbol, "HOLD", float(close.iloc[-1]), None, None,
                          "yetersiz veri", self.name, datetime.utcnow())

        price = float(close.iloc[-1])
        a = float(atr_val.iloc[-1]) if not pd.isna(atr_val.iloc[-1]) else 0.0
        last_rsi = float(r.iloc[-1])
        prev_rsi = float(r.iloc[-2])

        # Tetik: önceki bar aşırı bölgedeyken bu bar geri dönüyor.
        if prev_rsi < cfg.rsi_oversold <= last_rsi:
            stop = price - cfg.atr_stop_mult * a if a else None
            tp = price + 1.5 * cfg.atr_stop_mult * a if a else None
            return Signal(symbol, "BUY", price, stop, tp,
                          f"RSI {prev_rsi:.1f}->{last_rsi:.1f} oversold dönüş",
                          self.name, datetime.utcnow())
        if prev_rsi > cfg.rsi_overbought >= last_rsi:
            stop = price + cfg.atr_stop_mult * a if a else None
            tp = price - 1.5 * cfg.atr_stop_mult * a if a else None
            return Signal(symbol, "SELL", price, stop, tp,
                          f"RSI {prev_rsi:.1f}->{last_rsi:.1f} overbought dönüş",
                          self.name, datetime.utcnow())
        return Signal(symbol, "HOLD", price, None, None,
                      f"RSI={last_rsi:.1f}", self.name, datetime.utcnow())


STRATEGIES: dict[str, type[Strategy]] = {
    SMACrossoverStrategy.name: SMACrossoverStrategy,
    RSIMeanReversionStrategy.name: RSIMeanReversionStrategy,
}


def build_strategy(name: str) -> Strategy:
    if name not in STRATEGIES:
        raise ValueError(f"Bilinmeyen strateji: {name}. Seçenekler: {list(STRATEGIES)}")
    return STRATEGIES[name]()

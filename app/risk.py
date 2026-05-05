from __future__ import annotations

from dataclasses import dataclass

from .account import AccountSnapshot, PositionInfo
from .config import CONFIG, RiskConfig
from .logger import get_logger
from .strategy import Signal

log = get_logger(__name__)


@dataclass
class RiskDecision:
    allowed: bool
    reason: str
    suggested_qty: int = 0
    risk_per_share: float = 0.0
    risk_dollars: float = 0.0


class RiskGuard:
    """Sinyal -> izin/red kararı + önerilen miktar.

    Sert kurallar (her biri tek başına işlemi reddedebilir):
      - Günlük PnL < -daily_loss_limit_pct  => durdur
      - Aynı anda max_open_positions sınırı
      - Tek pozisyonun NLV'ye oranı > max_position_pct
      - Yetersiz nakit tamponu
      - Stop yoksa pozisyon boyutlandırılamaz
    """

    def __init__(self, cfg: RiskConfig = CONFIG.risk) -> None:
        self.cfg = cfg

    def daily_loss_breached(self, snap: AccountSnapshot) -> bool:
        return snap.total_pnl_day_pct <= -self.cfg.daily_loss_limit_pct

    def assess(
        self,
        signal: Signal,
        snap: AccountSnapshot,
        positions: list[PositionInfo],
    ) -> RiskDecision:
        if not signal.is_actionable():
            return RiskDecision(False, "HOLD sinyali")

        if self.daily_loss_breached(snap):
            return RiskDecision(
                False,
                f"Günlük kayıp limiti aşıldı: {snap.total_pnl_day_pct:.2%} "
                f"<= -{self.cfg.daily_loss_limit_pct:.0%}",
            )

        held_symbols = {p.symbol for p in positions if abs(p.quantity) > 0}
        if signal.symbol in held_symbols:
            return RiskDecision(False, f"{signal.symbol} için zaten açık pozisyon var")

        if len(held_symbols) >= self.cfg.max_open_positions:
            return RiskDecision(
                False,
                f"Max açık pozisyon dolu ({len(held_symbols)}/{self.cfg.max_open_positions})",
            )

        if signal.stop is None:
            return RiskDecision(False, "Stop seviyesi yok — boyutlandırma yapılamaz")

        risk_per_share = abs(signal.price - signal.stop)
        if risk_per_share <= 0:
            return RiskDecision(False, "Geçersiz stop mesafesi")

        risk_dollars = snap.net_liquidation * self.cfg.per_trade_risk_pct
        qty_by_risk = int(risk_dollars // risk_per_share)

        max_position_value = snap.net_liquidation * self.cfg.max_position_pct
        qty_by_cap = int(max_position_value // signal.price)

        cash_available = snap.cash - snap.net_liquidation * self.cfg.min_cash_buffer_pct
        qty_by_cash = int(max(cash_available, 0) // signal.price)

        qty = max(min(qty_by_risk, qty_by_cap, qty_by_cash), 0)
        if qty <= 0:
            return RiskDecision(
                False,
                f"Hesaplanan miktar 0 (risk={qty_by_risk}, cap={qty_by_cap}, cash={qty_by_cash})",
                risk_per_share=risk_per_share,
                risk_dollars=risk_dollars,
            )

        return RiskDecision(
            True,
            f"OK qty={qty} (risk={qty_by_risk}, cap={qty_by_cap}, cash={qty_by_cash})",
            suggested_qty=qty,
            risk_per_share=risk_per_share,
            risk_dollars=risk_dollars,
        )

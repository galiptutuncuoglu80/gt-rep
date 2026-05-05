from __future__ import annotations

from dataclasses import dataclass

from .ibkr_client import IBKRClient
from .logger import get_logger

log = get_logger(__name__)


@dataclass
class AccountSnapshot:
    account: str
    net_liquidation: float
    cash: float
    buying_power: float
    realized_pnl_day: float
    unrealized_pnl: float
    currency: str = "USD"

    @property
    def total_pnl_day(self) -> float:
        return self.realized_pnl_day + self.unrealized_pnl

    @property
    def total_pnl_day_pct(self) -> float:
        if self.net_liquidation <= 0:
            return 0.0
        return self.total_pnl_day / self.net_liquidation


@dataclass
class PositionInfo:
    symbol: str
    quantity: float
    avg_cost: float
    market_price: float
    market_value: float
    unrealized_pnl: float


def _account_value(values, tag: str, currency: str = "USD") -> float:
    for v in values:
        if v.tag == tag and (v.currency in (currency, "BASE", "")):
            try:
                return float(v.value)
            except (TypeError, ValueError):
                continue
    return 0.0


def fetch_account(client: IBKRClient) -> AccountSnapshot:
    ib = client.ib
    values = ib.accountSummary(client.cfg.account or "")
    pnl_summary = ib.pnl(account=client.cfg.account or "")
    realized = sum((p.realizedPnL or 0.0) for p in pnl_summary)
    unrealized = sum((p.unrealizedPnL or 0.0) for p in pnl_summary)

    snap = AccountSnapshot(
        account=client.cfg.account or (values[0].account if values else ""),
        net_liquidation=_account_value(values, "NetLiquidation"),
        cash=_account_value(values, "TotalCashValue"),
        buying_power=_account_value(values, "BuyingPower"),
        realized_pnl_day=realized,
        unrealized_pnl=unrealized,
    )
    log.info(
        f"Account NLV={snap.net_liquidation:,.2f} Cash={snap.cash:,.2f} "
        f"DayPnL={snap.total_pnl_day:,.2f} ({snap.total_pnl_day_pct:.2%})"
    )
    return snap


def fetch_positions(client: IBKRClient) -> list[PositionInfo]:
    ib = client.ib
    positions = ib.positions(account=client.cfg.account or "")
    out: list[PositionInfo] = []
    for p in positions:
        contract = p.contract
        if contract.secType != "STK":
            continue
        last = client.latest_price(contract.symbol) or p.avgCost
        mv = last * p.position
        upl = (last - p.avgCost) * p.position
        out.append(
            PositionInfo(
                symbol=contract.symbol,
                quantity=float(p.position),
                avg_cost=float(p.avgCost),
                market_price=float(last),
                market_value=float(mv),
                unrealized_pnl=float(upl),
            )
        )
    return out

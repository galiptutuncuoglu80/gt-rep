from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from ib_insync import IB, Stock, util

from .config import CONFIG, IBKRConfig
from .logger import get_logger

log = get_logger(__name__)


class IBKRClient:
    """ib_insync üzerinden TWS/Gateway'e bağlantı sarmalayıcısı.

    Paper trading varsayılan; canlıya geçiş yalnızca config değişikliğiyle olur.
    """

    def __init__(self, cfg: IBKRConfig = CONFIG.ibkr) -> None:
        self.cfg = cfg
        self.ib = IB()

    def connect(self) -> None:
        if self.ib.isConnected():
            return
        log.info(
            f"IBKR connect host={self.cfg.host} port={self.cfg.port} "
            f"clientId={self.cfg.client_id} paper={self.cfg.paper}"
        )
        self.ib.connect(
            self.cfg.host, self.cfg.port, clientId=self.cfg.client_id, timeout=10
        )
        # Live port (7496/4001) tespiti — kullanıcıyı uyar.
        if self.cfg.port in (7496, 4001) and not self.cfg.paper:
            log.warning("[bold red]CANLI HESAP portu kullanılıyor — dikkat![/]")

    def disconnect(self) -> None:
        if self.ib.isConnected():
            self.ib.disconnect()

    def stock(self, symbol: str) -> Stock:
        return Stock(
            symbol,
            CONFIG.universe.exchange,
            CONFIG.universe.currency,
        )

    def historical_bars(
        self,
        symbol: str,
        duration: str = "120 D",
        bar_size: str = "1 day",
        what_to_show: str = "TRADES",
    ):
        """Geçmiş bar verisi çeker. Pandas DataFrame döner."""
        contract = self.stock(symbol)
        self.ib.qualifyContracts(contract)
        bars = self.ib.reqHistoricalData(
            contract,
            endDateTime="",
            durationStr=duration,
            barSizeSetting=bar_size,
            whatToShow=what_to_show,
            useRTH=True,
            formatDate=1,
        )
        return util.df(bars)

    def latest_price(self, symbol: str) -> float | None:
        contract = self.stock(symbol)
        self.ib.qualifyContracts(contract)
        ticker = self.ib.reqMktData(contract, "", False, False)
        self.ib.sleep(1.5)
        price = ticker.last or ticker.close or ticker.marketPrice()
        self.ib.cancelMktData(contract)
        if price is None or price != price:  # NaN kontrolü
            return None
        return float(price)


@contextmanager
def ibkr_session(cfg: IBKRConfig = CONFIG.ibkr) -> Iterator[IBKRClient]:
    client = IBKRClient(cfg)
    try:
        client.connect()
        yield client
    finally:
        client.disconnect()

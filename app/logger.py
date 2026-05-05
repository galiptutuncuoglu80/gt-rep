from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler

from rich.logging import RichHandler

from .config import LOG_DIR

_CONFIGURED = False


def get_logger(name: str = "app") -> logging.Logger:
    global _CONFIGURED
    logger = logging.getLogger(name)
    if _CONFIGURED:
        return logger

    logger.setLevel(logging.INFO)
    logger.handlers.clear()

    console = RichHandler(rich_tracebacks=True, markup=True, show_path=False)
    console.setLevel(logging.INFO)

    file_handler = RotatingFileHandler(
        LOG_DIR / "app.log", maxBytes=2_000_000, backupCount=5, encoding="utf-8"
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    )

    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.handlers.clear()
    root.addHandler(console)
    root.addHandler(file_handler)

    _CONFIGURED = True
    return logger

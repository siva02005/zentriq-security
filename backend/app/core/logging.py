import logging
import sys
from backend.app.core.config import settings

def setup_logging() -> logging.Logger:
    logger = logging.getLogger("zentriq")
    logger.setLevel(getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO))
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    ))
    if not logger.handlers:
        logger.addHandler(handler)
    return logger

logger = setup_logging()

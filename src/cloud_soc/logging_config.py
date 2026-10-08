"""Optional structured diagnostic logging with display-secret filtering."""
from datetime import datetime, timezone
import json
import logging
import os

from cloud_soc.privacy import display


class JsonFormatter(logging.Formatter):
    def format(self, record):
        # Exception/request bodies are deliberately omitted from diagnostics.
        return json.dumps({"timestamp":datetime.now(timezone.utc).isoformat(),
                           "level":record.levelname,"logger":record.name,
                           "message":display(record.getMessage(),8192)},ensure_ascii=False)


def configure_logging():
    if os.environ.get("SOC_LOG_FORMAT") != "json":
        return
    logger = logging.getLogger("cloud_soc")
    if not any(getattr(handler,"soc_json",False) for handler in logger.handlers):
        handler = logging.StreamHandler()
        handler.soc_json = True
        handler.setFormatter(JsonFormatter())
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False

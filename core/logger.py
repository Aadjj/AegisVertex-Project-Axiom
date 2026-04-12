import logging
import sys
from datetime import datetime, timezone
from pythonjsonlogger import jsonlogger

class ElkJSONFormatter(jsonlogger.JsonFormatter):
    def add_fields(self, log_record, record, message_dict):
        super().add_fields(log_record, record, message_dict)
        log_record["timestamp"] = datetime.now(timezone.utc).isoformat()
        log_record["level"] = record.levelname
        log_record["logger"] = record.name

        if hasattr(record, "props"):
            log_record.update(record.props)

class BindLogger(logging.Logger):
    def bind(self, **kwargs):
        return BoundLoggerAdapter(self, kwargs)

class BoundLoggerAdapter(logging.LoggerAdapter):
    def process(self, msg, kwargs):
        kwargs.setdefault("extra", {})["props"] = self.extra
        return msg, kwargs

logging.setLoggerClass(BindLogger)

def get_logger(name: str, level: str = "INFO") -> logging.Logger:
    logger = logging.getLogger(name)

    if not logger.handlers:
        logger.setLevel(level.upper())
        handler = logging.StreamHandler(sys.stdout)
        formatter = ElkJSONFormatter("%(timestamp)s %(level)s %(name)s %(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    logger.propagate = False
    return logger

logger = get_logger("AegisFlow")
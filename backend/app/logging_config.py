"""Structured JSON logging with per-request correlation IDs.

Correlation IDs flow: HTTP request -> investigation -> every tool call ->
approval -> execution -> audit record, so a whole incident is greppable by one id.
"""

from __future__ import annotations

import json
import logging
import sys
import uuid
from contextvars import ContextVar
from typing import Any

_correlation_id: ContextVar[str] = ContextVar("correlation_id", default="-")

# Field names that must never reach a log sink, whatever their value.
REDACTED_KEYS = frozenset(
    {
        "password",
        "secret",
        "api_key",
        "apikey",
        "token",
        "access_token",
        "client_secret",
        "connection_string",
        "sas",
        "sastoken",
        "credential",
        "authorization",
    }
)
_REDACTED = "***REDACTED***"


def new_correlation_id() -> str:
    return uuid.uuid4().hex[:16]


def set_correlation_id(value: str | None = None) -> str:
    cid = value or new_correlation_id()
    _correlation_id.set(cid)
    return cid


def get_correlation_id() -> str:
    return _correlation_id.get()


def redact(value: Any) -> Any:
    """Recursively strip secret-shaped fields from a payload before logging."""
    if isinstance(value, dict):
        return {
            k: (_REDACTED if k.lower().replace("-", "_") in REDACTED_KEYS else redact(v))
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact(v) for v in value]
    return value


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "correlation_id": get_correlation_id(),
            "message": record.getMessage(),
        }
        extra = getattr(record, "extra_fields", None)
        if extra:
            payload.update(redact(extra))
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


class StructuredLogger(logging.LoggerAdapter):
    """logger.info("msg", tool="get_vm_status", vm="AVD-VM-023")"""

    _LOGGING_KWARGS = ("exc_info", "stack_info", "stacklevel", "extra")

    def process(self, msg: str, kwargs: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        fields = {k: v for k, v in kwargs.items() if k not in self._LOGGING_KWARGS}
        passthrough = {k: v for k, v in kwargs.items() if k in self._LOGGING_KWARGS}
        fields.update(passthrough.pop("extra", {}) or {})
        passthrough["extra"] = {"extra_fields": fields}
        return msg, passthrough


def configure_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level.upper())
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)


def get_logger(name: str) -> StructuredLogger:
    return StructuredLogger(logging.getLogger(name), {})

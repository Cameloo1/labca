from __future__ import annotations

import logging
import re
from typing import Optional, Sequence

from app.config import get_settings

settings = get_settings()

REDACTED_PRIVATE_KEY = "[REDACTED PRIVATE KEY]"
REDACTED_SEALED_VALUE = "[REDACTED SEALED VALUE]"

_PEM_KEY_PATTERN = re.compile(
    r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----.*?(?:-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----|\Z)",
    re.DOTALL,
)
_SEALED_PATTERN = re.compile(r"labca:v1:[A-Za-z0-9_:-]*")
_LEGACY_PATTERN = re.compile(r"enc::[A-Za-z0-9+/=]*")

# Attributes that every LogRecord carries; anything else came from extra=.
_STANDARD_RECORD_ATTRS = frozenset(logging.LogRecord("", 0, "", 0, "", (), None).__dict__) | {"message", "asctime"}


def redact(text: str) -> str:
    """Replace PEM private keys and sealed or legacy key values in text."""
    text = _PEM_KEY_PATTERN.sub(REDACTED_PRIVATE_KEY, text)
    text = _SEALED_PATTERN.sub(REDACTED_SEALED_VALUE, text)
    return _LEGACY_PATTERN.sub(REDACTED_SEALED_VALUE, text)


class SecretRedactionFilter(logging.Filter):
    """Scrub secrets from the message, extra fields, exception text, and stack info."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message: Optional[str] = record.getMessage()
        except (TypeError, ValueError):
            message = None  # malformed format arguments: leave the record as it is
        if message is not None:
            record.msg = redact(message)
            record.args = ()
        for key, value in list(record.__dict__.items()):
            if key in _STANDARD_RECORD_ATTRS:
                continue
            if isinstance(value, str):
                record.__dict__[key] = redact(value)
        if record.exc_info and not record.exc_text:
            record.exc_text = redact(logging.Formatter().formatException(record.exc_info))
        elif record.exc_text:
            record.exc_text = redact(record.exc_text)
        if record.stack_info:
            record.stack_info = redact(record.stack_info)
        return True


def install_redaction_filter(logger_names: Sequence[str] = ("", "uvicorn", "uvicorn.error", "uvicorn.access")) -> None:
    for name in logger_names:
        for handler in logging.getLogger(name).handlers:
            if not any(isinstance(existing, SecretRedactionFilter) for existing in handler.filters):
                handler.addFilter(SecretRedactionFilter())


logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)

logger = logging.getLogger("labca")

install_redaction_filter()

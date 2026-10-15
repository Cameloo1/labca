"""Tests for the JSON log formatter and configure_logging."""

from __future__ import annotations

import io
import json
import logging
import re
import uuid
from datetime import datetime

import pytest

from app.config import Settings
from app.logging_config import (
    REDACTED_PRIVATE_KEY,
    REDACTED_SEALED_VALUE,
    JsonFormatter,
    SecretRedactionFilter,
    configure_logging,
    install_redaction_filter,
)

BODY = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7"
PEM = f"-----BEGIN PRIVATE KEY-----\n{BODY}\n-----END PRIVATE KEY-----"
TOKEN = "labca:v1:k1:AAAAAAAA:BBBBBBBB:CCCCCCCC"


def _logger(with_filter: bool = True) -> tuple[logging.Logger, io.StringIO]:
    stream = io.StringIO()
    logger = logging.getLogger(f"json-test-{uuid.uuid4()}")
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)
    if with_filter:
        install_redaction_filter([logger.name])
    return logger, stream


def _lines(stream: io.StringIO) -> list[dict]:
    return [json.loads(line) for line in stream.getvalue().splitlines()]


def test_record_is_one_json_object_with_required_keys():
    logger, stream = _logger()
    logger.info("hello %s", "world")
    text = stream.getvalue()
    assert text.count("\n") == 1
    entry = json.loads(text)
    assert entry["level"] == "INFO"
    assert entry["logger"] == logger.name
    assert entry["message"] == "hello world"
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z", entry["ts"])
    datetime.fromisoformat(entry["ts"].replace("Z", "+00:00"))
    assert "exc" not in entry and "exc_type" not in entry


def test_extra_fields_are_copied_and_non_serializable_become_strings():
    logger, stream = _logger()
    logger.info("with extras", extra={"ca_id": "abc", "count": 3, "items": [1, 2], "obj": object})
    entry = _lines(stream)[0]
    assert entry["ca_id"] == "abc"
    assert entry["count"] == 3
    assert entry["items"] == [1, 2]
    assert isinstance(entry["obj"], str)
    assert "args" not in entry and "lineno" not in entry and "msg" not in entry


def test_exception_info_is_included_and_redacted():
    logger, stream = _logger()
    try:
        raise ValueError(f"cannot parse {PEM}")
    except ValueError:
        logger.exception("failure")
    entry = _lines(stream)[0]
    assert entry["exc_type"] == "ValueError"
    assert "Traceback" in entry["exc"]
    assert REDACTED_PRIVATE_KEY in entry["exc"]
    assert BODY not in stream.getvalue()


def test_private_key_and_sealed_token_are_redacted_in_json_output():
    logger, stream = _logger()
    logger.info("key %s token %s", PEM, TOKEN, extra={"detail": TOKEN})
    output = stream.getvalue()
    entry = json.loads(output)
    assert REDACTED_PRIVATE_KEY in entry["message"]
    assert REDACTED_SEALED_VALUE in entry["message"]
    assert entry["detail"] == REDACTED_SEALED_VALUE
    assert BODY not in output and "AAAAAAAA" not in output


def test_formatter_redacts_without_the_filter():
    logger, stream = _logger(with_filter=False)
    logger.info("key %s", PEM, extra={"detail": TOKEN})
    output = stream.getvalue()
    assert BODY not in output and "AAAAAAAA" not in output


@pytest.mark.parametrize("fmt", ["text", "json"])
def test_configure_logging_is_idempotent(fmt):
    root = logging.getLogger()
    uvicorn_logger = logging.getLogger("uvicorn")
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    uvicorn_logger.addHandler(handler)
    try:
        settings = Settings(_env_file=None, LOG_FORMAT=fmt)
        before = {name: len(logging.getLogger(name).handlers) for name in ("", "uvicorn")}
        configure_logging(settings)
        configure_logging(settings)
        after = {name: len(logging.getLogger(name).handlers) for name in ("", "uvicorn")}
        assert after == {"": before[""], "uvicorn": before["uvicorn"]}
        for owner in (root, uvicorn_logger):
            for existing in owner.handlers:
                filters = [item for item in existing.filters if isinstance(item, SecretRedactionFilter)]
                assert len(filters) == 1
        assert isinstance(handler.formatter, JsonFormatter) is (fmt == "json")
    finally:
        uvicorn_logger.removeHandler(handler)


def test_log_format_setting_default_and_validation():
    assert Settings(_env_file=None).LOG_FORMAT == "text"
    with pytest.raises(ValueError):
        Settings(_env_file=None, LOG_FORMAT="xml")

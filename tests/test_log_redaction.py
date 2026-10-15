"""Tests for the log redaction filter."""

from __future__ import annotations

import io
import logging
import uuid

import pytest

from app.logging_config import (
    REDACTED_PRIVATE_KEY,
    REDACTED_SEALED_VALUE,
    SecretRedactionFilter,
    install_redaction_filter,
    redact,
)

PEM_LABELS = ["PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "ENCRYPTED PRIVATE KEY", "OPENSSH PRIVATE KEY"]
BODY = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7"


def _pem(label: str) -> str:
    return f"-----BEGIN {label}-----\n{BODY}\n-----END {label}-----"


@pytest.mark.parametrize("label", PEM_LABELS)
def test_redact_private_key_variants(label):
    text = f"before {_pem(label)} after"
    result = redact(text)
    assert result == f"before {REDACTED_PRIVATE_KEY} after"
    assert BODY not in result


def test_redact_truncated_private_key_block():
    text = f"failed to parse -----BEGIN RSA PRIVATE KEY-----\n{BODY}\nAAAA"
    result = redact(text)
    assert result == f"failed to parse {REDACTED_PRIVATE_KEY}"
    assert BODY not in result


def test_redact_sealed_and_legacy_values():
    sealed = "labca:v1:k1:AAAA-_bb:CCCC:dddd_-"
    legacy = "enc::dGVzdC1rZXk="
    result = redact(f"token={sealed} old={legacy} end")
    assert result == f"token={REDACTED_SEALED_VALUE} old={REDACTED_SEALED_VALUE} end"


def test_redact_leaves_certificates_and_text():
    text = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\nordinary message: 42"
    assert redact(text) == text


def _capture(name: str) -> tuple[logging.Logger, io.StringIO]:
    stream = io.StringIO()
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(levelname)s %(message)s detail=%(detail)s"))
    logger.addHandler(handler)
    install_redaction_filter([name])
    return logger, stream


def test_filter_redacts_message_args_extra_and_exception():
    name = f"redaction-test-{uuid.uuid4()}"
    logger, stream = _capture(name)
    message_secret = _pem("PRIVATE KEY").replace(BODY, "MESSAGEBODY")
    exc_secret = _pem("EC PRIVATE KEY").replace(BODY, "EXCEPTIONBODY")
    token = "labca:v1:k1:AAAAAAAA:BBBBBBBB:CCCCCCCC"

    logger.info("loaded %s now", message_secret, extra={"detail": token})
    try:
        raise ValueError(f"cannot parse {exc_secret}")
    except ValueError:
        logger.exception("failure", extra={"detail": "none"})

    output = stream.getvalue()
    assert REDACTED_PRIVATE_KEY in output
    assert REDACTED_SEALED_VALUE in output
    for secret in ("MESSAGEBODY", "EXCEPTIONBODY", "AAAAAAAA", "BEGIN PRIVATE KEY", "BEGIN EC PRIVATE KEY"):
        assert secret not in output
    assert "ValueError" in output


def test_filter_handles_stack_info_and_preset_exc_text():
    record = logging.LogRecord("x", logging.ERROR, __file__, 1, "plain", (), None)
    record.stack_info = _pem("PRIVATE KEY")
    record.exc_text = _pem("RSA PRIVATE KEY")
    record.custom_number = 7
    assert SecretRedactionFilter().filter(record) is True
    assert record.stack_info == REDACTED_PRIVATE_KEY
    assert record.exc_text == REDACTED_PRIVATE_KEY
    assert record.custom_number == 7


def test_filter_leaves_record_with_bad_format_arguments():
    record = logging.LogRecord("x", logging.INFO, __file__, 1, "%s and %s", ("one",), None)
    assert SecretRedactionFilter().filter(record) is True
    assert record.msg == "%s and %s"
    assert record.args == ("one",)


def test_install_is_idempotent():
    name = f"redaction-idem-{uuid.uuid4()}"
    logger = logging.getLogger(name)
    logger.propagate = False
    logger.addHandler(logging.StreamHandler(io.StringIO()))
    logger.addHandler(logging.StreamHandler(io.StringIO()))
    install_redaction_filter([name])
    install_redaction_filter([name])
    for handler in logger.handlers:
        assert sum(isinstance(f, SecretRedactionFilter) for f in handler.filters) == 1

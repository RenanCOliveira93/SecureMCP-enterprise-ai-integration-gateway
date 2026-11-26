import logging

from securemcp.security.sanitize import RedactingFilter, fingerprint, mask_email, mask_phone, redact

JWT = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c3JfYXVyX2FuYSJ9.c2lnbmF0dXJlLXZhbHVl"


def test_redacts_tokens_keys_and_pii():
    text = (
        f"Authorization: Bearer {JWT} api_key=abc123 password: hunter2 "
        "mail joana.prado@mercadosolar.example phone +55 11 95555-1234 dev-insecure-crm-api-key"
    )
    out = redact(text)
    for secret in (JWT, "abc123", "hunter2", "joana.prado", "95555-1234", "dev-insecure"):
        assert secret not in out
    assert "[REDACTED]" in out and "[EMAIL]" in out and "[PHONE]" in out


def test_bare_jwt_redacted():
    assert redact(f"token {JWT} leaked").count("REDACTED") >= 1


def test_logging_filter_redacts_args(caplog):
    logger = logging.getLogger("t.redact")
    logger.addFilter(RedactingFilter())
    with caplog.at_level(logging.INFO, logger="t.redact"):
        logger.info("calling with %s", f"Bearer {JWT}")
    assert JWT not in caplog.text and "REDACTED" in caplog.text


def test_masking():
    assert mask_email("joana.prado@mercadosolar.example") == "j***@mercadosolar.example"
    assert mask_phone("+55 11 95555-1234") == "***-34"
    assert mask_email("broken") == "***"


def test_fingerprint_is_order_independent():
    assert fingerprint({"a": 1, "b": [1, 2]}) == fingerprint({"b": [1, 2], "a": 1})
    assert fingerprint({"a": 1}) != fingerprint({"a": 2})

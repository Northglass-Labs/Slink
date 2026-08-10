import json
import logging

import pytest

from app.logging_config import _redact_sensitive, setup_logging


pytestmark = pytest.mark.no_db


def test_redactor_scrubs_nested_keys_and_sensitive_values_in_messages():
    payload = {
        "event": (
            "upstream rejected authorization=Bearer bearer-secret "
            "password='password-secret' "
            "url=https://example.test/callback?api_key=query-secret&safe=yes"
        ),
        "request": {
            "headers": [
                {"Authorization": "Bearer header-secret"},
                "cookie=session_cookie=cookie-secret",
            ]
        },
    }

    redacted = _redact_sensitive(None, None, payload)
    rendered = json.dumps(redacted)

    for secret in (
        "bearer-secret",
        "password-secret",
        "query-secret",
        "header-secret",
        "cookie-secret",
    ):
        assert secret not in rendered
    assert rendered.count("***REDACTED***") >= 5


def test_stdlib_logging_uses_json_and_redacts_in_production(monkeypatch, capsys):
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.delenv("ENVIRONMENT", raising=False)
    setup_logging()

    logging.getLogger("slink.security-test").warning(
        "provider failed token=%s", "stdlib-secret"
    )

    output = capsys.readouterr().out.strip()
    record = json.loads(output)
    assert record["event"] == "provider failed token=***REDACTED***"
    assert "stdlib-secret" not in output

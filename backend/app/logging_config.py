"""Structured logging configuration for Slink.

JSON output in production (``APP_ENV=production``), pretty-print in development.
Sensitive keys and common credential shapes are redacted for both structlog and
ordinary stdlib logging records.
"""
import logging
import os
import re
import sys

import structlog


# Keys we never want to appear in plaintext in log output — matched against
# a substring of the key name, case-insensitive, so e.g. "pushover_api_token"
# or "X-Api-Key" both trip the redactor.
_SENSITIVE_KEY_SUBSTRINGS = (
    "password",
    "secret",
    "api_key",
    "apikey",
    "token",
    "authorization",
    "cookie",
    "bearer",
)

_REDACTED = "***REDACTED***"

_BEARER_RE = re.compile(r"(?i)\bbearer\s+[^\s,;]+")
_SENSITIVE_ASSIGNMENT_RE = re.compile(
    r"(?i)(\b(?:password|passwd|pwd|secret|api[_-]?key|apikey|"
    r"access[_-]?token|refresh[_-]?token|token|authorization|cookie)\b"
    r"\s*[:=]\s*)([\"']?)[^\s,;\"'&#]+\2"
)


def _scrub_string(value: str) -> str:
    value = _BEARER_RE.sub(f"Bearer {_REDACTED}", value)
    return _SENSITIVE_ASSIGNMENT_RE.sub(rf"\1{_REDACTED}", value)


def _scrub_value(key, value, depth: int = 0):
    if isinstance(key, str) and any(
        sensitive in key.lower() for sensitive in _SENSITIVE_KEY_SUBSTRINGS
    ):
        return _REDACTED
    if isinstance(value, str):
        return _scrub_string(value)
    if depth >= 8:
        return _REDACTED
    if isinstance(value, dict):
        return {
            nested_key: _scrub_value(nested_key, nested_value, depth + 1)
            for nested_key, nested_value in value.items()
        }
    if isinstance(value, list):
        return [_scrub_value(None, item, depth + 1) for item in value]
    if isinstance(value, tuple):
        return tuple(_scrub_value(None, item, depth + 1) for item in value)
    return value


def _redact_sensitive(_logger, _method_name, event_dict):
    """structlog processor that masks sensitive values.

    Walks bounded nested mappings/sequences, masks sensitive-key values, and
    scrubs common credential shapes embedded in interpolated messages.
    """
    return {
        key: _scrub_value(key, value)
        for key, value in event_dict.items()
    }


def setup_logging() -> None:
    """Configure structlog and stdlib logging."""
    is_production = os.environ.get("APP_ENV", "").lower() == "production"

    shared_processors = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        _redact_sensitive,
    ]

    if is_production:
        # JSON for CloudWatch / SIEM ingestion
        renderer = structlog.processors.JSONRenderer()
    else:
        # Pretty console output for local development
        renderer = structlog.dev.ConsoleRenderer()

    structlog.configure(
        processors=[
            *shared_processors,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            renderer,
        ],
        foreign_pre_chain=shared_processors,
    )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    # Configure root logger
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(logging.INFO)

    # Reduce noise from libraries
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("apscheduler").setLevel(logging.WARNING)

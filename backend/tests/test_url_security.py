import asyncio
import socket
from unittest.mock import AsyncMock

import pytest
from pydantic import ValidationError
from app.schemas.detection import DetectionDetail
from app.schemas.webhook import WebhookCreate, WebhookUpdate
from app.utils.source_url import sanitize_source_url
from app.utils.url_validator import (
    PinnedAsyncNetworkBackend,
    WebhookURLError,
    resolve_webhook_target,
    resolve_webhook_target_async,
    validate_webhook_url,
)

pytestmark = pytest.mark.no_db


def test_webhook_schema_bounds_stored_and_logged_fields():
    with pytest.raises(ValidationError):
        WebhookCreate(name="x" * 101, url="https://hooks.slack.com/services/test")
    with pytest.raises(ValidationError):
        WebhookCreate(name="ok", url="https://hooks.slack.com/" + "x" * 2048)
    with pytest.raises(ValidationError):
        WebhookUpdate(severity_filter="critical," * 20)


def _public_resolution():
    return [
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", 443))
    ]


def test_webhook_requires_https_before_dns_resolution():
    with pytest.raises(WebhookURLError, match="HTTPS"):
        validate_webhook_url("http://hooks.slack.com/services/example")


def test_webhook_rejects_arbitrary_public_host(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: _public_resolution())
    with pytest.raises(WebhookURLError, match="approved provider"):
        validate_webhook_url("https://example.com/webhook")


def test_webhook_accepts_allowlisted_https_provider_and_returns_pinned_target(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: _public_resolution())
    target = resolve_webhook_target("https://hooks.slack.com/services/example")

    assert target.hostname == "hooks.slack.com"
    assert target.ip == "93.184.216.34"
    assert target.port == 443


async def test_async_webhook_resolution_returns_the_exact_validated_peer(monkeypatch):
    loop = asyncio.get_running_loop()
    monkeypatch.setattr(
        loop,
        "getaddrinfo",
        AsyncMock(return_value=_public_resolution()),
    )
    target = await resolve_webhook_target_async(
        "https://tenant.logic.azure.com/workflows/example"
    )
    assert target.ip == "93.184.216.34"


async def test_pinned_network_backend_never_reresolves_original_hostname():
    delegate = AsyncMock()
    delegate.connect_tcp.return_value = object()
    backend = PinnedAsyncNetworkBackend(
        hostname="hooks.slack.com",
        pinned_ip="93.184.216.34",
        delegate=delegate,
    )

    stream = await backend.connect_tcp("hooks.slack.com", 443, timeout=5)

    assert stream is delegate.connect_tcp.return_value
    delegate.connect_tcp.assert_awaited_once()
    assert delegate.connect_tcp.await_args.kwargs["host"] == "93.184.216.34"

    with pytest.raises(WebhookURLError):
        await backend.connect_tcp("attacker.example", 443)


@pytest.mark.parametrize(
    ("source", "url"),
    [
        ("crowdstrike_intel", "javascript:alert(1)"),
        ("crowdstrike_intel", "https://attacker.example/report"),
        ("crowdstrike_intel", "http://falcon.crowdstrike.com/report"),
        ("ransomlook", "https://user:pass@www.ransomlook.io/recent"),
        ("github_advisory", "https://github.com:8443/advisories/GHSA-example"),
    ],
)
def test_source_url_rejects_unsafe_scheme_host_userinfo_and_port(source, url):
    assert sanitize_source_url(source, url) == ""


def test_source_url_preserves_allowlisted_https_provider_link():
    url = "https://falcon.us-1.crowdstrike.com/intelligence-v2/reports/example"
    assert sanitize_source_url("crowdstrike_intel", url) == url


def test_detection_response_sanitizes_unsafe_historical_source_url():
    detail = DetectionDetail.model_validate(
        {
            "id": 1,
            "source": "crowdstrike_intel",
            "title": "Example",
            "snippet": "Example",
            "severity": "high",
            "status": "new",
            "matched_keywords": ["acme-corp"],
            "first_seen": "2026-07-11T00:00:00Z",
            "last_seen": "2026-07-11T00:00:00Z",
            "source_url": "javascript:alert(1)",
            "content_hash": "a" * 64,
            "notified_at": None,
            "created_at": "2026-07-11T00:00:00Z",
            "raw_data": {},
        }
    )
    assert detail.source_url == ""

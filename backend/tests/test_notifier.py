"""
Tests for the Teams notifier.

Unit tests validate card construction and graceful degradation when no Teams
configuration is present. No network calls are made in these tests.
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from app.services.notifier import (
    TeamsNotifier,
    _get_cached_channel_state,
    build_adaptive_card,
    invalidate_channel_cache,
)
from app.models.detection import Detection

# All notifier tests are pure unit tests — no database connection needed.
pytestmark = pytest.mark.no_db


# ---------------------------------------------------------------------------
# build_adaptive_card
# ---------------------------------------------------------------------------

def test_build_adaptive_card_structure():
    """Card has required type and schema fields."""
    card = build_adaptive_card(
        severity="critical",
        source="crowdstrike_recon",
        title="acme.example 1 TB Database",
        matched_keywords=["acme", "acme-corp"],
        first_seen="2026-03-15T13:02:34Z",
        snippet="acme.example database leaked...",
        detection_id=1,
        base_url="https://slink.example.com",
        actor="Example Threat Group",
    )
    assert card["type"] == "AdaptiveCard"
    assert card["$schema"] == "http://adaptivecards.io/schemas/adaptive-card.json"
    assert card["version"] == "1.4"


def test_build_adaptive_card_content():
    """Card body contains the key detection fields."""
    card = build_adaptive_card(
        severity="critical",
        source="crowdstrike_recon",
        title="acme.example 1 TB Database",
        matched_keywords=["acme", "acme-corp"],
        first_seen="2026-03-15T13:02:34Z",
        snippet="acme.example database leaked...",
        detection_id=1,
        base_url="https://slink.example.com",
        actor="Example Threat Group",
    )
    card_str = str(card)
    assert "acme.example" in card_str
    assert "acme-corp" in card_str
    assert "Example Threat Group" in card_str
    assert "crowdstrike_recon" in card_str


def test_build_adaptive_card_open_url_action():
    """Card includes Action.OpenUrl buttons linking to external investigation tools."""
    card = build_adaptive_card(
        severity="critical",
        source="crowdstrike_recon",
        title="acme.example 1 TB Database",
        matched_keywords=["acme", "acme-corp"],
        first_seen="2026-03-15T13:02:34Z",
        snippet="acme.example database leaked...",
        detection_id=1,
        base_url="https://slink.example.com",
        actor="Example Threat Group",
    )
    card_str = str(card)
    assert "Action.OpenUrl" in card_str
    # crowdstrike_recon source → links to Falcon Recon dashboard.
    # Region-agnostic: don't pin a cloud region (configurable via
    # CS_FALCON_CONSOLE_BASE); just assert the recon deep link is present.
    assert "crowdstrike.com/intelligence-v2/recon" in card_str


def test_build_adaptive_card_no_actor():
    """Card can be built without an actor — no KeyError or crash."""
    card = build_adaptive_card(
        severity="high",
        source="ransomwatch",
        title="Company listed on leak site",
        matched_keywords=["acme"],
        first_seen="2026-03-15T13:02:34Z",
        snippet="acme.example appears on ransomwatch...",
        detection_id=42,
        base_url="https://slink.example.com",
        actor=None,
    )
    assert card["type"] == "AdaptiveCard"
    card_str = str(card)
    assert "acme" in card_str


def test_build_adaptive_card_severity_colors():
    """Different severity levels produce different header colors."""
    critical_card = build_adaptive_card(
        severity="critical", source="s", title="t",
        matched_keywords=["k"], first_seen="2026-01-01T00:00:00Z",
        snippet="s", detection_id=1, base_url="https://example.com",
    )
    high_card = build_adaptive_card(
        severity="high", source="s", title="t",
        matched_keywords=["k"], first_seen="2026-01-01T00:00:00Z",
        snippet="s", detection_id=2, base_url="https://example.com",
    )
    medium_card = build_adaptive_card(
        severity="medium", source="s", title="t",
        matched_keywords=["k"], first_seen="2026-01-01T00:00:00Z",
        snippet="s", detection_id=3, base_url="https://example.com",
    )
    # Each card renders as a string — the style/color values must differ
    assert str(critical_card) != str(high_card)
    assert str(high_card) != str(medium_card)


# ---------------------------------------------------------------------------
# TeamsNotifier — graceful degradation when unconfigured
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_notifier_skips_when_unconfigured(caplog):
    """When no Teams config is set, send_detection logs a warning and does not crash."""
    import logging

    detection = Detection(
        id=1,
        source="ransomwatch",
        title="Test detection",
        snippet="test snippet",
        source_url="https://example.com",
        content_hash="abc123",
        matched_keywords=["acme-corp"],
        severity="critical",
        status="new",
        raw_data={},
    )

    # Patch settings so no credentials are present
    with patch("app.services.notifier.settings") as mock_settings:
        mock_settings.teams_tenant_id = ""
        mock_settings.teams_client_id = ""
        mock_settings.teams_client_secret = ""
        mock_settings.teams_chat_id = ""
        mock_settings.teams_webhook_url = ""
        mock_settings.pushover_api_token = ""
        mock_settings.pushover_user_key = ""
        mock_settings.slink_base_url = "https://slink.example.com"

        notifier = TeamsNotifier()
        with caplog.at_level(logging.WARNING, logger="app.services.notifier"):
            # Should not raise
            await notifier.send_detection(detection)

    assert any("Teams" in record.message or "not configured" in record.message.lower()
               for record in caplog.records)


@pytest.mark.asyncio
async def test_notifier_send_batch_skips_when_unconfigured():
    """send_batch with no config does not crash."""
    detection = Detection(
        id=2,
        source="ransomlook",
        title="Batch detection",
        snippet="batch snippet",
        source_url="https://example.com",
        content_hash="def456",
        matched_keywords=["acme-corp"],
        severity="medium",
        status="new",
        raw_data={},
    )

    with patch("app.services.notifier.settings") as mock_settings:
        mock_settings.teams_tenant_id = ""
        mock_settings.teams_client_id = ""
        mock_settings.teams_client_secret = ""
        mock_settings.teams_chat_id = ""
        mock_settings.teams_webhook_url = ""
        mock_settings.pushover_api_token = ""
        mock_settings.pushover_user_key = ""
        mock_settings.slink_base_url = "https://slink.example.com"

        notifier = TeamsNotifier()
        # Must not raise
        await notifier.send_batch([detection])


@pytest.mark.asyncio
async def test_notifier_health_alert_skips_when_unconfigured():
    """send_health_alert with no config does not crash."""
    with patch("app.services.notifier.settings") as mock_settings:
        mock_settings.teams_tenant_id = ""
        mock_settings.teams_client_id = ""
        mock_settings.teams_client_secret = ""
        mock_settings.teams_chat_id = ""
        mock_settings.teams_webhook_url = ""
        mock_settings.pushover_api_token = ""
        mock_settings.pushover_user_key = ""
        mock_settings.slink_base_url = "https://slink.example.com"

        notifier = TeamsNotifier()
        await notifier.send_health_alert("ransomwatch", "Connection timeout after 3 failures")


# ---------------------------------------------------------------------------
# Pushover
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_pushover_skips_when_unconfigured(caplog):
    """When no Pushover config is set, _send_pushover skips without crash."""
    import logging

    with patch("app.services.notifier.settings") as mock_settings:
        mock_settings.teams_tenant_id = ""
        mock_settings.teams_client_id = ""
        mock_settings.teams_client_secret = ""
        mock_settings.teams_chat_id = ""
        mock_settings.teams_webhook_url = ""
        mock_settings.pushover_api_token = ""
        mock_settings.pushover_user_key = ""
        mock_settings.slink_base_url = "https://slink.example.com"

        notifier = TeamsNotifier()
        with caplog.at_level(logging.DEBUG, logger="app.services.notifier"):
            await notifier._send_pushover(
                title="Test", message="test", severity="high"
            )

    assert any("Pushover not configured" in record.message for record in caplog.records)


@pytest.mark.asyncio
async def test_pushover_sends_when_configured(httpx_mock):
    """When Pushover is configured, _send_pushover POSTs to the API."""
    httpx_mock.add_response(
        url="https://api.pushover.net/1/messages.json",
        json={"status": 1, "request": "test-req-id"},
    )

    with patch("app.services.notifier.settings") as mock_settings:
        mock_settings.teams_tenant_id = ""
        mock_settings.teams_client_id = ""
        mock_settings.teams_client_secret = ""
        mock_settings.teams_chat_id = ""
        mock_settings.teams_webhook_url = ""
        mock_settings.pushover_api_token = "test-token"
        mock_settings.pushover_user_key = "test-user"
        mock_settings.slink_base_url = "https://slink.example.com"

        notifier = TeamsNotifier()
        await notifier._send_pushover(
            title="Slink CRITICAL: crowdstrike_recon",
            message="acme.example leak card",
            severity="critical",
            url="https://slink.example.com/detections/1",
        )

    # Verify request was made
    request = httpx_mock.get_request()
    assert request is not None
    body = request.content.decode()
    assert "test-token" in body
    assert "acme.example" in body


@pytest.mark.asyncio
async def test_provider_error_body_is_not_logged(httpx_mock, caplog):
    """Provider responses can echo credentials and must stay out of logs."""
    import logging

    httpx_mock.add_response(
        url="https://api.pushover.net/1/messages.json",
        status_code=400,
        text="arbitrary-provider-secret",
    )

    with patch("app.services.notifier.settings") as mock_settings:
        mock_settings.teams_tenant_id = ""
        mock_settings.teams_client_id = ""
        mock_settings.teams_client_secret = ""
        mock_settings.teams_chat_id = ""
        mock_settings.teams_webhook_url = ""
        mock_settings.pushover_api_token = "test-token"
        mock_settings.pushover_user_key = "test-user"
        mock_settings.slink_base_url = "https://slink.example.com"

        notifier = TeamsNotifier()
        with caplog.at_level(logging.ERROR, logger="app.services.notifier"):
            await notifier._send_pushover(title="Test", message="test")

    assert "arbitrary-provider-secret" not in caplog.text


@pytest.mark.asyncio
async def test_channel_state_fails_closed_without_database():
    invalidate_channel_cache()
    assert await _get_cached_channel_state(None, "pushover") is False


@pytest.mark.asyncio
async def test_channel_state_fails_closed_on_database_error():
    invalidate_channel_cache()
    db = MagicMock()
    db.execute = AsyncMock(side_effect=RuntimeError("database unavailable"))
    assert await _get_cached_channel_state(db, "pushover") is False


@pytest.mark.asyncio
async def test_channel_state_fails_closed_when_row_is_missing():
    invalidate_channel_cache()
    result = MagicMock()
    result.scalar_one_or_none.return_value = None
    db = MagicMock()
    db.execute = AsyncMock(return_value=result)
    assert await _get_cached_channel_state(db, "pushover") is False


@pytest.mark.asyncio
async def test_emergency_respects_disabled_pushover_channel():
    detection = Detection(
        id=3,
        source="ransomwatch",
        title="Example incident",
        snippet="Example evidence",
        source_url="https://ransomware.live/id/3",
        content_hash="c" * 64,
        matched_keywords=["acme-corp"],
        severity="critical",
        status="new",
        raw_data={},
    )
    with patch("app.services.notifier.settings") as mock_settings:
        mock_settings.teams_tenant_id = ""
        mock_settings.teams_client_id = ""
        mock_settings.teams_client_secret = ""
        mock_settings.teams_chat_id = ""
        mock_settings.teams_webhook_url = ""
        mock_settings.pushover_api_token = "configured-token"
        mock_settings.pushover_user_key = "configured-user"
        mock_settings.slink_base_url = "https://slink.example.com"

        notifier = TeamsNotifier()
        notifier._dispatch_teams = AsyncMock()
        notifier._is_channel_enabled = AsyncMock(return_value=False)
        notifier._client.post = AsyncMock()
        await notifier.send_emergency(detection, db=MagicMock())

    notifier._client.post.assert_not_awaited()


@pytest.mark.asyncio
async def test_graph_delivery_respects_disabled_channel():
    with patch("app.services.notifier.settings") as mock_settings:
        mock_settings.teams_tenant_id = "tenant"
        mock_settings.teams_client_id = "client"
        mock_settings.teams_client_secret = "secret"
        mock_settings.teams_chat_id = "chat"
        mock_settings.teams_webhook_url = ""
        mock_settings.pushover_api_token = ""
        mock_settings.pushover_user_key = ""
        mock_settings.slink_base_url = "https://slink.example.com"

        notifier = TeamsNotifier()
        notifier._is_channel_enabled = AsyncMock(return_value=False)
        notifier._send_via_graph = AsyncMock()
        await notifier._dispatch_teams({"type": "AdaptiveCard"}, db=MagicMock())

    notifier._send_via_graph.assert_not_awaited()


@pytest.mark.asyncio
async def test_notification_omits_unsafe_feed_url(httpx_mock):
    httpx_mock.add_response(
        url="https://api.pushover.net/1/messages.json",
        json={"status": 1, "request": "test-request"},
    )
    detection = Detection(
        id=4,
        source="crowdstrike_intel",
        title="Example report",
        snippet="Example evidence",
        source_url="javascript:alert(1)",
        content_hash="d" * 64,
        matched_keywords=["example-threat-actor"],
        severity="high",
        status="new",
        raw_data={},
    )
    with patch("app.services.notifier.settings") as mock_settings:
        mock_settings.teams_tenant_id = ""
        mock_settings.teams_client_id = ""
        mock_settings.teams_client_secret = ""
        mock_settings.teams_chat_id = ""
        mock_settings.teams_webhook_url = ""
        mock_settings.pushover_api_token = "test-token"
        mock_settings.pushover_user_key = "test-user"
        mock_settings.slink_base_url = "https://slink.example.com"

        notifier = TeamsNotifier()
        notifier._dispatch_teams = AsyncMock()
        notifier._is_channel_enabled = AsyncMock(return_value=True)
        await notifier.send_detection(detection, db=MagicMock())

    body = httpx_mock.get_request().content.decode()
    assert "javascript" not in body
    assert "url=" not in body

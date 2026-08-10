"""
Tests for CrowdStrikeReconCollector and CrowdStrikeAuth.

Unit tests:
  - Collector metadata (name, poll_interval_seconds)
  - parse_notifications() with sample CS response shapes
  - CrowdStrikeAuth token caching and refresh logic (no real HTTP)

Integration tests (mocked HTTP via pytest-httpx):
  - collect(): full two-request flow (query IDs, then fetch entities)
  - health_check(): token fetch success and failure paths
  - configure_watches(): create/delete rule lifecycle

CrowdStrike API envelope shape (verified 2026-03):
  {"meta": {...}, "resources": [...], "errors": [...]}
"""
import time

import pytest
from pytest_httpx import HTTPXMock

from app.collectors.crowdstrike_recon import CrowdStrikeReconCollector
from app.collectors.crowdstrike_auth import CrowdStrikeAuth
from app.collectors.base import RawDetection


BASE_URL = "https://api.crowdstrike.com"

# ---------------------------------------------------------------------------
# Sample data — matches actual CS Recon API shape (verified 2026-03)
# ---------------------------------------------------------------------------

SAMPLE_NOTIFICATION = {
    "id": "notif-001",
    "rule_name": "ACME Corp",
    "rule_id": "rule-abc",
    "rule_topic": "SA_DOMAIN",
    "rule_priority": "high",
    "item_type": "exposed_data",
    "item_site": "pastebin.com",
    "item_date": "2026-03-24T12:00:00Z",
    "actor_slug": "h4x0r_dude",
    "source_category": "paste_site",
    "created_date": "2026-03-24T12:00:00Z",
    "breach_summary": {
        "description": "ACME Corp credentials found on paste site",
        "credentials_domains": ["acme.com"],
    },
}

SAMPLE_NOTIFICATION_MINIMAL = {
    "id": "notif-002",
}

TOKEN_RESPONSE = {
    "access_token": "test-bearer-token",
    "expires_in": 1800,
    "token_type": "bearer",
}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def collector():
    return CrowdStrikeReconCollector(
        client_id="test-id",
        client_secret="test-secret",
        base_url=BASE_URL,
    )


@pytest.fixture
def auth():
    return CrowdStrikeAuth(
        client_id="test-id",
        client_secret="test-secret",
        base_url=BASE_URL,
    )


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------

def test_collector_name(collector):
    assert collector.name == "crowdstrike_recon"


def test_collector_poll_interval(collector):
    assert collector.poll_interval_seconds == 60


# ---------------------------------------------------------------------------
# parse_notifications() — pure function, no HTTP
# ---------------------------------------------------------------------------

def test_parse_notifications_returns_raw_detections(collector):
    results = collector.parse_notifications([SAMPLE_NOTIFICATION])
    assert len(results) == 1
    assert isinstance(results[0], RawDetection)


def test_parse_notifications_title_uses_rule_name(collector):
    results = collector.parse_notifications([SAMPLE_NOTIFICATION])
    assert "ACME Corp" in results[0].title


def test_parse_notifications_content_includes_breach_description(collector):
    results = collector.parse_notifications([SAMPLE_NOTIFICATION])
    assert "ACME Corp credentials" in results[0].content


def test_parse_notifications_content_includes_site(collector):
    results = collector.parse_notifications([SAMPLE_NOTIFICATION])
    assert "pastebin.com" in results[0].content


def test_parse_notifications_content_includes_actor(collector):
    results = collector.parse_notifications([SAMPLE_NOTIFICATION])
    assert "h4x0r_dude" in results[0].content


def test_parse_notifications_maps_actor_slug_to_actor(collector):
    results = collector.parse_notifications([SAMPLE_NOTIFICATION])
    assert results[0].actor == "h4x0r_dude"


def test_parse_notifications_source_url_is_empty(collector):
    """CS Recon doesn't provide public URLs for notifications."""
    results = collector.parse_notifications([SAMPLE_NOTIFICATION])
    assert results[0].source_url == ""


def test_parse_notifications_source_is_collector_name(collector):
    results = collector.parse_notifications([SAMPLE_NOTIFICATION])
    assert results[0].source == "crowdstrike_recon"


def test_parse_notifications_raw_payload_preserved(collector):
    results = collector.parse_notifications([SAMPLE_NOTIFICATION])
    assert results[0].raw_payload == SAMPLE_NOTIFICATION


def test_parse_notifications_empty_list(collector):
    assert collector.parse_notifications([]) == []


def test_parse_notifications_multiple_items(collector):
    second = {**SAMPLE_NOTIFICATION, "id": "notif-003", "actor_slug": ""}
    results = collector.parse_notifications([SAMPLE_NOTIFICATION, second])
    assert len(results) == 2


def test_parse_notifications_no_actor_sets_actor_none(collector):
    notif = {**SAMPLE_NOTIFICATION, "actor_slug": ""}
    results = collector.parse_notifications([notif])
    assert results[0].actor is None


def test_parse_notifications_minimal_does_not_raise(collector):
    """Notifications with only 'id' should parse without raising."""
    results = collector.parse_notifications([SAMPLE_NOTIFICATION_MINIMAL])
    assert len(results) == 1
    assert results[0].title.startswith("Recon notification")
    assert results[0].actor is None


def test_parse_notifications_no_rule_name_uses_id_in_title(collector):
    notif = {**SAMPLE_NOTIFICATION, "rule_name": ""}
    results = collector.parse_notifications([notif])
    assert "notif-001" in results[0].title


# ---------------------------------------------------------------------------
# CrowdStrikeAuth — token caching and refresh logic
# ---------------------------------------------------------------------------

async def test_auth_caches_token_on_second_call(httpx_mock: HTTPXMock):
    """get_token() should only call the auth endpoint once while token is fresh."""
    httpx_mock.add_response(
        url=f"{BASE_URL}/oauth2/token",
        json=TOKEN_RESPONSE,
    )
    auth_obj = CrowdStrikeAuth("id", "secret", BASE_URL)
    token1 = await auth_obj.get_token()
    token2 = await auth_obj.get_token()
    assert token1 == token2 == "test-bearer-token"
    # Only one HTTP call should have been made
    assert len(httpx_mock.get_requests()) == 1


async def test_auth_refreshes_token_when_near_expiry(httpx_mock: HTTPXMock):
    """get_token() should re-authenticate when token is about to expire.

    We pre-seed the auth object with an 'old-token' that is near expiry,
    then register a single mock for the refresh call.  No initial auth call
    is expected because the token is already cached — only the refresh matters.
    """
    httpx_mock.add_response(
        url=f"{BASE_URL}/oauth2/token",
        json={**TOKEN_RESPONSE, "access_token": "refreshed-token"},
    )
    auth_obj = CrowdStrikeAuth("id", "secret", BASE_URL)
    # Pre-seed: token exists but expires in 30 s (< 60 s buffer -> triggers refresh)
    auth_obj._token = "old-token"
    auth_obj._expires_at = time.monotonic() + 30
    new_token = await auth_obj.get_token()
    assert new_token == "refreshed-token"


async def test_auth_raises_on_bad_credentials(httpx_mock: HTTPXMock):
    """get_token() should propagate HTTP errors from the token endpoint."""
    httpx_mock.add_response(
        url=f"{BASE_URL}/oauth2/token",
        status_code=401,
    )
    auth_obj = CrowdStrikeAuth("bad-id", "bad-secret", BASE_URL)
    with pytest.raises(Exception):
        await auth_obj.get_token()


# ---------------------------------------------------------------------------
# collect() — mocked HTTP
# ---------------------------------------------------------------------------

async def test_collect_returns_detections(collector, httpx_mock: HTTPXMock):
    """collect() does two requests: query IDs, then fetch entities."""
    httpx_mock.add_response(url=f"{BASE_URL}/oauth2/token", json=TOKEN_RESPONSE)
    httpx_mock.add_response(
        url=f"{BASE_URL}/recon/queries/notifications/v1",
        json={"resources": ["notif-001"]},
    )
    # No URL filter — entities endpoint includes dynamic ?ids= query params
    httpx_mock.add_response(json={"resources": [SAMPLE_NOTIFICATION]})
    results = await collector.collect()
    assert len(results) == 1
    assert results[0].title == "Recon alert: ACME Corp"


async def test_collect_empty_ids_returns_empty_list(collector, httpx_mock: HTTPXMock):
    """When the query returns no IDs, collect() returns an empty list."""
    httpx_mock.add_response(url=f"{BASE_URL}/oauth2/token", json=TOKEN_RESPONSE)
    httpx_mock.add_response(
        url=f"{BASE_URL}/recon/queries/notifications/v1",
        json={"resources": []},
    )
    results = await collector.collect()
    assert results == []


async def test_collect_raises_on_http_error(collector, httpx_mock: HTTPXMock):
    httpx_mock.add_response(url=f"{BASE_URL}/oauth2/token", json=TOKEN_RESPONSE)
    httpx_mock.add_response(
        url=f"{BASE_URL}/recon/queries/notifications/v1",
        status_code=500,
    )
    with pytest.raises(Exception):
        await collector.collect()


# ---------------------------------------------------------------------------
# health_check() — mocked HTTP
# ---------------------------------------------------------------------------

async def test_health_check_returns_true_on_valid_token(collector, httpx_mock: HTTPXMock):
    httpx_mock.add_response(url=f"{BASE_URL}/oauth2/token", json=TOKEN_RESPONSE)
    assert await collector.health_check() is True


async def test_health_check_returns_false_on_auth_failure(collector, httpx_mock: HTTPXMock):
    httpx_mock.add_response(url=f"{BASE_URL}/oauth2/token", status_code=401)
    assert await collector.health_check() is False


# ---------------------------------------------------------------------------
# configure_watches() — mocked HTTP
# ---------------------------------------------------------------------------

async def test_configure_watches_creates_missing_rules(collector, httpx_mock: HTTPXMock):
    """Keywords not in existing rules should be POSTed to the rules endpoint."""
    httpx_mock.add_response(url=f"{BASE_URL}/oauth2/token", json=TOKEN_RESPONSE)
    # No existing rule IDs — skip the entities fetch entirely
    httpx_mock.add_response(
        url=f"{BASE_URL}/recon/queries/rules/v1",
        json={"resources": []},
    )
    # POST to create the new rule
    httpx_mock.add_response(
        url=f"{BASE_URL}/recon/entities/rules/v1",
        json={"resources": [{"id": "rule-new", "name": "ACME Corp"}]},
    )
    await collector.configure_watches(["ACME Corp"])
    requests = httpx_mock.get_requests()
    # Exclude the OAuth2 token POST — count only Recon rule creation POSTs
    post_requests = [r for r in requests if r.method == "POST" and "oauth2" not in str(r.url)]
    assert len(post_requests) == 1


async def test_configure_watches_deletes_orphaned_rules(collector, httpx_mock: HTTPXMock):
    """Rules that aren't in the keyword list should be DELETEd."""
    httpx_mock.add_response(url=f"{BASE_URL}/oauth2/token", json=TOKEN_RESPONSE)
    httpx_mock.add_response(
        url=f"{BASE_URL}/recon/queries/rules/v1",
        json={"resources": ["rule-old"]},
    )
    # GET entities?ids=rule-old — no URL filter due to query params
    httpx_mock.add_response(
        json={"resources": [{"id": "rule-old", "name": "OldKeyword"}]}
    )
    # POST to create the new keyword rule
    httpx_mock.add_response(
        url=f"{BASE_URL}/recon/entities/rules/v1",
        json={"resources": [{"id": "rule-new", "name": "NewKeyword"}]},
    )
    # DELETE entities?ids=rule-old — no URL filter due to query params
    httpx_mock.add_response(json={"resources": []})
    await collector.configure_watches(["NewKeyword"])
    requests = httpx_mock.get_requests()
    delete_requests = [r for r in requests if r.method == "DELETE"]
    assert len(delete_requests) == 1


async def test_configure_watches_no_op_when_rules_match(collector, httpx_mock: HTTPXMock):
    """No create or delete if keywords already match existing rules exactly."""
    httpx_mock.add_response(url=f"{BASE_URL}/oauth2/token", json=TOKEN_RESPONSE)
    httpx_mock.add_response(
        url=f"{BASE_URL}/recon/queries/rules/v1",
        json={"resources": ["rule-abc"]},
    )
    # GET entities?ids=rule-abc — no URL filter due to query params
    httpx_mock.add_response(
        json={"resources": [{"id": "rule-abc", "name": "ACME Corp"}]}
    )
    await collector.configure_watches(["ACME Corp"])
    requests = httpx_mock.get_requests()
    # OAuth2 token fetch is a POST — exclude it, only check for Recon rule mutations
    mutating = [r for r in requests if r.method in ("POST", "DELETE") and "oauth2" not in str(r.url)]
    assert mutating == []

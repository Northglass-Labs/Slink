"""
Tests for CrowdStrikeIntelCollector.

Unit tests:
  - Collector metadata (name, poll_interval_seconds)
  - parse_reports() with sample CS Intel response shapes

Integration tests (mocked HTTP via pytest-httpx):
  - collect(): two-request flow (query IDs, then fetch entities)
  - health_check(): token fetch success and failure

CS Intel API envelope shape:
  {"meta": {...}, "resources": [...], "errors": [...]}
"""
import pytest
from pytest_httpx import HTTPXMock

from app.collectors.crowdstrike_intel import (
    CrowdStrikeIntelCollector,
    CrowdStrikePayloadError,
    _MAX_TOTAL_REPORTS,
)
from app.collectors.base import RawDetection


BASE_URL = "https://api.crowdstrike.com"

TOKEN_RESPONSE = {
    "access_token": "test-bearer-token",
    "expires_in": 1800,
    "token_type": "bearer",
}

SAMPLE_REPORT = {
    "id": "rpt-001",
    "name": "FANCY BEAR Targets Energy Sector",
    "short_description": "Russian nexus actor FANCY BEAR conducting spearphishing.",
    "summary": "Full report summary here...",
    "url": "https://falcon.crowdstrike.com/intelligence/reports/rpt-001",
    "actors": [
        {"name": "FANCY BEAR", "slug": "fancy-bear"},
    ],
    "tags": [
        {"id": 1, "slug": "russia", "value": "Russia"},
        {"id": 2, "slug": "energy", "value": "Energy"},
        {"id": 3, "slug": "spearphishing", "value": "Spearphishing"},
    ],
    "created_date": 1742000000,
}

SAMPLE_REPORT_MINIMAL = {
    "id": "rpt-002",
}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def collector():
    return CrowdStrikeIntelCollector(
        client_id="test-id",
        client_secret="test-secret",
        base_url=BASE_URL,
    )


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------

def test_collector_name(collector):
    assert collector.name == "crowdstrike_intel"


def test_collector_poll_interval(collector):
    assert collector.poll_interval_seconds == 300


# ---------------------------------------------------------------------------
# parse_reports() — pure function, no HTTP
# ---------------------------------------------------------------------------

def test_parse_reports_returns_raw_detections(collector):
    results = collector.parse_reports([SAMPLE_REPORT])
    assert len(results) == 1
    assert isinstance(results[0], RawDetection)


def test_parse_reports_maps_name_to_title(collector):
    results = collector.parse_reports([SAMPLE_REPORT])
    assert results[0].title == "FANCY BEAR Targets Energy Sector"


def test_parse_reports_maps_actor_name(collector):
    results = collector.parse_reports([SAMPLE_REPORT])
    assert results[0].actor == "FANCY BEAR"


def test_parse_reports_maps_url_to_source_url(collector):
    results = collector.parse_reports([SAMPLE_REPORT])
    assert results[0].source_url == "https://falcon.crowdstrike.com/intelligence/reports/rpt-001"


def test_parse_reports_source_is_collector_name(collector):
    results = collector.parse_reports([SAMPLE_REPORT])
    assert results[0].source == "crowdstrike_intel"


def test_parse_reports_content_includes_short_description(collector):
    results = collector.parse_reports([SAMPLE_REPORT])
    assert "spearphishing" in results[0].content


def test_parse_reports_content_includes_actor(collector):
    results = collector.parse_reports([SAMPLE_REPORT])
    assert "FANCY BEAR" in results[0].content


def test_parse_reports_content_includes_tags(collector):
    results = collector.parse_reports([SAMPLE_REPORT])
    assert "Energy" in results[0].content


def test_parse_reports_raw_payload_preserved(collector):
    results = collector.parse_reports([SAMPLE_REPORT])
    assert results[0].raw_payload == SAMPLE_REPORT


def test_parse_reports_empty_list(collector):
    assert collector.parse_reports([]) == []


def test_parse_reports_multiple_reports(collector):
    second = {**SAMPLE_REPORT, "id": "rpt-003", "name": "COZY BEAR Report"}
    results = collector.parse_reports([SAMPLE_REPORT, second])
    assert len(results) == 2
    assert results[1].title == "COZY BEAR Report"


def test_parse_reports_multiple_actors_joined(collector):
    """When a report has multiple actors, actor field should join their names."""
    report = {
        **SAMPLE_REPORT,
        "actors": [{"name": "FANCY BEAR"}, {"name": "COZY BEAR"}],
    }
    results = collector.parse_reports([report])
    assert "FANCY BEAR" in results[0].actor
    assert "COZY BEAR" in results[0].actor


def test_parse_reports_no_actors_sets_actor_none(collector):
    report = {**SAMPLE_REPORT, "actors": []}
    results = collector.parse_reports([report])
    assert results[0].actor is None


def test_parse_reports_minimal_does_not_raise(collector):
    """A report with only 'id' should parse without raising."""
    results = collector.parse_reports([SAMPLE_REPORT_MINIMAL])
    assert len(results) == 1
    assert "rpt-002" in results[0].title
    assert results[0].actor is None


# ---------------------------------------------------------------------------
# collect() — mocked HTTP
# ---------------------------------------------------------------------------

async def test_collect_returns_detections(collector, httpx_mock: HTTPXMock):
    """collect() performs two requests: query IDs, then fetch entities.

    pytest-httpx matches responses in registration order when no URL filter is
    given, so we omit the URL for the entities call (which has dynamic ?ids=...
    query params that would prevent URL-based matching).
    """
    httpx_mock.add_response(url=f"{BASE_URL}/oauth2/token", json=TOKEN_RESPONSE)
    httpx_mock.add_response(
        url=f"{BASE_URL}/intel/queries/reports/v1",
        json={"resources": ["rpt-001"]},
    )
    # No URL filter here — entities endpoint is called with ?ids=rpt-001
    httpx_mock.add_response(json={"resources": [SAMPLE_REPORT]})
    results = await collector.collect()
    assert len(results) == 1
    assert results[0].title == "FANCY BEAR Targets Energy Sector"


async def test_collect_empty_ids_returns_empty_list(collector, httpx_mock: HTTPXMock):
    httpx_mock.add_response(url=f"{BASE_URL}/oauth2/token", json=TOKEN_RESPONSE)
    httpx_mock.add_response(
        url=f"{BASE_URL}/intel/queries/reports/v1",
        json={"resources": []},
    )
    results = await collector.collect()
    assert results == []


async def test_collect_raises_on_http_error(collector, httpx_mock: HTTPXMock):
    httpx_mock.add_response(url=f"{BASE_URL}/oauth2/token", json=TOKEN_RESPONSE)
    httpx_mock.add_response(
        url=f"{BASE_URL}/intel/queries/reports/v1",
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


async def test_report_id_response_has_an_aggregate_bound(collector, httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url=f"{BASE_URL}/oauth2/token", json=TOKEN_RESPONSE
    )
    httpx_mock.add_response(
        url=f"{BASE_URL}/intel/queries/reports/v1",
        json={"resources": [f"rpt-{i}" for i in range(_MAX_TOTAL_REPORTS + 1)]},
    )
    with pytest.raises(CrowdStrikePayloadError):
        await collector.collect()


def test_parse_reports_skips_malformed_record_without_losing_valid_records(collector):
    malformed = {**SAMPLE_REPORT, "actors": ["not-an-object"], "name": {"bad": "type"}}
    results = collector.parse_reports([malformed, SAMPLE_REPORT])
    assert len(results) == 1
    assert results[0].title == SAMPLE_REPORT["name"]


def test_parse_reports_rejects_untrusted_source_link(collector):
    report = {**SAMPLE_REPORT, "url": "javascript:alert(1)"}
    results = collector.parse_reports([report])
    assert results[0].source_url == ""

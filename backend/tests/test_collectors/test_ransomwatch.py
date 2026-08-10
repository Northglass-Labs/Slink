"""
Tests for RansomWatchCollector.

Unit tests cover parse_posts() with known API response shape (no HTTP).
Integration tests use pytest-httpx to mock the actual HTTP calls made by
collect() and health_check().

Actual ransomware.live /v2/recentvictims field reference (verified 2026-03):
  victim, group, description, url, domain, country, attackdate
"""
import pytest
from pytest_httpx import HTTPXMock

from app.collectors.ransomwatch import RansomWatchCollector
from app.collectors.base import RawDetection


# ---------------------------------------------------------------------------
# Sample data that mirrors the real ransomware.live API shape
# ---------------------------------------------------------------------------

SAMPLE_POST = {
    "activity": "Financial Services",
    "attackdate": "2026-03-24 20:35:31.261624",
    "claim_url": "",
    "country": "US",
    "description": "Salesforce records containing PII and other internal data.",
    "discovered": "2026-03-24 20:35:32.901048",
    "domain": "berkadia.com",
    "duplicates": [],
    "extrainfos": [],
    "group": "shinyhunters",
    "press": None,
    "screenshot": "",
    "url": "https://www.ransomware.live/id/abc123",
    "victim": "Berkadia Commercial Mortgage",
}

SAMPLE_POST_MINIMAL = {
    "victim": "",
    "group": "",
    "description": "",
    "url": "",
    "domain": "",
    "country": "",
}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def collector():
    return RansomWatchCollector()


# ---------------------------------------------------------------------------
# Metadata tests — no I/O required
# ---------------------------------------------------------------------------

def test_collector_name(collector):
    assert collector.name == "ransomwatch"


def test_collector_poll_interval(collector):
    assert collector.poll_interval_seconds == 300


# ---------------------------------------------------------------------------
# parse_posts unit tests — pure function, no HTTP
# ---------------------------------------------------------------------------

def test_parse_posts_returns_raw_detections(collector):
    """parse_posts converts a list of API dicts to RawDetection objects."""
    results = collector.parse_posts([SAMPLE_POST])
    assert len(results) == 1
    assert isinstance(results[0], RawDetection)


def test_parse_posts_maps_victim_to_title(collector):
    results = collector.parse_posts([SAMPLE_POST])
    assert results[0].title == "Berkadia Commercial Mortgage"


def test_parse_posts_maps_group_to_actor(collector):
    results = collector.parse_posts([SAMPLE_POST])
    assert results[0].actor == "shinyhunters"


def test_parse_posts_maps_url_to_source_url(collector):
    results = collector.parse_posts([SAMPLE_POST])
    assert results[0].source_url == "https://www.ransomware.live/id/abc123"


def test_parse_posts_source_is_collector_name(collector):
    results = collector.parse_posts([SAMPLE_POST])
    assert results[0].source == "ransomwatch"


def test_parse_posts_content_includes_victim_and_description(collector):
    """Content block should include victim name and description for keyword matching."""
    results = collector.parse_posts([SAMPLE_POST])
    content = results[0].content
    assert "Berkadia Commercial Mortgage" in content
    assert "Salesforce records" in content


def test_parse_posts_content_includes_group(collector):
    results = collector.parse_posts([SAMPLE_POST])
    assert "shinyhunters" in results[0].content


def test_parse_posts_raw_payload_preserved(collector):
    results = collector.parse_posts([SAMPLE_POST])
    assert results[0].raw_payload == SAMPLE_POST


def test_parse_posts_empty_list(collector):
    assert collector.parse_posts([]) == []


def test_parse_posts_multiple_posts(collector):
    second = {**SAMPLE_POST, "victim": "Another Corp", "url": "https://www.ransomware.live/id/xyz"}
    results = collector.parse_posts([SAMPLE_POST, second])
    assert len(results) == 2
    assert results[1].title == "Another Corp"


def test_parse_posts_missing_group_sets_actor_none(collector):
    """When group is absent or empty string, actor should be None."""
    post = {**SAMPLE_POST, "group": ""}
    results = collector.parse_posts([post])
    assert results[0].actor is None


def test_parse_posts_minimal_post_does_not_raise(collector):
    """parse_posts should not raise even when optional fields are absent."""
    results = collector.parse_posts([SAMPLE_POST_MINIMAL])
    assert len(results) == 1
    assert results[0].title == ""
    assert results[0].actor is None


# ---------------------------------------------------------------------------
# collect() integration test — mocked HTTP
# ---------------------------------------------------------------------------

async def test_collect_returns_detections(collector, httpx_mock: HTTPXMock):
    """collect() hits the API and returns parsed RawDetection list."""
    httpx_mock.add_response(
        url="https://api.ransomware.live/v2/recentvictims",
        json=[SAMPLE_POST],
    )
    results = await collector.collect()
    assert len(results) == 1
    assert results[0].title == "Berkadia Commercial Mortgage"


async def test_collect_empty_response(collector, httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url="https://api.ransomware.live/v2/recentvictims",
        json=[],
    )
    results = await collector.collect()
    assert results == []


async def test_collect_raises_on_http_error(collector, httpx_mock: HTTPXMock):
    """collect() propagates HTTP errors via raise_for_status()."""
    httpx_mock.add_response(
        url="https://api.ransomware.live/v2/recentvictims",
        status_code=503,
    )
    with pytest.raises(Exception):
        await collector.collect()


# ---------------------------------------------------------------------------
# health_check() tests — mocked HTTP
# ---------------------------------------------------------------------------

async def test_health_check_returns_true_on_200(collector, httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url="https://api.ransomware.live/v2/groups",
        status_code=200,
        json=[],
    )
    assert await collector.health_check() is True


async def test_health_check_returns_false_on_error(collector, httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url="https://api.ransomware.live/v2/groups",
        status_code=500,
        json={},
    )
    assert await collector.health_check() is False

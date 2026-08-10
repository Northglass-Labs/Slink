"""
Tests for URLhausCollector.

Covers:
  - Collector metadata (name, poll_interval_seconds)
  - parse_urls() pure mapping with sample URLhaus records
  - collect() with a mocked httpx response (pytest-httpx)
  - No-key short-circuit (returns [])
  - health_check() happy + failure paths
  - Auth-Key header is sent on requests when configured
"""
import pytest
from pytest_httpx import HTTPXMock

from app.collectors.urlhaus import URLhausCollector
from app.collectors.base import RawDetection

# Pure unit tests — no DB needed. Skip setup_db autouse fixture.
pytestmark = pytest.mark.no_db


URLHAUS_RECENT = "https://urlhaus-api.abuse.ch/v1/urls/recent/"


SAMPLE_RECORD = {
    "id": "12345",
    "urlhaus_reference": "https://urlhaus.abuse.ch/url/12345/",
    "url": "http://acme.example/malware/payload.exe",
    "url_status": "online",
    "host": "acme.example",
    "date_added": "2026-04-01 10:00:00",
    "threat": "malware_download",
    "blacklists": {"surbl": "not listed", "spamhaus_dbl": "not listed"},
    "reporter": "anonymous",
    "larted": "true",
    "tags": ["emotet", "exe"],
    "payloads": [
        {"signature": "Emotet", "file_type": "exe", "file_size": "1024"}
    ],
}


SAMPLE_RECORD_MINIMAL = {
    "id": "9999",
    "url": "http://example.test/x",
    "host": "example.test",
}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def collector():
    return URLhausCollector(auth_key="test-auth-key")


@pytest.fixture
def collector_no_key():
    return URLhausCollector(auth_key="")


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------

def test_collector_name(collector):
    assert collector.name == "urlhaus"


def test_collector_poll_interval(collector):
    assert collector.poll_interval_seconds == 600


# ---------------------------------------------------------------------------
# parse_urls() — pure function, no HTTP
# ---------------------------------------------------------------------------

def test_parse_urls_returns_raw_detections(collector):
    results = collector.parse_urls([SAMPLE_RECORD])
    assert len(results) == 1
    assert isinstance(results[0], RawDetection)


def test_parse_urls_url_in_title(collector):
    results = collector.parse_urls([SAMPLE_RECORD])
    assert results[0].title == "http://acme.example/malware/payload.exe"


def test_parse_urls_source_is_collector_name(collector):
    results = collector.parse_urls([SAMPLE_RECORD])
    assert results[0].source == "urlhaus"


def test_parse_urls_source_url_uses_urlhaus_reference(collector):
    results = collector.parse_urls([SAMPLE_RECORD])
    assert results[0].source_url == "https://urlhaus.abuse.ch/url/12345/"


def test_parse_urls_content_includes_threat(collector):
    results = collector.parse_urls([SAMPLE_RECORD])
    assert "malware_download" in results[0].content


def test_parse_urls_content_includes_tags(collector):
    results = collector.parse_urls([SAMPLE_RECORD])
    assert "emotet" in results[0].content


def test_parse_urls_content_includes_payload_signature(collector):
    results = collector.parse_urls([SAMPLE_RECORD])
    assert "Emotet" in results[0].content


def test_parse_urls_raw_payload_preserved(collector):
    results = collector.parse_urls([SAMPLE_RECORD])
    assert results[0].raw_payload == SAMPLE_RECORD


def test_parse_urls_minimal_record_does_not_raise(collector):
    results = collector.parse_urls([SAMPLE_RECORD_MINIMAL])
    assert len(results) == 1
    assert results[0].title == "http://example.test/x"


def test_parse_urls_empty_list(collector):
    assert collector.parse_urls([]) == []


def test_parse_urls_title_truncated_to_500_chars(collector):
    long_url = "http://example.test/" + ("a" * 1000)
    results = collector.parse_urls([{"url": long_url}])
    assert len(results[0].title) <= 500


# ---------------------------------------------------------------------------
# collect() — mocked HTTP
# ---------------------------------------------------------------------------

async def test_collect_returns_detections(collector, httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url=URLHAUS_RECENT,
        json={"query_status": "ok", "urls": [SAMPLE_RECORD]},
    )
    results = await collector.collect()
    assert len(results) == 1
    assert results[0].title == "http://acme.example/malware/payload.exe"


async def test_collect_no_results_query_status(collector, httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url=URLHAUS_RECENT,
        json={"query_status": "no_results", "urls": []},
    )
    results = await collector.collect()
    assert results == []


async def test_collect_unknown_query_status_returns_empty(collector, httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url=URLHAUS_RECENT,
        json={"query_status": "rate_limited", "urls": []},
    )
    results = await collector.collect()
    assert results == []


async def test_collect_no_key_short_circuits(collector_no_key, httpx_mock: HTTPXMock):
    """With no Auth-Key set the collector must return [] without hitting HTTP.

    pytest-httpx fails the test if any unmatched request is made, so this
    implicitly asserts no network call happened.
    """
    results = await collector_no_key.collect()
    assert results == []


async def test_collect_sends_auth_key_header(collector, httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url=URLHAUS_RECENT,
        json={"query_status": "ok", "urls": []},
    )
    await collector.collect()
    requests = httpx_mock.get_requests()
    assert len(requests) == 1
    assert requests[0].headers.get("Auth-Key") == "test-auth-key"


async def test_collect_raises_on_http_error(collector, httpx_mock: HTTPXMock):
    httpx_mock.add_response(url=URLHAUS_RECENT, status_code=503)
    with pytest.raises(Exception):
        await collector.collect()


# ---------------------------------------------------------------------------
# health_check() — mocked HTTP
# ---------------------------------------------------------------------------

async def test_health_check_returns_true_when_no_key(collector_no_key):
    """No key = collector intentionally disabled, not failing."""
    assert await collector_no_key.health_check() is True


async def test_health_check_returns_true_on_200(collector, httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url=URLHAUS_RECENT,
        json={"query_status": "ok", "urls": []},
    )
    assert await collector.health_check() is True


async def test_health_check_returns_false_on_network_error(collector, httpx_mock: HTTPXMock):
    httpx_mock.add_exception(
        url=URLHAUS_RECENT,
        exception=Exception("connection refused"),
    )
    assert await collector.health_check() is False

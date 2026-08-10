"""
Tests for FeodoTrackerCollector.

Covers:
  - Collector metadata
  - parse_records() pure mapping
  - collect() with mocked httpx response
  - No-key path: Feodo's downloads are public, so collect() still works
    without an Auth-Key (the collector logs a debug message but proceeds).
  - health_check() happy + failure paths
  - Auth-Key header is sent when configured
"""
import pytest
from pytest_httpx import HTTPXMock

from app.collectors.feodo_tracker import FeodoTrackerCollector
from app.collectors.base import RawDetection

# Pure unit tests — no DB needed. Skip setup_db autouse fixture.
pytestmark = pytest.mark.no_db


FEODO_JSON = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"


SAMPLE_RECORD = {
    "ip_address": "192.0.2.10",
    "port": 443,
    "status": "online",
    "hostname": None,
    "as_number": 64500,
    "as_name": "EXAMPLE-AS",
    "country": "US",
    "first_seen": "2026-04-01 09:00:00",
    "last_online": "2026-04-02 12:00:00",
    "malware": "Emotet",
}


SAMPLE_RECORD_MINIMAL = {
    "ip_address": "198.51.100.5",
    "port": 80,
}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def collector():
    return FeodoTrackerCollector(auth_key="test-auth-key")


@pytest.fixture
def collector_no_key():
    return FeodoTrackerCollector(auth_key="")


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------

def test_collector_name(collector):
    assert collector.name == "feodo_tracker"


def test_collector_poll_interval(collector):
    assert collector.poll_interval_seconds == 300


# ---------------------------------------------------------------------------
# parse_records()
# ---------------------------------------------------------------------------

def test_parse_records_returns_raw_detections(collector):
    results = collector.parse_records([SAMPLE_RECORD])
    assert len(results) == 1
    assert isinstance(results[0], RawDetection)


def test_parse_records_title_includes_malware_and_ipport(collector):
    results = collector.parse_records([SAMPLE_RECORD])
    assert "Emotet" in results[0].title
    assert "192.0.2.10:443" in results[0].title


def test_parse_records_actor_is_malware_family(collector):
    results = collector.parse_records([SAMPLE_RECORD])
    assert results[0].actor == "Emotet"


def test_parse_records_source_is_collector_name(collector):
    results = collector.parse_records([SAMPLE_RECORD])
    assert results[0].source == "feodo_tracker"


def test_parse_records_content_includes_ip_and_port(collector):
    results = collector.parse_records([SAMPLE_RECORD])
    assert "192.0.2.10" in results[0].content
    assert "443" in results[0].content


def test_parse_records_content_includes_country(collector):
    results = collector.parse_records([SAMPLE_RECORD])
    assert "US" in results[0].content


def test_parse_records_source_url_filters_by_ip(collector):
    results = collector.parse_records([SAMPLE_RECORD])
    assert "192.0.2.10" in results[0].source_url


def test_parse_records_raw_payload_preserved(collector):
    results = collector.parse_records([SAMPLE_RECORD])
    assert results[0].raw_payload == SAMPLE_RECORD


def test_parse_records_minimal_does_not_raise(collector):
    results = collector.parse_records([SAMPLE_RECORD_MINIMAL])
    assert len(results) == 1
    assert results[0].actor is None


def test_parse_records_empty_list(collector):
    assert collector.parse_records([]) == []


# ---------------------------------------------------------------------------
# collect()
# ---------------------------------------------------------------------------

async def test_collect_returns_detections(collector, httpx_mock: HTTPXMock):
    httpx_mock.add_response(url=FEODO_JSON, json=[SAMPLE_RECORD])
    results = await collector.collect()
    assert len(results) == 1
    assert "Emotet" in results[0].title


async def test_collect_handles_wrapped_response(collector, httpx_mock: HTTPXMock):
    """Defensive path: tolerate a {data: [...]} wrapper if abuse.ch ever changes shape."""
    httpx_mock.add_response(url=FEODO_JSON, json={"data": [SAMPLE_RECORD]})
    results = await collector.collect()
    assert len(results) == 1


async def test_collect_empty_array(collector, httpx_mock: HTTPXMock):
    httpx_mock.add_response(url=FEODO_JSON, json=[])
    assert await collector.collect() == []


async def test_collect_works_without_auth_key(collector_no_key, httpx_mock: HTTPXMock):
    """Feodo's blocklist is public — no key still produces results."""
    httpx_mock.add_response(url=FEODO_JSON, json=[SAMPLE_RECORD])
    results = await collector_no_key.collect()
    assert len(results) == 1


async def test_collect_no_auth_key_means_no_auth_header(collector_no_key, httpx_mock: HTTPXMock):
    httpx_mock.add_response(url=FEODO_JSON, json=[])
    await collector_no_key.collect()
    requests = httpx_mock.get_requests()
    assert len(requests) == 1
    assert requests[0].headers.get("Auth-Key") is None


async def test_collect_sends_auth_key_when_configured(collector, httpx_mock: HTTPXMock):
    httpx_mock.add_response(url=FEODO_JSON, json=[])
    await collector.collect()
    requests = httpx_mock.get_requests()
    assert len(requests) == 1
    assert requests[0].headers.get("Auth-Key") == "test-auth-key"


async def test_collect_raises_on_http_error(collector, httpx_mock: HTTPXMock):
    httpx_mock.add_response(url=FEODO_JSON, status_code=503)
    with pytest.raises(Exception):
        await collector.collect()


# ---------------------------------------------------------------------------
# health_check()
# ---------------------------------------------------------------------------

async def test_health_check_returns_true_on_200(collector, httpx_mock: HTTPXMock):
    httpx_mock.add_response(url=FEODO_JSON, json=[])
    assert await collector.health_check() is True


async def test_health_check_returns_false_on_network_error(collector, httpx_mock: HTTPXMock):
    httpx_mock.add_exception(
        url=FEODO_JSON,
        exception=Exception("connection refused"),
    )
    assert await collector.health_check() is False


async def test_health_check_returns_true_on_200_without_key(collector_no_key, httpx_mock: HTTPXMock):
    """Public endpoint — health check works without an Auth-Key."""
    httpx_mock.add_response(url=FEODO_JSON, json=[])
    assert await collector_no_key.health_check() is True

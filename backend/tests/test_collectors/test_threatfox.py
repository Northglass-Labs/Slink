"""
Tests for ThreatFoxCollector.

Covers the abuse.ch Auth-Key migration: the collector must now send
``Auth-Key`` on every request and short-circuit to [] when the key is
unconfigured, like every other credentialed collector in the registry.
"""
import pytest
from pytest_httpx import HTTPXMock

from app.collectors.threatfox import ThreatFoxCollector
from app.collectors.base import RawDetection

# These are pure unit tests — no DB needed. Skip the (autouse) setup_db
# fixture to avoid the schema-DROP/CREATE race on shared test runs.
pytestmark = pytest.mark.no_db


THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"


SAMPLE_IOC = {
    "id": "12345",
    "ioc": "192.0.2.10:443",
    "ioc_type": "ip:port",
    "threat_type": "botnet_cc",
    "malware": "win.emotet",
    "malware_printable": "Emotet",
    "confidence_level": 75,
    "tags": ["emotet", "c2"],
}


SAMPLE_LOW_CONFIDENCE = {**SAMPLE_IOC, "id": "999", "confidence_level": 25}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def collector():
    return ThreatFoxCollector(auth_key="test-auth-key")


@pytest.fixture
def collector_no_key():
    return ThreatFoxCollector(auth_key="")


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------

def test_collector_name(collector):
    assert collector.name == "threatfox"


def test_collector_poll_interval(collector):
    assert collector.poll_interval_seconds == 3600


# ---------------------------------------------------------------------------
# collect()
# ---------------------------------------------------------------------------

async def test_collect_returns_detections(collector, httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url=THREATFOX_API,
        method="POST",
        json={"query_status": "ok", "data": [SAMPLE_IOC]},
    )
    results = await collector.collect()
    assert len(results) == 1
    assert isinstance(results[0], RawDetection)
    assert "Emotet" in results[0].title


async def test_collect_filters_low_confidence(collector, httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url=THREATFOX_API,
        method="POST",
        json={"query_status": "ok", "data": [SAMPLE_IOC, SAMPLE_LOW_CONFIDENCE]},
    )
    results = await collector.collect()
    assert len(results) == 1


async def test_collect_no_key_short_circuits(collector_no_key):
    """No Auth-Key = no HTTP call. pytest-httpx fails on unexpected requests."""
    assert await collector_no_key.collect() == []


async def test_collect_sends_auth_key_header(collector, httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url=THREATFOX_API,
        method="POST",
        json={"query_status": "ok", "data": []},
    )
    await collector.collect()
    requests = httpx_mock.get_requests()
    assert len(requests) == 1
    assert requests[0].headers.get("Auth-Key") == "test-auth-key"


async def test_collect_query_status_not_ok_returns_empty(collector, httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url=THREATFOX_API,
        method="POST",
        json={"query_status": "illegal_query"},
    )
    assert await collector.collect() == []


async def test_collect_raises_on_http_error(collector, httpx_mock: HTTPXMock):
    httpx_mock.add_response(url=THREATFOX_API, method="POST", status_code=503)
    with pytest.raises(Exception):
        await collector.collect()


async def test_collect_source_url_built_from_id(collector, httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url=THREATFOX_API,
        method="POST",
        json={"query_status": "ok", "data": [SAMPLE_IOC]},
    )
    results = await collector.collect()
    assert results[0].source_url == "https://threatfox.abuse.ch/ioc/12345"


# ---------------------------------------------------------------------------
# health_check()
# ---------------------------------------------------------------------------

async def test_health_check_returns_true_when_no_key(collector_no_key):
    assert await collector_no_key.health_check() is True


async def test_health_check_returns_true_on_200(collector, httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url=THREATFOX_API,
        method="POST",
        json={"query_status": "ok", "data": []},
    )
    assert await collector.health_check() is True


async def test_health_check_returns_false_on_network_error(collector, httpx_mock: HTTPXMock):
    httpx_mock.add_exception(
        url=THREATFOX_API,
        method="POST",
        exception=Exception("connection refused"),
    )
    assert await collector.health_check() is False

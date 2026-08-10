"""
Tests for AlienVaultOTXCollector.

Unit tests:
  - Collector metadata (name, poll_interval_seconds)
  - parse_pulses() with sample OTX pulse shapes

Integration tests (mocked HTTP via pytest-httpx):
  - collect(): fetch subscribed pulses
  - health_check(): user/me endpoint 200 and non-200 paths

OTX /api/v1/pulses/subscribed response shape:
  {"results": [...pulses...], "count": N, "next": "...", "previous": null}
"""
import pytest
from pytest_httpx import HTTPXMock

from app.collectors.alienvault_otx import AlienVaultOTXCollector
from app.collectors.base import RawDetection


OTX_BASE = "https://otx.alienvault.com"

SAMPLE_PULSE = {
    "id": "5f3e1a2b3c4d5e6f7a8b9c0d",
    "name": "LockBit 3.0 Infrastructure IOCs",
    "description": "IP addresses and domains used by LockBit 3.0 in recent campaigns.",
    "author_name": "threat_researcher",
    "adversary": "LockBit",
    "tags": ["ransomware", "lockbit", "ioc"],
    "malware_families": [{"display_name": "LockBit"}],
    "pulse_source": "web",
    "created": "2026-03-24T10:00:00Z",
    "TLP": "white",
}

SAMPLE_PULSE_MINIMAL = {
    "id": "aabbccdd",
    "name": "",
}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def collector():
    return AlienVaultOTXCollector(api_key="test-otx-api-key")


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------

def test_collector_name(collector):
    assert collector.name == "alienvault_otx"


def test_collector_poll_interval(collector):
    assert collector.poll_interval_seconds == 300


# ---------------------------------------------------------------------------
# parse_pulses() — pure function, no HTTP
# ---------------------------------------------------------------------------

def test_parse_pulses_returns_raw_detections(collector):
    results = collector.parse_pulses([SAMPLE_PULSE])
    assert len(results) == 1
    assert isinstance(results[0], RawDetection)


def test_parse_pulses_maps_name_to_title(collector):
    results = collector.parse_pulses([SAMPLE_PULSE])
    assert results[0].title == "LockBit 3.0 Infrastructure IOCs"


def test_parse_pulses_maps_adversary_to_actor(collector):
    results = collector.parse_pulses([SAMPLE_PULSE])
    assert results[0].actor == "LockBit"


def test_parse_pulses_builds_source_url_from_id(collector):
    results = collector.parse_pulses([SAMPLE_PULSE])
    expected = f"{OTX_BASE}/pulse/5f3e1a2b3c4d5e6f7a8b9c0d"
    assert results[0].source_url == expected


def test_parse_pulses_source_is_collector_name(collector):
    results = collector.parse_pulses([SAMPLE_PULSE])
    assert results[0].source == "alienvault_otx"


def test_parse_pulses_content_includes_description(collector):
    results = collector.parse_pulses([SAMPLE_PULSE])
    assert "LockBit 3.0 in recent campaigns" in results[0].content


def test_parse_pulses_content_includes_adversary(collector):
    results = collector.parse_pulses([SAMPLE_PULSE])
    assert "LockBit" in results[0].content


def test_parse_pulses_content_includes_tags(collector):
    results = collector.parse_pulses([SAMPLE_PULSE])
    assert "ransomware" in results[0].content


def test_parse_pulses_content_includes_malware_family(collector):
    results = collector.parse_pulses([SAMPLE_PULSE])
    assert "LockBit" in results[0].content


def test_parse_pulses_raw_payload_preserved(collector):
    results = collector.parse_pulses([SAMPLE_PULSE])
    assert results[0].raw_payload == SAMPLE_PULSE


def test_parse_pulses_empty_list(collector):
    assert collector.parse_pulses([]) == []


def test_parse_pulses_multiple_pulses(collector):
    second = {**SAMPLE_PULSE, "id": "99887766", "name": "Second Pulse"}
    results = collector.parse_pulses([SAMPLE_PULSE, second])
    assert len(results) == 2
    assert results[1].title == "Second Pulse"


def test_parse_pulses_empty_adversary_sets_actor_none(collector):
    pulse = {**SAMPLE_PULSE, "adversary": ""}
    results = collector.parse_pulses([pulse])
    assert results[0].actor is None


def test_parse_pulses_minimal_does_not_raise(collector):
    """A pulse with only 'id' and empty name should parse without raising."""
    results = collector.parse_pulses([SAMPLE_PULSE_MINIMAL])
    assert len(results) == 1
    assert results[0].actor is None


def test_parse_pulses_empty_id_gives_empty_source_url(collector):
    pulse = {**SAMPLE_PULSE, "id": ""}
    results = collector.parse_pulses([pulse])
    assert results[0].source_url == ""


# ---------------------------------------------------------------------------
# collect() — mocked HTTP
# ---------------------------------------------------------------------------

async def test_collect_returns_detections(collector, httpx_mock: HTTPXMock):
    """collect() hits the subscribed pulses endpoint and parses results."""
    httpx_mock.add_response(
        url=f"{OTX_BASE}/api/v1/pulses/subscribed?limit=50",
        json={"results": [SAMPLE_PULSE], "count": 1},
    )
    results = await collector.collect()
    assert len(results) == 1
    assert results[0].title == "LockBit 3.0 Infrastructure IOCs"


async def test_collect_empty_results(collector, httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url=f"{OTX_BASE}/api/v1/pulses/subscribed?limit=50",
        json={"results": [], "count": 0},
    )
    results = await collector.collect()
    assert results == []


async def test_collect_raises_on_http_error(collector, httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url=f"{OTX_BASE}/api/v1/pulses/subscribed?limit=50",
        status_code=503,
    )
    with pytest.raises(Exception):
        await collector.collect()


# ---------------------------------------------------------------------------
# health_check() — mocked HTTP
# ---------------------------------------------------------------------------

async def test_health_check_returns_true_on_200(collector, httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url=f"{OTX_BASE}/api/v1/user/me",
        status_code=200,
        json={"username": "test_user"},
    )
    assert await collector.health_check() is True


async def test_health_check_returns_false_on_401(collector, httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url=f"{OTX_BASE}/api/v1/user/me",
        status_code=401,
        json={"detail": "Invalid API key"},
    )
    assert await collector.health_check() is False


async def test_health_check_returns_false_on_network_error(collector, httpx_mock: HTTPXMock):
    httpx_mock.add_exception(
        url=f"{OTX_BASE}/api/v1/user/me",
        exception=Exception("connection refused"),
    )
    assert await collector.health_check() is False

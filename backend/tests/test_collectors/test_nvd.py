"""
Tests for NVDCollector.

Unit tests cover the pure mapping helpers (_parse_vulnerabilities, _format_cvss,
_english_description). Integration tests use pytest-httpx to stub the NVD CVE
API 2.0 responses for collect() and health_check().

NVD CVE API 2.0 response shape (trimmed to what the collector reads):
  {"vulnerabilities": [
    {"cve": {
      "id": "CVE-YYYY-NNNNN",
      "descriptions": [{"lang": "en", "value": "..."}],
      "metrics": {"cvssMetricV31": [{"cvssData": {
        "baseScore": float, "baseSeverity": "CRITICAL", "vectorString": "..."
      }}]}
    }}
  ]}
"""
import re

import pytest
from pytest_httpx import HTTPXMock

from app.collectors.base import RawDetection
from app.collectors.nvd import (
    NVDCollector,
    _english_description,
    _format_cvss,
)

# This whole module is pure HTTP-mocking + unit tests — no DB needed. The
# marker tells the autouse setup_db fixture to skip the DROP/CREATE cycle,
# which is both faster and avoids an intermittent race in the schema reset.
pytestmark = pytest.mark.no_db


SAMPLE_CVE = {
    "cve": {
        "id": "CVE-2026-12345",
        "published": "2026-04-30T00:00:00.000",
        "lastModified": "2026-04-30T01:00:00.000",
        "vulnStatus": "Analyzed",
        "descriptions": [
            {"lang": "en", "value": "An example RCE in the acme-corp widget service."},
            {"lang": "es", "value": "Ejecución remota de código en acme-corp."},
        ],
        "metrics": {
            "cvssMetricV31": [
                {
                    "source": "nvd@nist.gov",
                    "type": "Primary",
                    "cvssData": {
                        "baseScore": 9.8,
                        "baseSeverity": "CRITICAL",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    },
                }
            ]
        },
    }
}

SAMPLE_CVE_NO_METRICS = {
    "cve": {
        "id": "CVE-2026-99999",
        "descriptions": [{"lang": "en", "value": "Reserved CVE — no metrics yet."}],
        "metrics": {},
    }
}

SAMPLE_CVE_V2_ONLY = {
    "cve": {
        "id": "CVE-2010-00001",
        "descriptions": [{"lang": "en", "value": "Legacy CVE with only v2 metrics."}],
        "metrics": {
            "cvssMetricV2": [
                {
                    "cvssData": {
                        "baseScore": 7.5,
                        "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
                    },
                    "baseSeverity": "HIGH",
                }
            ]
        },
    }
}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def collector():
    return NVDCollector(api_key="test-nvd-api-key")


@pytest.fixture
def anon_collector():
    """An anonymous-mode NVD collector — exercises the no-key code path."""
    return NVDCollector(api_key=None)


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------

def test_collector_name(collector):
    assert collector.name == "nvd"


def test_collector_poll_interval(collector):
    assert collector.poll_interval_seconds == 3600


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------

def test_english_description_picks_en_when_present():
    descriptions = [
        {"lang": "fr", "value": "FR"},
        {"lang": "en", "value": "EN"},
    ]
    assert _english_description(descriptions) == "EN"


def test_english_description_falls_back_to_first():
    descriptions = [{"lang": "fr", "value": "FR only"}]
    assert _english_description(descriptions) == "FR only"


def test_english_description_empty_list():
    assert _english_description([]) == ""


def test_format_cvss_prefers_v31():
    metrics = {
        "cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL", "vectorString": "AV:N"}}],
        "cvssMetricV2": [{"cvssData": {"baseScore": 7.5, "vectorString": "AV:L"}, "baseSeverity": "HIGH"}],
    }
    out = _format_cvss(metrics)
    assert "CVSS v3.1" in out
    assert "9.8" in out
    assert "CRITICAL" in out
    assert "CVSS v2" not in out


def test_format_cvss_falls_back_to_v2_when_v3_absent():
    metrics = {
        "cvssMetricV2": [
            {"cvssData": {"baseScore": 7.5, "vectorString": "AV:L"}, "baseSeverity": "HIGH"}
        ]
    }
    out = _format_cvss(metrics)
    assert "CVSS v2" in out
    assert "7.5" in out


def test_format_cvss_empty_when_no_metrics():
    assert _format_cvss({}) == ""


# ---------------------------------------------------------------------------
# _parse_vulnerabilities — pure mapping
# ---------------------------------------------------------------------------

def test_parse_returns_raw_detections(collector):
    out = collector._parse_vulnerabilities([SAMPLE_CVE])
    assert len(out) == 1
    assert isinstance(out[0], RawDetection)


def test_parse_title_starts_with_cve_id(collector):
    out = collector._parse_vulnerabilities([SAMPLE_CVE])
    assert out[0].title.startswith("CVE-2026-12345 — ")


def test_parse_title_uses_first_100_chars_of_description(collector):
    long_desc = "A" * 500
    item = {
        "cve": {
            "id": "CVE-2026-00001",
            "descriptions": [{"lang": "en", "value": long_desc}],
            "metrics": {},
        }
    }
    out = collector._parse_vulnerabilities([item])
    # Description portion of the title should be no more than 100 chars,
    # and the title overall is "CVE-... — <100 chars>".
    title = out[0].title
    desc_portion = title.split(" — ", 1)[1]
    assert len(desc_portion) <= 100


def test_parse_source_url_built_from_cve_id(collector):
    out = collector._parse_vulnerabilities([SAMPLE_CVE])
    assert out[0].source_url == "https://nvd.nist.gov/vuln/detail/CVE-2026-12345"


def test_parse_source_is_collector_name(collector):
    out = collector._parse_vulnerabilities([SAMPLE_CVE])
    assert out[0].source == "nvd"


def test_parse_content_includes_description(collector):
    out = collector._parse_vulnerabilities([SAMPLE_CVE])
    assert "acme-corp widget service" in out[0].content


def test_parse_content_includes_cvss_score(collector):
    out = collector._parse_vulnerabilities([SAMPLE_CVE])
    assert "9.8" in out[0].content
    assert "CRITICAL" in out[0].content


def test_parse_raw_payload_preserved(collector):
    out = collector._parse_vulnerabilities([SAMPLE_CVE])
    assert out[0].raw_payload == SAMPLE_CVE


def test_parse_skips_entries_without_cve_id(collector):
    bogus = {"cve": {"id": "", "descriptions": []}}
    out = collector._parse_vulnerabilities([bogus, SAMPLE_CVE])
    assert len(out) == 1
    assert out[0].title.startswith("CVE-2026-12345")


def test_parse_handles_missing_metrics(collector):
    out = collector._parse_vulnerabilities([SAMPLE_CVE_NO_METRICS])
    assert len(out) == 1
    # No CVSS data — content should be the description alone.
    assert "Reserved CVE" in out[0].content
    assert "CVSS" not in out[0].content


def test_parse_handles_v2_only_metrics(collector):
    out = collector._parse_vulnerabilities([SAMPLE_CVE_V2_ONLY])
    assert len(out) == 1
    assert "CVSS v2" in out[0].content


def test_parse_empty_list(collector):
    assert collector._parse_vulnerabilities([]) == []


# ---------------------------------------------------------------------------
# collect() — mocked HTTP
# ---------------------------------------------------------------------------

# Match any URL with the NVD base — date params shift on every call.
_NVD_URL_PATTERN = re.compile(r"^https://services\.nvd\.nist\.gov/rest/json/cves/2\.0")


async def test_collect_returns_detections(collector, httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url=_NVD_URL_PATTERN,
        json={"vulnerabilities": [SAMPLE_CVE], "totalResults": 1},
    )
    results = await collector.collect()
    assert len(results) == 1
    assert results[0].title.startswith("CVE-2026-12345")


async def test_collect_empty_results(collector, httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url=_NVD_URL_PATTERN,
        json={"vulnerabilities": [], "totalResults": 0},
    )
    assert await collector.collect() == []


async def test_collect_raises_on_http_error(collector, httpx_mock: HTTPXMock):
    httpx_mock.add_response(url=_NVD_URL_PATTERN, status_code=503)
    with pytest.raises(Exception):
        await collector.collect()


async def test_collect_anonymous_mode_still_works(anon_collector, httpx_mock: HTTPXMock):
    """No API key is allowed — NVD is usable anonymously, just slower.

    This is the deliberate departure from the "no key = no-op" pattern.
    """
    httpx_mock.add_response(
        url=_NVD_URL_PATTERN,
        json={"vulnerabilities": [SAMPLE_CVE]},
    )
    results = await anon_collector.collect()
    assert len(results) == 1


async def test_collect_sends_apikey_header_when_configured(
    collector, httpx_mock: HTTPXMock
):
    """The API key must be sent in the 'apiKey' header per NVD docs."""
    httpx_mock.add_response(
        url=_NVD_URL_PATTERN,
        json={"vulnerabilities": []},
    )
    await collector.collect()
    request = httpx_mock.get_requests()[-1]
    assert request.headers.get("apiKey") == "test-nvd-api-key"


async def test_collect_omits_apikey_header_when_anonymous(
    anon_collector, httpx_mock: HTTPXMock
):
    httpx_mock.add_response(url=_NVD_URL_PATTERN, json={"vulnerabilities": []})
    await anon_collector.collect()
    request = httpx_mock.get_requests()[-1]
    assert "apiKey" not in request.headers


# ---------------------------------------------------------------------------
# health_check() — mocked HTTP
# ---------------------------------------------------------------------------

async def test_health_check_returns_true_on_200(collector, httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url=re.compile(r"^https://services\.nvd\.nist\.gov/.*"),
        status_code=200,
        json={"vulnerabilities": []},
    )
    assert await collector.health_check() is True


async def test_health_check_returns_false_on_500(collector, httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url=re.compile(r"^https://services\.nvd\.nist\.gov/.*"),
        status_code=500,
    )
    assert await collector.health_check() is False


async def test_health_check_returns_false_on_network_error(collector, httpx_mock: HTTPXMock):
    httpx_mock.add_exception(
        url=re.compile(r"^https://services\.nvd\.nist\.gov/.*"),
        exception=Exception("connection refused"),
    )
    assert await collector.health_check() is False

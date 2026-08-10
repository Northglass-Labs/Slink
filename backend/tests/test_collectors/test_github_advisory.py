"""
Tests for GitHubAdvisoryCollector.

Unit tests cover the pure mapping helpers (_parse_advisories, _cve_identifiers,
_format_packages). Integration tests use pytest-httpx to stub the GraphQL
endpoint for collect() and health_check().

GraphQL response shape (trimmed to what the collector reads):
  {"data": {"securityAdvisories": {"nodes": [
    {"ghsaId": "GHSA-xxxx-xxxx-xxxx", "summary": "...", "description": "...",
     "severity": "HIGH"|"CRITICAL", "publishedAt": ISO8601,
     "permalink": "https://github.com/advisories/GHSA-...",
     "identifiers": [{"type": "GHSA"|"CVE", "value": "..."}],
     "references": [{"url": "..."}],
     "vulnerabilities": {"nodes": [
       {"package": {"ecosystem": "NPM", "name": "..."},
        "vulnerableVersionRange": "< 1.2.3",
        "firstPatchedVersion": {"identifier": "1.2.3"}}
     ]}}
  ]}}}
"""
import pytest
from pytest_httpx import HTTPXMock

from app.collectors.base import RawDetection
from app.collectors.github_advisory import (
    GitHubAdvisoryCollector,
    _GITHUB_GRAPHQL,
    _cve_identifiers,
    _format_packages,
)

# This whole module is pure HTTP-mocking + unit tests — no DB needed. The
# marker tells the autouse setup_db fixture to skip the DROP/CREATE cycle,
# which is both faster and avoids an intermittent race in the schema reset.
pytestmark = pytest.mark.no_db


SAMPLE_ADVISORY = {
    "ghsaId": "GHSA-aaaa-bbbb-cccc",
    "summary": "Prototype pollution in acme-utils",
    "description": "A prototype pollution vulnerability allows arbitrary property write.",
    "severity": "HIGH",
    "publishedAt": "2026-04-30T00:00:00Z",
    "updatedAt": "2026-04-30T01:00:00Z",
    "permalink": "https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
    "origin": "UNSPECIFIED",
    "identifiers": [
        {"type": "GHSA", "value": "GHSA-aaaa-bbbb-cccc"},
        {"type": "CVE", "value": "CVE-2026-12345"},
    ],
    "references": [{"url": "https://example.invalid/advisory"}],
    "vulnerabilities": {
        "nodes": [
            {
                "package": {"ecosystem": "NPM", "name": "acme-utils"},
                "vulnerableVersionRange": "< 1.2.3",
                "firstPatchedVersion": {"identifier": "1.2.3"},
            }
        ]
    },
}

SAMPLE_ADVISORY_LOW = {
    "ghsaId": "GHSA-low-low-low0",
    "summary": "Low severity, no CVE",
    "description": "",
    "severity": "LOW",
    "publishedAt": "2026-04-30T00:00:00Z",
    "permalink": "https://github.com/advisories/GHSA-low-low-low0",
    "identifiers": [{"type": "GHSA", "value": "GHSA-low-low-low0"}],
    "references": [],
    "vulnerabilities": {"nodes": []},
}

SAMPLE_ADVISORY_LOW_WITH_CVE = {
    "ghsaId": "GHSA-cve0-cve0-cve0",
    "summary": "Low severity but has a CVE — keep it",
    "description": "",
    "severity": "LOW",
    "publishedAt": "2026-04-30T00:00:00Z",
    "permalink": "https://github.com/advisories/GHSA-cve0-cve0-cve0",
    "identifiers": [
        {"type": "GHSA", "value": "GHSA-cve0-cve0-cve0"},
        {"type": "CVE", "value": "CVE-2026-99999"},
    ],
    "references": [],
    "vulnerabilities": {"nodes": []},
}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def collector():
    return GitHubAdvisoryCollector(token="test-github-token")


@pytest.fixture
def no_token_collector():
    return GitHubAdvisoryCollector(token=None)


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------

def test_collector_name(collector):
    assert collector.name == "github_advisory"


def test_collector_poll_interval(collector):
    assert collector.poll_interval_seconds == 1800


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------

def test_cve_identifiers_extracts_cve_only():
    ids = [
        {"type": "GHSA", "value": "GHSA-aaaa"},
        {"type": "CVE", "value": "CVE-2026-1"},
        {"type": "cve", "value": "CVE-2026-2"},  # case-insensitive
    ]
    assert _cve_identifiers(ids) == ["CVE-2026-1", "CVE-2026-2"]


def test_cve_identifiers_empty_list_returns_empty():
    assert _cve_identifiers([]) == []


def test_format_packages_renders_ecosystem_name_range():
    block = _format_packages({"nodes": [
        {
            "package": {"ecosystem": "NPM", "name": "acme-utils"},
            "vulnerableVersionRange": "< 1.2.3",
            "firstPatchedVersion": {"identifier": "1.2.3"},
        }
    ]})
    assert "NPM:acme-utils" in block
    assert "< 1.2.3" in block
    assert "1.2.3" in block


def test_format_packages_handles_missing_patched_version():
    block = _format_packages({"nodes": [
        {
            "package": {"ecosystem": "PIP", "name": "acme-py"},
            "vulnerableVersionRange": ">= 0.1.0",
            "firstPatchedVersion": None,
        }
    ]})
    assert "PIP:acme-py" in block
    assert "patched" not in block


def test_format_packages_empty_returns_empty():
    assert _format_packages({}) == ""
    assert _format_packages({"nodes": []}) == ""


# ---------------------------------------------------------------------------
# _parse_advisories — pure mapping
# ---------------------------------------------------------------------------

def test_parse_returns_raw_detections(collector):
    out = collector._parse_advisories([SAMPLE_ADVISORY])
    assert len(out) == 1
    assert isinstance(out[0], RawDetection)


def test_parse_title_starts_with_ghsa_id(collector):
    out = collector._parse_advisories([SAMPLE_ADVISORY])
    assert out[0].title.startswith("GHSA-aaaa-bbbb-cccc — ")
    assert "Prototype pollution" in out[0].title


def test_parse_source_url_uses_permalink(collector):
    out = collector._parse_advisories([SAMPLE_ADVISORY])
    assert out[0].source_url == "https://github.com/advisories/GHSA-aaaa-bbbb-cccc"


def test_parse_source_is_collector_name(collector):
    out = collector._parse_advisories([SAMPLE_ADVISORY])
    assert out[0].source == "github_advisory"


def test_parse_content_includes_summary_and_description(collector):
    out = collector._parse_advisories([SAMPLE_ADVISORY])
    assert "Prototype pollution in acme-utils" in out[0].content
    assert "arbitrary property write" in out[0].content


def test_parse_content_includes_cve_refs(collector):
    out = collector._parse_advisories([SAMPLE_ADVISORY])
    assert "CVE-2026-12345" in out[0].content


def test_parse_content_includes_affected_packages(collector):
    out = collector._parse_advisories([SAMPLE_ADVISORY])
    assert "NPM:acme-utils" in out[0].content


def test_parse_raw_payload_preserved(collector):
    out = collector._parse_advisories([SAMPLE_ADVISORY])
    assert out[0].raw_payload == SAMPLE_ADVISORY


def test_parse_skips_low_severity_without_cve(collector):
    """LOW + no CVE = filtered out."""
    out = collector._parse_advisories([SAMPLE_ADVISORY_LOW])
    assert out == []


def test_parse_keeps_low_severity_with_cve(collector):
    """LOW but has a CVE — included per the brief's 'all CVEs' clause."""
    out = collector._parse_advisories([SAMPLE_ADVISORY_LOW_WITH_CVE])
    assert len(out) == 1
    assert "CVE-2026-99999" in out[0].content


def test_parse_empty_list(collector):
    assert collector._parse_advisories([]) == []


def test_parse_critical_passes_through(collector):
    advisory = {**SAMPLE_ADVISORY, "severity": "CRITICAL"}
    out = collector._parse_advisories([advisory])
    assert len(out) == 1
    assert "CRITICAL" in out[0].content


# ---------------------------------------------------------------------------
# collect() — mocked HTTP
# ---------------------------------------------------------------------------

async def test_collect_returns_detections(collector, httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url=_GITHUB_GRAPHQL,
        json={"data": {"securityAdvisories": {"nodes": [SAMPLE_ADVISORY]}}},
    )
    results = await collector.collect()
    assert len(results) == 1
    assert results[0].title.startswith("GHSA-aaaa-bbbb-cccc")


async def test_collect_no_token_returns_empty(no_token_collector):
    """No token = collector intentionally disabled, no HTTP made."""
    results = await no_token_collector.collect()
    assert results == []


async def test_collect_empty_nodes(collector, httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url=_GITHUB_GRAPHQL,
        json={"data": {"securityAdvisories": {"nodes": []}}},
    )
    assert await collector.collect() == []


async def test_collect_raises_on_http_error(collector, httpx_mock: HTTPXMock):
    httpx_mock.add_response(url=_GITHUB_GRAPHQL, status_code=502)
    with pytest.raises(Exception):
        await collector.collect()


async def test_collect_raises_on_graphql_errors(collector, httpx_mock: HTTPXMock):
    """GraphQL errors arrive at HTTP 200 — must surface as an exception."""
    httpx_mock.add_response(
        url=_GITHUB_GRAPHQL,
        json={"errors": [{"message": "Bad credentials"}]},
    )
    with pytest.raises(Exception):
        await collector.collect()


async def test_collect_sends_authorization_header(collector, httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url=_GITHUB_GRAPHQL,
        json={"data": {"securityAdvisories": {"nodes": []}}},
    )
    await collector.collect()
    request = httpx_mock.get_requests()[-1]
    assert request.headers.get("Authorization") == "Bearer test-github-token"


# ---------------------------------------------------------------------------
# health_check() — mocked HTTP
# ---------------------------------------------------------------------------

async def test_health_check_no_token_returns_true(no_token_collector):
    """No token configured = collector intentionally disabled, not failing."""
    assert await no_token_collector.health_check() is True


async def test_health_check_returns_true_on_200_with_data(collector, httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url=_GITHUB_GRAPHQL,
        json={"data": {"viewer": {"login": "test_user"}}},
    )
    assert await collector.health_check() is True


async def test_health_check_returns_false_on_401(collector, httpx_mock: HTTPXMock):
    httpx_mock.add_response(url=_GITHUB_GRAPHQL, status_code=401)
    assert await collector.health_check() is False


async def test_health_check_returns_false_on_graphql_errors(collector, httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url=_GITHUB_GRAPHQL,
        json={"errors": [{"message": "Bad credentials"}]},
    )
    assert await collector.health_check() is False


async def test_health_check_returns_false_on_network_error(collector, httpx_mock: HTTPXMock):
    httpx_mock.add_exception(
        url=_GITHUB_GRAPHQL,
        exception=Exception("connection refused"),
    )
    assert await collector.health_check() is False

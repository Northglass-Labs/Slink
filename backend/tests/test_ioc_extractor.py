"""Tests for the IOC extractor service."""
import pytest
from datetime import datetime, timezone

from app.models.detection import Detection
from app.models.indicator import Indicator
from app.services.ioc_extractor import (
    extract_indicators,
    _extract_from_text,
    _extract_otx,
    _extract_crowdstrike,
    _extract_threatfox,
    _map_otx_type,
    _map_cs_type,
    _map_threatfox_type,
)


# ---------------------------------------------------------------------------
# Unit tests for regex extraction (no DB needed)
# ---------------------------------------------------------------------------

class TestExtractFromText:
    """Test the regex-based text extraction (no DB)."""

    def test_extracts_cve(self):
        text = "Exploits CVE-2024-1234 and CVE-2023-99999 are active."
        now = datetime.now(timezone.utc)
        results = _extract_from_text(text, detection_id=1, source="test", now=now)
        cves = [r for r in results if r["type"] == "cve"]
        assert len(cves) == 2
        assert cves[0]["value"] == "CVE-2024-1234"
        assert cves[1]["value"] == "CVE-2023-99999"

    def test_extracts_sha256(self):
        sha = "a" * 64
        text = f"Hash: {sha}"
        now = datetime.now(timezone.utc)
        results = _extract_from_text(text, detection_id=1, source="test", now=now)
        sha_results = [r for r in results if r["type"] == "hash_sha256"]
        assert len(sha_results) == 1
        assert sha_results[0]["value"] == sha

    def test_extracts_md5(self):
        md5 = "d41d8cd98f00b204e9800998ecf8427e"
        text = f"MD5: {md5}"
        now = datetime.now(timezone.utc)
        results = _extract_from_text(text, detection_id=1, source="test", now=now)
        md5_results = [r for r in results if r["type"] == "hash_md5"]
        assert len(md5_results) == 1
        assert md5_results[0]["value"] == md5

    def test_md5_not_extracted_when_substring_of_sha256(self):
        """MD5-length substrings of a SHA256 should not be extracted separately."""
        sha = "a" * 64
        text = f"Hash: {sha}"
        now = datetime.now(timezone.utc)
        results = _extract_from_text(text, detection_id=1, source="test", now=now)
        md5_results = [r for r in results if r["type"] == "hash_md5"]
        assert len(md5_results) == 0

    def test_empty_text_returns_empty(self):
        now = datetime.now(timezone.utc)
        results = _extract_from_text("", detection_id=1, source="test", now=now)
        assert results == []

    def test_no_iocs_returns_empty(self):
        now = datetime.now(timezone.utc)
        results = _extract_from_text("No indicators here.", detection_id=1, source="test", now=now)
        assert results == []

    def test_extracts_public_ipv4(self):
        text = "C2 server at 8.8.8.8 talks to victims"
        now = datetime.now(timezone.utc)
        results = _extract_from_text(text, detection_id=1, source="test", now=now)
        ips = [r for r in results if r["type"] == "ipv4"]
        assert len(ips) == 1
        assert ips[0]["value"] == "8.8.8.8"

    def test_skips_private_and_loopback_ipv4(self):
        text = "Local hosts: 192.168.1.1, 10.0.0.5, 127.0.0.1, 172.16.0.1"
        now = datetime.now(timezone.utc)
        results = _extract_from_text(text, detection_id=1, source="test", now=now)
        ips = [r for r in results if r["type"] == "ipv4"]
        assert ips == []

    def test_skips_invalid_ipv4_octets(self):
        text = "Bad octets: 999.999.999.999"
        now = datetime.now(timezone.utc)
        results = _extract_from_text(text, detection_id=1, source="test", now=now)
        ips = [r for r in results if r["type"] == "ipv4"]
        assert ips == []

    def test_extracts_valid_domain(self):
        text = "Credential domains: auth.acme.example, acme.example"
        now = datetime.now(timezone.utc)
        results = _extract_from_text(text, detection_id=1, source="test", now=now)
        domains = [r for r in results if r["type"] == "domain"]
        values = {d["value"] for d in domains}
        assert "auth.acme.example" in values
        assert "acme.example" in values

    def test_skips_blocklisted_domains(self):
        text = "Reference example.com and python.org docs"
        now = datetime.now(timezone.utc)
        results = _extract_from_text(text, detection_id=1, source="test", now=now)
        domains = [r for r in results if r["type"] == "domain"]
        assert domains == []

    def test_skips_version_string_as_domain(self):
        text = "Python 3.11.4 was released"
        now = datetime.now(timezone.utc)
        results = _extract_from_text(text, detection_id=1, source="test", now=now)
        domains = [r for r in results if r["type"] == "domain"]
        assert domains == []

    def test_skips_unknown_tld_as_domain(self):
        text = "File at config.local or some.fakeextension"
        now = datetime.now(timezone.utc)
        results = _extract_from_text(text, detection_id=1, source="test", now=now)
        domains = [r for r in results if r["type"] == "domain"]
        assert domains == []

    def test_dedups_same_domain(self):
        text = "evil.com sent to evil.com via EVIL.COM"
        now = datetime.now(timezone.utc)
        results = _extract_from_text(text, detection_id=1, source="test", now=now)
        domains = [r for r in results if r["type"] == "domain"]
        assert len(domains) == 1


class TestExtractOtx:
    """Test OTX extraction logic."""

    def test_extracts_indicators_array(self):
        raw = {
            "indicators": [
                {"type": "FileHash-MD5", "indicator": "d41d8cd98f00b204e9800998ecf8427e"},
                {"type": "IPv4", "indicator": "192.168.1.1"},
                {"type": "domain", "indicator": "evil.com"},
                {"type": "UnknownType", "indicator": "skip_me"},
            ]
        }
        now = datetime.now(timezone.utc)
        results = _extract_otx(raw, detection_id=1, source="alienvault_otx", now=now)
        # Should pick up MD5, IPv4, domain but not UnknownType
        assert len(results) == 3
        types = [r["type"] for r in results]
        assert "hash_md5" in types
        assert "ipv4" in types
        assert "domain" in types

    def test_extracts_attack_ids(self):
        raw = {
            "attack_ids": [
                {"id": "T1059", "name": "Command and Scripting Interpreter"},
                {"id": "T1566.001", "name": "Spearphishing Attachment"},
            ]
        }
        now = datetime.now(timezone.utc)
        results = _extract_otx(raw, detection_id=1, source="alienvault_otx", now=now)
        assert len(results) == 2
        assert all(r["type"] == "mitre_technique" for r in results)
        assert results[0]["value"] == "T1059"

    def test_extracts_malware_families(self):
        raw = {
            "malware_families": [
                {"display_name": "Emotet"},
                {"display_name": "TrickBot"},
            ]
        }
        now = datetime.now(timezone.utc)
        results = _extract_otx(raw, detection_id=1, source="alienvault_otx", now=now)
        assert len(results) == 2
        assert all(r["type"] == "malware_family" for r in results)

    def test_empty_raw_data(self):
        now = datetime.now(timezone.utc)
        results = _extract_otx({}, detection_id=1, source="alienvault_otx", now=now)
        assert results == []


class TestExtractCrowdStrike:
    """Test CrowdStrike extraction logic."""

    def test_extracts_from_indicators_field(self):
        raw = {
            "indicators": [
                {"type": "md5", "value": "d41d8cd98f00b204e9800998ecf8427e"},
                {"type": "sha256", "value": "a" * 64},
                {"type": "ip_address", "value": "10.0.0.1"},
            ]
        }
        now = datetime.now(timezone.utc)
        results = _extract_crowdstrike(raw, detection_id=1, source="crowdstrike_intel", now=now)
        assert len(results) == 3

    def test_skips_non_dict_entries(self):
        raw = {
            "indicators": ["just_a_string", 123, None]
        }
        now = datetime.now(timezone.utc)
        results = _extract_crowdstrike(raw, detection_id=1, source="crowdstrike_intel", now=now)
        assert results == []

    def test_skips_unknown_types(self):
        raw = {
            "indicators": [
                {"type": "unknown_thing", "value": "some_value"},
            ]
        }
        now = datetime.now(timezone.utc)
        results = _extract_crowdstrike(raw, detection_id=1, source="crowdstrike_intel", now=now)
        assert results == []

    def test_recon_extracts_credentials_domains_from_breach_summary(self):
        """CS Recon credentials_domains array should produce domain indicators."""
        raw = {
            "breach_summary": {
                "credentials_domains": ["auth.acme.example", "acme.example"],
            }
        }
        now = datetime.now(timezone.utc)
        results = _extract_crowdstrike(
            raw, detection_id=1, source="crowdstrike_recon", now=now
        )
        domains = [r["value"] for r in results if r["type"] == "domain"]
        assert "auth.acme.example" in domains
        assert "acme.example" in domains

    def test_recon_falls_back_to_snippet_regex(self):
        """CS Recon should regex-extract from snippet when structured fields are empty."""
        raw = {}
        snippet = (
            "Exposed data containing credentials\n"
            "Rule: acme-corp.example\n"
            "Credential domains: acme-corp.example, login.acme-corp.example"
        )
        now = datetime.now(timezone.utc)
        results = _extract_crowdstrike(
            raw, detection_id=1, source="crowdstrike_recon", now=now, snippet=snippet
        )
        domains = {r["value"] for r in results if r["type"] == "domain"}
        assert "acme-corp.example" in domains
        assert "login.acme-corp.example" in domains

    def test_recon_dedups_structured_and_snippet_results(self):
        """If a domain appears in both breach_summary and snippet, only emit once."""
        raw = {
            "breach_summary": {
                "credentials_domains": ["acme.example"],
            }
        }
        snippet = "Credential domains: acme.example"
        now = datetime.now(timezone.utc)
        results = _extract_crowdstrike(
            raw, detection_id=1, source="crowdstrike_recon", now=now, snippet=snippet
        )
        matching = [
            r for r in results
            if r["type"] == "domain" and r["value"] == "acme.example"
        ]
        assert len(matching) == 1

    def test_intel_does_not_pull_credentials_domains(self):
        """Only CS Recon should consult breach_summary; CS Intel should skip it."""
        raw = {
            "breach_summary": {
                "credentials_domains": ["acme.example"],
            }
        }
        now = datetime.now(timezone.utc)
        results = _extract_crowdstrike(
            raw, detection_id=1, source="crowdstrike_intel", now=now,
            snippet="Credential domains: acme.example",
        )
        assert results == []


class TestTypeMapping:
    """Test OTX and CrowdStrike type mapping."""

    def test_otx_type_mapping(self):
        assert _map_otx_type("FileHash-MD5") == "hash_md5"
        assert _map_otx_type("FileHash-SHA256") == "hash_sha256"
        assert _map_otx_type("IPv4") == "ipv4"
        assert _map_otx_type("domain") == "domain"
        assert _map_otx_type("CVE") == "cve"
        assert _map_otx_type("NotAType") is None

    def test_cs_type_mapping(self):
        assert _map_cs_type("md5") == "hash_md5"
        assert _map_cs_type("SHA256") == "hash_sha256"  # case insensitive
        assert _map_cs_type("ip_address") == "ipv4"
        assert _map_cs_type("DOMAIN") == "domain"
        assert _map_cs_type("not_real") is None


class TestExtractThreatFox:
    """Test ThreatFox extraction logic."""

    def test_extracts_ip_port_ioc(self):
        raw = {
            "ioc": "192.168.1.1:4443",
            "ioc_type": "ip:port",
            "malware_printable": "Cobalt Strike",
            "malware": "win.cobalt_strike",
        }
        now = datetime.now(timezone.utc)
        results = _extract_threatfox(raw, detection_id=1, source="threatfox", now=now)
        assert len(results) == 2
        assert results[0]["type"] == "ipv4"
        assert results[0]["value"] == "192.168.1.1:4443"
        assert results[1]["type"] == "malware_family"
        assert results[1]["value"] == "Cobalt Strike"

    def test_extracts_domain_ioc(self):
        raw = {
            "ioc": "evil.example.com",
            "ioc_type": "domain",
            "malware_printable": "Emotet",
        }
        now = datetime.now(timezone.utc)
        results = _extract_threatfox(raw, detection_id=1, source="threatfox", now=now)
        assert len(results) == 2
        assert results[0]["type"] == "domain"
        assert results[0]["value"] == "evil.example.com"

    def test_extracts_sha256_ioc(self):
        sha = "a" * 64
        raw = {
            "ioc": sha,
            "ioc_type": "sha256_hash",
            "malware_printable": "QakBot",
        }
        now = datetime.now(timezone.utc)
        results = _extract_threatfox(raw, detection_id=1, source="threatfox", now=now)
        assert len(results) == 2
        assert results[0]["type"] == "hash_sha256"
        assert results[0]["value"] == sha

    def test_skips_unknown_malware(self):
        raw = {
            "ioc": "http://evil.com/payload.exe",
            "ioc_type": "url",
            "malware_printable": "unknown",
        }
        now = datetime.now(timezone.utc)
        results = _extract_threatfox(raw, detection_id=1, source="threatfox", now=now)
        # Only the URL indicator, no malware_family since it's "unknown"
        assert len(results) == 1
        assert results[0]["type"] == "url"

    def test_skips_unknown_ioc_type(self):
        raw = {
            "ioc": "something",
            "ioc_type": "new_unsupported_type",
            "malware_printable": "SomeBot",
        }
        now = datetime.now(timezone.utc)
        results = _extract_threatfox(raw, detection_id=1, source="threatfox", now=now)
        # Only malware_family, no IOC since type is unmapped
        assert len(results) == 1
        assert results[0]["type"] == "malware_family"

    def test_empty_raw_data(self):
        now = datetime.now(timezone.utc)
        results = _extract_threatfox({}, detection_id=1, source="threatfox", now=now)
        assert results == []

    def test_threatfox_type_mapping(self):
        assert _map_threatfox_type("ip:port") == "ipv4"
        assert _map_threatfox_type("domain") == "domain"
        assert _map_threatfox_type("url") == "url"
        assert _map_threatfox_type("md5_hash") == "hash_md5"
        assert _map_threatfox_type("sha256_hash") == "hash_sha256"
        assert _map_threatfox_type("not_a_type") is None


# ---------------------------------------------------------------------------
# Integration tests (require DB)
# ---------------------------------------------------------------------------

class TestExtractIndicatorsIntegration:
    """Integration tests for extract_indicators with real DB."""

    @pytest.fixture
    async def otx_detection(self, db):
        """Create a detection with OTX-style raw_data."""
        detection = Detection(
            source="alienvault_otx",
            title="OTX Pulse: Threat Group X",
            snippet="Indicators for Threat Group X targeting acme.example",
            source_url="https://otx.alienvault.com/pulse/123",
            content_hash="a" * 64,
            matched_keywords=["acme"],
            severity="high",
            status="new",
            raw_data={
                "indicators": [
                    {"type": "FileHash-MD5", "indicator": "d41d8cd98f00b204e9800998ecf8427e"},
                    {"type": "IPv4", "indicator": "192.168.1.100"},
                ],
                "attack_ids": [{"id": "T1059", "name": "Command and Scripting Interpreter"}],
                "malware_families": [{"display_name": "Emotet"}],
            },
        )
        db.add(detection)
        await db.commit()
        await db.refresh(detection)
        return detection

    @pytest.fixture
    async def text_detection(self, db):
        """Create a detection with CVEs in the snippet."""
        detection = Detection(
            source="ransomwatch",
            title="Ransomwatch: Group Y",
            snippet="Exploited CVE-2024-1234 and CVE-2023-5678 to deploy ransomware",
            source_url="https://ransomwatch.example.com/post/123",
            content_hash="b" * 64,
            matched_keywords=["acme-corp"],
            severity="critical",
            status="new",
            raw_data={},
        )
        db.add(detection)
        await db.commit()
        await db.refresh(detection)
        return detection

    async def test_extract_otx_indicators(self, db, otx_detection):
        count = await extract_indicators(otx_detection, db)
        assert count == 4  # MD5 + IPv4 + MITRE + malware_family

        from sqlalchemy import select
        result = await db.execute(
            select(Indicator).where(Indicator.detection_id == otx_detection.id)
        )
        indicators = result.scalars().all()
        assert len(indicators) == 4
        types = {i.type for i in indicators}
        assert types == {"hash_md5", "ipv4", "mitre_technique", "malware_family"}

    async def test_extract_text_indicators(self, db, text_detection):
        count = await extract_indicators(text_detection, db)
        assert count == 2  # Two CVEs

        from sqlalchemy import select
        result = await db.execute(
            select(Indicator).where(Indicator.detection_id == text_detection.id)
        )
        indicators = result.scalars().all()
        assert len(indicators) == 2
        assert all(i.type == "cve" for i in indicators)
        values = {i.value for i in indicators}
        assert "CVE-2024-1234" in values
        assert "CVE-2023-5678" in values

    async def test_upsert_updates_last_seen(self, db, otx_detection):
        """Running extraction twice should update last_seen, not create duplicates."""
        count1 = await extract_indicators(otx_detection, db)
        assert count1 == 4

        count2 = await extract_indicators(otx_detection, db)
        assert count2 == 4  # Same count (upsert)

        from sqlalchemy import select
        result = await db.execute(
            select(Indicator).where(Indicator.detection_id == otx_detection.id)
        )
        indicators = result.scalars().all()
        assert len(indicators) == 4  # No duplicates

    async def test_no_raw_data_returns_zero(self, db):
        detection = Detection(
            source="alienvault_otx",
            title="Empty detection",
            snippet="No IOCs here",
            source_url="https://example.com",
            content_hash="c" * 64,
            matched_keywords=["test"],
            severity="low",
            status="new",
            raw_data=None,
        )
        db.add(detection)
        await db.commit()
        await db.refresh(detection)

        count = await extract_indicators(detection, db)
        assert count == 0

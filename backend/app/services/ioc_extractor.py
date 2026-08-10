"""Extract structured IOCs from detection raw_data."""
import ipaddress
import re
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.metrics import indicators_extracted
from app.models.indicator import Indicator
from app.models.detection import Detection


# Regex patterns for extracting IOCs from text content
_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


# Common false-positive substrings to reject as "domains"
_DOMAIN_BLOCKLIST = {
    # Documentation / placeholders
    "python.org", "example.com", "example.net", "example.org",
    # Common non-threat infrastructure
    "schema.org", "w3.org", "localhost",
}

# TLDs to accept (reduces version-string false positives like "3.11.4")
_VALID_TLDS = {
    "com", "net", "org", "io", "co", "uk", "de", "fr", "ru", "cn", "jp",
    "info", "biz", "me", "tv", "gov", "edu", "mil", "int",
    "onion",  # Tor
    # IANA-reserved TLDs (RFC 2606 / 6761) — used in test fixtures and
    # documentation. Allowing them through means we extract them when present;
    # real threat feeds never use these so there is no production false-positive
    # cost, and the test suite stays honest by sentinelling its data with them.
    "example", "test", "invalid", "localhost",
    # Country TLDs - add as needed
}


async def extract_indicators(detection: Detection, db: AsyncSession) -> int:
    """Extract IOCs from a detection's raw_data and persist as indicators.

    Returns the number of indicators created/updated.
    """
    raw = detection.raw_data or {}
    source = detection.source
    now = datetime.now(timezone.utc)
    indicators: list[dict] = []

    if source == "alienvault_otx":
        indicators.extend(_extract_otx(raw, detection.id, source, now))
    elif source in ("crowdstrike_recon", "crowdstrike_intel"):
        indicators.extend(_extract_crowdstrike(raw, detection.id, source, now, snippet=detection.snippet or ""))
    elif source == "threatfox":
        indicators.extend(_extract_threatfox(raw, detection.id, source, now))
    elif source == "cisa_kev":
        indicators.extend(_extract_cisa_kev(raw, detection.id, source, now))
    else:
        # Best-effort regex extraction from snippet for ransomlook/ransomwatch
        indicators.extend(_extract_from_text(detection.snippet or "", detection.id, source, now))

    if not indicators:
        return 0

    # Record metric for each extracted indicator
    for ind in indicators:
        indicators_extracted.labels(type=ind["type"]).inc()

    # Upsert — update last_seen if the indicator already exists for this detection
    for ind in indicators:
        stmt = pg_insert(Indicator).values(**ind)
        stmt = stmt.on_conflict_do_update(
            constraint="uq_indicator_detection_type_value",
            set_={"last_seen": now},
        )
        await db.execute(stmt)
    await db.flush()  # caller (scheduler batch loop) commits the whole batch
    return len(indicators)


def _extract_otx(raw: dict, detection_id: int, source: str, now: datetime) -> list[dict]:
    """Extract from AlienVault OTX pulse data."""
    results = []

    # OTX indicators array
    for ind in raw.get("indicators", []):
        ioc_type = _map_otx_type(ind.get("type", ""))
        if ioc_type:
            results.append({
                "detection_id": detection_id,
                "type": ioc_type,
                "value": ind.get("indicator", ""),
                "source": source,
                "first_seen": now,
                "last_seen": now,
            })

    # Attack IDs (MITRE)
    for attack_id in raw.get("attack_ids", []):
        if isinstance(attack_id, dict):
            tid = attack_id.get("id", "")
        else:
            tid = str(attack_id)
        if tid.startswith("T"):
            results.append({
                "detection_id": detection_id,
                "type": "mitre_technique",
                "value": tid,
                "source": source,
                "first_seen": now,
                "last_seen": now,
            })

    # Malware families
    for family in raw.get("malware_families", []):
        name = family.get("display_name", "") if isinstance(family, dict) else str(family)
        if name:
            results.append({
                "detection_id": detection_id,
                "type": "malware_family",
                "value": name,
                "source": source,
                "first_seen": now,
                "last_seen": now,
            })

    return results


def _map_otx_type(otx_type: str) -> str | None:
    """Map OTX indicator types to our normalized types."""
    mapping = {
        "FileHash-MD5": "hash_md5",
        "FileHash-SHA256": "hash_sha256",
        "FileHash-SHA1": "hash_sha1",
        "IPv4": "ipv4",
        "domain": "domain",
        "hostname": "domain",
        "URL": "url",
        "email": "email",
        "CVE": "cve",
    }
    return mapping.get(otx_type)


def _extract_crowdstrike(
    raw: dict,
    detection_id: int,
    source: str,
    now: datetime,
    snippet: str = "",
) -> list[dict]:
    """Extract from CrowdStrike report/notification data.

    For CS Recon detections (credential leaks, exposed data), structured
    indicator fields are typically empty — the actionable IOCs (credential
    domains, leak sites) live in the snippet text. We always run a regex
    fallback over the snippet for that source as a result.
    """
    results = []

    # CrowdStrike reports may have indicators in various fields
    for field in ("indicators", "iocs", "ioc_values"):
        for ioc in raw.get(field, []):
            if isinstance(ioc, dict):
                ioc_type = ioc.get("type", "")
                value = ioc.get("value", ioc.get("indicator", ""))
            else:
                continue
            mapped = _map_cs_type(ioc_type)
            if mapped and value:
                results.append({
                    "detection_id": detection_id,
                    "type": mapped,
                    "value": value,
                    "source": source,
                    "first_seen": now,
                    "last_seen": now,
                })

    # CS Recon: also pull credential domains directly from breach_summary
    # so that we don't rely solely on snippet wording.
    if source == "crowdstrike_recon":
        breach = raw.get("breach_summary") or {}
        if isinstance(breach, dict):
            for domain in breach.get("credentials_domains", []) or []:
                if isinstance(domain, str) and domain:
                    results.append({
                        "detection_id": detection_id,
                        "type": "domain",
                        "value": domain.lower(),
                        "source": source,
                        "first_seen": now,
                        "last_seen": now,
                    })

        # Fallback: regex extraction over the snippet text. Catches any
        # IOCs that aren't surfaced through structured fields.
        if snippet:
            results.extend(_extract_from_text(snippet, detection_id, source, now))

    # Final dedup pass — multiple sources (structured + snippet regex) may
    # produce the same indicator for one detection.
    seen: set[str] = set()
    deduped: list[dict] = []
    for ind in results:
        key = f"{ind['type']}:{ind['value'].lower()}"
        if key in seen:
            continue
        seen.add(key)
        deduped.append(ind)
    return deduped


def _map_cs_type(cs_type: str) -> str | None:
    """Map CrowdStrike indicator types to our normalized types."""
    mapping = {
        "md5": "hash_md5",
        "sha256": "hash_sha256",
        "sha1": "hash_sha1",
        "ip_address": "ipv4",
        "domain": "domain",
        "url": "url",
        "email_address": "email",
    }
    return mapping.get(cs_type.lower())


def _extract_threatfox(raw: dict, detection_id: int, source: str, now: datetime) -> list[dict]:
    """Extract from ThreatFox IOC data — already structured."""
    results = []
    ioc_value = raw.get("ioc", "")
    ioc_type = raw.get("ioc_type", "")

    mapped = _map_threatfox_type(ioc_type)
    if mapped and ioc_value:
        results.append({
            "detection_id": detection_id,
            "type": mapped,
            "value": ioc_value,
            "source": source,
            "first_seen": now,
            "last_seen": now,
        })

    # Extract malware family
    malware = raw.get("malware_printable", raw.get("malware", ""))
    if malware and malware != "unknown":
        results.append({
            "detection_id": detection_id,
            "type": "malware_family",
            "value": malware,
            "source": source,
            "first_seen": now,
            "last_seen": now,
        })

    return results


def _map_threatfox_type(tf_type: str) -> str | None:
    """Map ThreatFox indicator types to our normalized types."""
    mapping = {
        "ip:port": "ipv4",
        "domain": "domain",
        "url": "url",
        "md5_hash": "hash_md5",
        "sha256_hash": "hash_sha256",
    }
    return mapping.get(tf_type)


def _extract_cisa_kev(raw: dict, detection_id: int, source: str, now: datetime) -> list[dict]:
    """Extract CVE from CISA KEV entry."""
    results = []
    cve_id = raw.get("cveID", "")
    if cve_id:
        results.append({
            "detection_id": detection_id,
            "type": "cve",
            "value": cve_id,
            "source": source,
            "first_seen": now,
            "last_seen": now,
        })
    return results


def _extract_from_text(text: str, detection_id: int, source: str, now: datetime) -> list[dict]:
    """Best-effort regex extraction for sources without structured IOC data."""
    if not text:
        return []

    results: list[dict] = []
    seen_values: set[str] = set()  # dedup within this detection

    def add(type_: str, value: str) -> None:
        key = f"{type_}:{value.lower()}"
        if key in seen_values:
            return
        seen_values.add(key)
        results.append({
            "detection_id": detection_id,
            "type": type_,
            "value": value,
            "source": source,
            "first_seen": now,
            "last_seen": now,
        })

    # CVEs — always high signal
    for match in _CVE_RE.findall(text):
        add("cve", match.upper())

    # SHA256 (32-byte hex) — check first; longer pattern wins so we can
    # suppress MD5-length substrings of any SHA256 we already saw.
    sha256_matches = set(_SHA256_RE.findall(text))
    for match in sha256_matches:
        add("hash_sha256", match.lower())

    # MD5 (16-byte hex) — skip if substring of a SHA256 already found
    for match in _MD5_RE.findall(text):
        lower = match.lower()
        if any(lower in sha.lower() for sha in sha256_matches):
            continue
        add("hash_md5", lower)

    # IPv4 — validate octets via the ipaddress module and skip non-routable
    # ranges so we don't flag local fixtures or doc examples.
    for match in _IPV4_RE.findall(text):
        try:
            ip = ipaddress.ip_address(match)
        except ValueError:
            continue
        if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_multicast:
            continue
        add("ipv4", match)

    # Domains — validate TLD against a known list and skip pure version
    # strings (e.g. "3.11.4") to keep noise down.
    for match in _DOMAIN_RE.findall(text):
        lower = match.lower()
        if lower in _DOMAIN_BLOCKLIST:
            continue
        # Pure-numeric "domains" are version strings, not IOCs.
        if lower.replace(".", "").isdigit():
            continue
        parts = lower.rsplit(".", 1)
        if len(parts) != 2:
            continue
        tld = parts[1]
        if tld not in _VALID_TLDS:
            continue
        add("domain", lower)

    return results

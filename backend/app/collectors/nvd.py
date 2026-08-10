"""
NVD CVE collector — National Vulnerability Database (NIST).

Polls the NVD CVE API 2.0 for recently *modified* CVE records (added or
updated). NVD recommends a delta-window approach via the
``lastModStartDate`` / ``lastModEndDate`` parameters rather than re-fetching
the full feed; we ask for a one-hour window ending now on each poll, with
a small overlap so a transient network blip can't drop a record.

Auth: a ``apiKey`` HTTP header lifts the rate limit from 5 requests per
30 seconds (anonymous) to 50 per 30 seconds. The key is optional — the
collector still works without it, just slower. With no key set it falls
through gracefully; we don't no-op the way the auth-key-required collectors
do, because NVD is genuinely usable anonymously.

Reference: https://nvd.nist.gov/developers/vulnerabilities

Response shape (top level):
  {
    "resultsPerPage": int, "startIndex": int, "totalResults": int,
    "format": str, "version": str, "timestamp": str,
    "vulnerabilities": [
      {"cve": {
        "id": "CVE-YYYY-NNNNN",
        "published": ISO8601, "lastModified": ISO8601,
        "descriptions": [{"lang": "en", "value": "..."}, ...],
        "metrics": {
          "cvssMetricV31": [{"cvssData": {"baseScore": float, "baseSeverity": str,
                                          "vectorString": str}, ...}],
          "cvssMetricV2":  [...]
        }
      }}, ...
    ]
  }
"""
import logging
from datetime import datetime, timedelta, timezone

import httpx

from app.collectors.base import BaseCollector, RawDetection

logger = logging.getLogger(__name__)

_NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# NVD wants ISO-8601 with milliseconds; UTC offsets must use %2B if encoded
# manually. httpx's params= handles URL encoding for us, so plain "+00:00"
# (or, equivalently, no offset suffix when we pass naive UTC) is fine.
_NVD_DATE_FMT = "%Y-%m-%dT%H:%M:%S.000"


class NVDCollector(BaseCollector):
    name = "nvd"
    poll_interval_seconds = 3600  # hourly — matches the delta window we request

    # 1-hour fetch window with a small overlap to absorb transient failures.
    _WINDOW_HOURS = 1
    _OVERLAP_MINUTES = 5

    def __init__(self, api_key: str | None = None) -> None:
        self._api_key = api_key or ""
        # Per NVD docs the apiKey goes in the request header, not as a query
        # parameter. We add it only when present so anonymous mode works.
        headers = {"apiKey": self._api_key} if self._api_key else {}
        self._client = httpx.AsyncClient(timeout=60, headers=headers)

    async def collect(self, since: datetime | None = None) -> list[RawDetection]:
        end = datetime.now(timezone.utc)
        # Use the scheduler-provided ``since`` when available so a missed poll
        # cycle is recovered cleanly. Fall back to a fixed 1-hour window
        # (with overlap) when we have no prior success timestamp.
        if since is not None:
            start = since - timedelta(minutes=self._OVERLAP_MINUTES)
        else:
            start = end - timedelta(
                hours=self._WINDOW_HOURS, minutes=self._OVERLAP_MINUTES
            )

        params = {
            "lastModStartDate": start.strftime(_NVD_DATE_FMT),
            "lastModEndDate": end.strftime(_NVD_DATE_FMT),
        }

        resp = await self._client.get(_NVD_API, params=params)
        resp.raise_for_status()
        data = resp.json()

        vulnerabilities = data.get("vulnerabilities", [])
        detections = self._parse_vulnerabilities(vulnerabilities)
        logger.info(
            "NVD: fetched %d modified CVEs between %s and %s",
            len(vulnerabilities), params["lastModStartDate"], params["lastModEndDate"],
        )
        return detections

    # ------------------------------------------------------------------
    # parse_vulnerabilities — pure mapping, useful for unit tests
    # ------------------------------------------------------------------

    def _parse_vulnerabilities(self, items: list[dict]) -> list[RawDetection]:
        results: list[RawDetection] = []
        for item in items:
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            if not cve_id:
                # Without a CVE id we can't build a meaningful title or URL.
                continue

            description = _english_description(cve.get("descriptions") or [])
            cvss_summary = _format_cvss(cve.get("metrics") or {})

            # Title format per the brief: "CVE-YYYY-NNNNN — <description first 100>"
            short_desc = description[:100].rstrip()
            title = f"{cve_id} — {short_desc}" if short_desc else cve_id
            # Cap title at 500 chars to match the schema convention.
            title = title[:500]

            content_parts = [description]
            if cvss_summary:
                content_parts.append(cvss_summary)
            content = "\n\n".join(p for p in content_parts if p)

            results.append(
                RawDetection(
                    source=self.name,
                    source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    title=title,
                    content=content,
                    raw_payload=item,
                )
            )
        return results

    # ------------------------------------------------------------------
    # health_check — anonymous-friendly
    # ------------------------------------------------------------------

    async def health_check(self) -> bool:
        # Hit the API with a tiny request that works with or without a key.
        # resultsPerPage=1 keeps the response small even when the rolling
        # window is wide.
        try:
            resp = await self._client.get(_NVD_API, params={"resultsPerPage": 1})
            return resp.status_code == 200
        except Exception:
            return False

    async def close(self) -> None:
        await self._client.aclose()


# ---------------------------------------------------------------------------
# helpers — kept module-level so tests can import them directly
# ---------------------------------------------------------------------------


def _english_description(descriptions: list[dict]) -> str:
    """Pull the English description out of NVD's multi-lang list."""
    for entry in descriptions:
        if entry.get("lang") == "en":
            return entry.get("value", "")
    # Fall back to whatever the first entry has — better than empty.
    if descriptions:
        return descriptions[0].get("value", "")
    return ""


def _format_cvss(metrics: dict) -> str:
    """Return a one-line CVSS summary from the metrics block.

    Prefers v3.1, then v3.0, then v2 — matches NVD's own ordering. Returns
    empty string when no CVSS data is present.
    """
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        items = metrics.get(key) or []
        if not items:
            continue
        primary = items[0].get("cvssData") or {}
        score = primary.get("baseScore")
        severity = primary.get("baseSeverity") or items[0].get("baseSeverity") or ""
        vector = primary.get("vectorString") or ""
        if score is None and not severity and not vector:
            continue
        version_label = (
            "CVSS v3.1" if key == "cvssMetricV31"
            else "CVSS v3.0" if key == "cvssMetricV30"
            else "CVSS v2"
        )
        bits = [version_label]
        if score is not None:
            bits.append(f"score={score}")
        if severity:
            bits.append(f"severity={severity}")
        if vector:
            bits.append(f"vector={vector}")
        return " ".join(bits)
    return ""

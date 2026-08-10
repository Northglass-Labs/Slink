"""
CISA KEV collector — Known Exploited Vulnerabilities catalog.

Polls the CISA KEV JSON feed daily for newly added CVEs. Free, no auth.
Only returns vulnerabilities added in the last 7 days to avoid flooding
the detection engine with historical data.
"""
import logging
from datetime import datetime, timedelta, timezone

import httpx

from app.collectors.base import BaseCollector, RawDetection

logger = logging.getLogger(__name__)

_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class CISAKEVCollector(BaseCollector):
    name = "cisa_kev"
    poll_interval_seconds = 86400  # daily

    def __init__(self) -> None:
        self._client = httpx.AsyncClient(timeout=60)

    async def collect(self, since: datetime | None = None) -> list[RawDetection]:
        resp = await self._client.get(_KEV_URL)
        resp.raise_for_status()
        data = resp.json()

        cutoff = datetime.now(timezone.utc) - timedelta(days=7)
        vulnerabilities = data.get("vulnerabilities", [])
        detections = []

        for vuln in vulnerabilities:
            date_added = vuln.get("dateAdded", "")
            try:
                added_dt = datetime.strptime(date_added, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            except ValueError:
                continue

            if added_dt < cutoff:
                continue

            cve_id = vuln.get("cveID", "")
            vendor = vuln.get("vendorProject", "")
            product = vuln.get("product", "")
            name = vuln.get("vulnerabilityName", "")
            description = vuln.get("shortDescription", "")
            ransomware = vuln.get("knownRansomwareCampaignUse", "Unknown")

            title = f"CISA KEV: {cve_id} — {vendor} {product}"
            content = (
                f"{name}\n"
                f"{description}\n"
                f"Vendor: {vendor}\n"
                f"Product: {product}\n"
                f"Ransomware Use: {ransomware}\n"
                f"Added: {date_added}"
            )

            detections.append(RawDetection(
                source="cisa_kev",
                source_url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                title=title,
                content=content,
                raw_payload=vuln,
            ))

        logger.info("CISA KEV: %d total vulnerabilities, %d added in last 7 days", len(vulnerabilities), len(detections))
        return detections

    async def health_check(self) -> bool:
        try:
            resp = await self._client.get(_KEV_URL)
            return resp.status_code == 200
        except Exception:
            return False

    async def close(self) -> None:
        await self._client.aclose()

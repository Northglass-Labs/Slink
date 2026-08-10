"""
ThreatFox collector — IOC feed from abuse.ch.

Polls the ThreatFox API for recent IOCs (last 24 hours). Returns RawDetections
for IOCs that are high-confidence (>= 50). Keyword matching happens later in
the detection engine, not here.

Auth: abuse.ch made the ``Auth-Key`` header mandatory across every feed
(including ThreatFox) in 2025. We pull the key from settings via the shared
:class:`AbuseChAuth` helper so every abuse.ch collector uses one source of
truth. With no key set the collector returns an empty list instead of failing.

The raw_payload preserves the full ThreatFox IOC object so the IOC extractor
can parse structured indicator data from it.
"""
import logging
from datetime import datetime

import httpx

from app.collectors.abusech_auth import AbuseChAuth
from app.collectors.base import BaseCollector, RawDetection
from app.config import settings

logger = logging.getLogger(__name__)

_THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"


class ThreatFoxCollector(BaseCollector):
    name = "threatfox"
    poll_interval_seconds = 3600  # hourly — ThreatFox data doesn't change fast

    def __init__(self, auth_key: str | None = None) -> None:
        # Constructor accepts an explicit key for tests; production reads
        # from settings via the shared abuse.ch helper.
        self._auth = AbuseChAuth(auth_key if auth_key is not None else settings.abusech_auth_key)
        self._client = httpx.AsyncClient(
            timeout=60,
            headers=self._auth.headers(),
        )

    async def collect(self, since: datetime | None = None) -> list[RawDetection]:
        if not self._auth.configured:
            logger.info("ThreatFox: ABUSECH_AUTH_KEY not set — skipping collection")
            return []

        resp = await self._client.post(
            _THREATFOX_API,
            json={"query": "get_iocs", "days": 1},
        )
        resp.raise_for_status()
        data = resp.json()

        if data.get("query_status") != "ok":
            logger.warning("ThreatFox query_status: %s", data.get("query_status"))
            return []

        iocs = data.get("data", [])
        detections = []

        for ioc in iocs:
            # Only include reasonably confident IOCs
            confidence = ioc.get("confidence_level", 0)
            if confidence < 50:
                continue

            malware = ioc.get("malware_printable", ioc.get("malware", "unknown"))
            ioc_value = ioc.get("ioc", "")
            ioc_type = ioc.get("ioc_type", "")
            threat_type = ioc.get("threat_type", "")
            tags = ", ".join(ioc.get("tags") or [])

            title = f"ThreatFox: {malware} — {ioc_type} indicator"
            content = (
                f"Malware: {malware}\n"
                f"IOC: {ioc_value}\n"
                f"Type: {ioc_type}\n"
                f"Threat: {threat_type}\n"
                f"Confidence: {confidence}%\n"
                f"Tags: {tags}"
            )

            detections.append(RawDetection(
                source="threatfox",
                source_url=f"https://threatfox.abuse.ch/ioc/{ioc.get('id', '')}",
                title=title,
                content=content,
                raw_payload=ioc,
            ))

        logger.info("ThreatFox: %d IOCs fetched, %d above confidence threshold", len(iocs), len(detections))
        return detections

    async def health_check(self) -> bool:
        # No key configured = collector is intentionally disabled, not failing.
        if not self._auth.configured:
            return True
        try:
            resp = await self._client.post(
                _THREATFOX_API,
                json={"query": "get_iocs", "days": 1},
            )
            return resp.status_code == 200
        except Exception:
            return False

    async def close(self) -> None:
        await self._client.aclose()

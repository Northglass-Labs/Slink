"""
AlienVault OTX (Open Threat Exchange) collector.

OTX aggregates community threat intelligence as "pulses" — each pulse describes
an indicator set with context. We subscribe to pulses via the API and surface
them as RawDetection objects for the detection engine.

Auth: a static API key sent in the X-OTX-API-KEY request header.
Poll interval: 300 s (5 min) — the public feed is updated sporadically.

OTX pulse field reference:
  id          — unique pulse ID
  name        — pulse title
  description — human-readable description
  author_name — OTX username of the pulse author
  adversary   — threat actor name (may be empty)
  malware_families — list of malware family names
  tags        — list of tag strings
  pulse_source — where the intelligence originated (e.g. "web")
  created     — ISO 8601 timestamp
  TLP         — traffic light protocol level
"""
import logging

import httpx

from app.collectors.base import BaseCollector, RawDetection

logger = logging.getLogger(__name__)

_OTX_BASE_URL = "https://otx.alienvault.com"


class AlienVaultOTXCollector(BaseCollector):
    name = "alienvault_otx"
    poll_interval_seconds = 300

    def __init__(self, api_key: str) -> None:
        self._api_key = api_key
        self._client = httpx.AsyncClient(
            timeout=60,
            # X-OTX-API-KEY is the auth mechanism — keep it out of logs
            headers={"X-OTX-API-KEY": api_key},
        )

    # ------------------------------------------------------------------
    # collect()
    # ------------------------------------------------------------------

    async def collect(self, since=None) -> list[RawDetection]:
        """Fetch subscribed pulses and return as RawDetection list.

        Limits to the 50 most recent pulses to avoid timeouts on accounts
        with large subscription lists. The OTX API returns newest first.
        """
        resp = await self._client.get(
            f"{_OTX_BASE_URL}/api/v1/pulses/subscribed",
            params={"limit": 50},
        )
        resp.raise_for_status()
        pulses = resp.json().get("results", [])
        return self.parse_pulses(pulses)

    # ------------------------------------------------------------------
    # parse_pulses()
    # ------------------------------------------------------------------

    def parse_pulses(self, data: list[dict]) -> list[RawDetection]:
        """Map OTX pulse dicts to RawDetection objects."""
        detections = []
        for pulse in data:
            pulse_id = pulse.get("id", "")
            name = pulse.get("name", f"OTX pulse {pulse_id}")
            description = pulse.get("description", "")
            author = pulse.get("author_name", "")
            adversary = pulse.get("adversary", "")
            tags = pulse.get("tags") or []
            malware_families = pulse.get("malware_families") or []

            # Build source URL from the pulse ID — OTX permalink format
            source_url = f"{_OTX_BASE_URL}/pulse/{pulse_id}" if pulse_id else ""

            tags_str = ", ".join(tags) if tags else ""
            malware_str = ", ".join(
                m.get("display_name", m.get("name", "")) if isinstance(m, dict) else str(m)
                for m in malware_families
            )

            content_parts = filter(None, [
                description,
                f"Adversary: {adversary}" if adversary else "",
                f"Author: {author}" if author else "",
                f"Tags: {tags_str}" if tags_str else "",
                f"Malware: {malware_str}" if malware_str else "",
            ])
            content = "\n".join(content_parts)

            detections.append(
                RawDetection(
                    source=self.name,
                    source_url=source_url,
                    title=name,
                    content=content,
                    raw_payload=pulse,
                    actor=adversary or None,
                )
            )
        return detections

    # ------------------------------------------------------------------
    # health_check()
    # ------------------------------------------------------------------

    async def close(self) -> None:
        """Close the underlying HTTP client to release connections."""
        await self._client.aclose()

    async def health_check(self) -> bool:
        """Return True if the OTX user endpoint responds with 200."""
        try:
            resp = await self._client.get(f"{_OTX_BASE_URL}/api/v1/user/me")
            return resp.status_code == 200
        except Exception:
            return False

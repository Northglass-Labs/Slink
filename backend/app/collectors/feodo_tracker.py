"""
Feodo Tracker collector — abuse.ch banking-trojan / botnet C2 IP feed.

Polls https://feodotracker.abuse.ch/downloads/ipblocklist.json (a flat JSON
array of recent IP entries from the past 30 days). Each entry becomes one
RawDetection capturing the IP/port, malware family, and first/last-seen
timestamps. Full record is kept in ``raw_payload``.

Auth: Feodo Tracker's blocklist downloads are currently public, but abuse.ch
moved their auth scheme to require an Auth-Key on most feeds in 2025. We
route through :class:`AbuseChAuth` like the other abuse.ch collectors so the
header is sent whenever a key is configured — that means we don't have to
revisit this collector if abuse.ch tightens auth on Feodo too. With no key
configured we still attempt the fetch (Feodo currently doesn't reject anonymous
clients), keeping the collector useful out-of-the-box.

Feodo IP record fields (verified against ipblocklist.json):
  ip_address, port, status, hostname, as_number, as_name,
  country, first_seen, last_online, malware
"""
from __future__ import annotations

import logging

import httpx

from app.collectors.abusech_auth import AbuseChAuth
from app.collectors.base import BaseCollector, RawDetection
from app.config import settings

logger = logging.getLogger(__name__)

_FEODO_JSON = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"


class FeodoTrackerCollector(BaseCollector):
    name = "feodo_tracker"
    poll_interval_seconds = 300  # 5 minutes

    def __init__(self, auth_key: str | None = None) -> None:
        self._auth = AbuseChAuth(auth_key if auth_key is not None else settings.abusech_auth_key)
        self._client = httpx.AsyncClient(
            timeout=60,
            headers=self._auth.headers(),
        )

    # ------------------------------------------------------------------
    # collect()
    # ------------------------------------------------------------------

    async def collect(self, since=None) -> list[RawDetection]:
        # Feodo's blocklist is public, but we still log a hint when no key is
        # set so operators know the collector is running without auth.
        if not self._auth.configured:
            logger.debug(
                "Feodo Tracker: ABUSECH_AUTH_KEY not set — fetching anonymously"
            )

        resp = await self._client.get(_FEODO_JSON)
        resp.raise_for_status()
        data = resp.json()

        # The endpoint returns a JSON array directly (not wrapped in an
        # object). Defensive: tolerate the wrapped case too.
        if isinstance(data, dict):
            data = data.get("data") or []

        return self.parse_records(data or [])

    # ------------------------------------------------------------------
    # parse_records()
    # ------------------------------------------------------------------

    def parse_records(self, records: list[dict]) -> list[RawDetection]:
        """Map Feodo IP records to RawDetection objects."""
        detections: list[RawDetection] = []
        for record in records:
            ip = record.get("ip_address", "")
            port = record.get("port", "")
            malware = record.get("malware") or ""
            hostname = record.get("hostname") or ""
            country = record.get("country", "")
            as_number = record.get("as_number", "")
            as_name = record.get("as_name", "")
            status = record.get("status", "")
            first_seen = record.get("first_seen", "")
            last_online = record.get("last_online", "")

            ip_port = f"{ip}:{port}" if ip and port else (ip or "")
            title = (
                f"Feodo: {malware} C2 — {ip_port}" if malware and ip_port
                else (f"Feodo C2 — {ip_port}" if ip_port else "Feodo Tracker entry")
            )[:500]

            content_parts = filter(None, [
                f"IP: {ip}" if ip else "",
                f"Port: {port}" if port else "",
                f"Malware: {malware}" if malware else "",
                f"Hostname: {hostname}" if hostname else "",
                f"Country: {country}" if country else "",
                f"AS: {as_number} {as_name}".strip() if as_number or as_name else "",
                f"Status: {status}" if status else "",
                f"First seen: {first_seen}" if first_seen else "",
                f"Last online: {last_online}" if last_online else "",
            ])
            content = "\n".join(content_parts)

            # Feodo doesn't expose stable per-record permalinks; link to the
            # browse page filtered by IP, which is the closest equivalent.
            source_url = (
                f"https://feodotracker.abuse.ch/browse/host/{ip}/" if ip else
                "https://feodotracker.abuse.ch/blocklist/"
            )

            actor = malware or None

            detections.append(
                RawDetection(
                    source=self.name,
                    source_url=source_url,
                    title=title,
                    content=content,
                    raw_payload=record,
                    actor=actor,
                )
            )

        return detections

    # ------------------------------------------------------------------
    # health_check()
    # ------------------------------------------------------------------

    async def health_check(self) -> bool:
        try:
            resp = await self._client.get(_FEODO_JSON)
            return resp.status_code == 200
        except Exception:
            return False

    async def close(self) -> None:
        await self._client.aclose()

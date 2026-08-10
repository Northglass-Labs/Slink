"""
URLhaus collector — abuse.ch malicious-URL feed.

Polls https://urlhaus-api.abuse.ch/v1/urls/recent/ for URLs added in the last
~3 days (the endpoint returns up to 1000 entries). Each record becomes one
RawDetection with the URL in ``title``, threat tag + payload metadata in
``content``, and the full upstream record in ``raw_payload``.

Auth: abuse.ch made the ``Auth-Key`` header mandatory across every feed in
2025; the same key works for ThreatFox, URLhaus, MalwareBazaar, and Feodo
Tracker. We share that key via :class:`AbuseChAuth`. With no key configured
the collector returns an empty list — the same convention every credentialed
collector in the registry uses.

URLhaus record fields (from API docs):
  id, urlhaus_reference, url, url_status, host, date_added, threat,
  blacklists, reporter, larted, tags
"""
from __future__ import annotations

import logging

import httpx

from app.collectors.abusech_auth import AbuseChAuth
from app.collectors.base import BaseCollector, RawDetection
from app.config import settings

logger = logging.getLogger(__name__)

_URLHAUS_RECENT = "https://urlhaus-api.abuse.ch/v1/urls/recent/"


class URLhausCollector(BaseCollector):
    name = "urlhaus"
    poll_interval_seconds = 600  # 10 minutes

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
        if not self._auth.configured:
            logger.info("URLhaus: ABUSECH_AUTH_KEY not set — skipping collection")
            return []

        resp = await self._client.get(_URLHAUS_RECENT)
        resp.raise_for_status()
        data = resp.json()

        # URLhaus uses "ok" for both empty and non-empty result sets; "no_results"
        # is also benign. Anything else is worth a log line.
        status = data.get("query_status", "")
        if status not in ("ok", "no_results"):
            logger.warning("URLhaus query_status: %s", status)
            return []

        urls = data.get("urls") or []
        return self.parse_urls(urls)

    # ------------------------------------------------------------------
    # parse_urls()
    # ------------------------------------------------------------------

    def parse_urls(self, urls: list[dict]) -> list[RawDetection]:
        """Map URLhaus URL records to RawDetection objects."""
        detections: list[RawDetection] = []
        for record in urls:
            url = record.get("url", "")
            host = record.get("host", "")
            threat = record.get("threat", "")
            url_status = record.get("url_status", "")
            date_added = record.get("date_added", "")
            reporter = record.get("reporter", "")
            tags = record.get("tags") or []
            tags_str = ", ".join(tags) if tags else ""

            # Payload info — URLhaus sometimes embeds the malware family /
            # signature alongside the URL when a sample has been linked.
            payloads = record.get("payloads") or []
            payload_summaries: list[str] = []
            for p in payloads:
                signature = p.get("signature") if isinstance(p, dict) else None
                file_type = p.get("file_type") if isinstance(p, dict) else None
                if signature or file_type:
                    payload_summaries.append(
                        f"{signature or 'unknown signature'} ({file_type or 'unknown type'})"
                    )
            payloads_str = "; ".join(payload_summaries)

            content_parts = filter(None, [
                f"URL: {url}" if url else "",
                f"Host: {host}" if host else "",
                f"Threat: {threat}" if threat else "",
                f"Status: {url_status}" if url_status else "",
                f"Tags: {tags_str}" if tags_str else "",
                f"Payloads: {payloads_str}" if payloads_str else "",
                f"Reporter: {reporter}" if reporter else "",
                f"Date added: {date_added}" if date_added else "",
            ])
            content = "\n".join(content_parts)

            # Title is just the URL — the detection-engine title field is what
            # users see in the feed list, and the URL is the most informative
            # short identifier for this kind of record.
            title = (url or host or "URLhaus URL")[:500]

            detections.append(
                RawDetection(
                    source=self.name,
                    source_url=record.get("urlhaus_reference", "") or "",
                    title=title,
                    content=content,
                    raw_payload=record,
                )
            )

        return detections

    # ------------------------------------------------------------------
    # health_check()
    # ------------------------------------------------------------------

    async def health_check(self) -> bool:
        # No key = intentionally disabled.
        if not self._auth.configured:
            return True
        try:
            resp = await self._client.get(_URLHAUS_RECENT)
            return resp.status_code == 200
        except Exception:
            return False

    async def close(self) -> None:
        await self._client.aclose()

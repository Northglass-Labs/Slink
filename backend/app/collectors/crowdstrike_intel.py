"""
CrowdStrike Adversary Intel collector.

Falcon Intelligence publishes threat reports tied to adversary groups. This
collector fetches recent reports and exposes them as RawDetection objects so
the detection engine can match them against the configured entity watch list.

Keyword / threat-actor matching is handled entirely by the detection engine —
this collector's job is only to fetch and normalize the data.

Poll interval is 300 s (5 min) since new Intel reports are published infrequently.

CS Intel API envelope shape:
  {"meta": {...}, "resources": [...], "errors": []}
"""
import logging

import httpx

from app.collectors.base import BaseCollector, RawDetection
from app.collectors.crowdstrike_auth import CrowdStrikeAuth
from app.utils.source_url import sanitize_source_url

logger = logging.getLogger(__name__)

_MAX_IDS_PER_REQUEST = 100
_MAX_TOTAL_REPORTS = 500
_MAX_RESPONSE_BYTES = 5 * 1024 * 1024


class CrowdStrikePayloadError(ValueError):
    pass


def _resources_from_response(response: httpx.Response, *, label: str) -> list:
    if len(response.content) > _MAX_RESPONSE_BYTES:
        raise CrowdStrikePayloadError(f"{label} response exceeded size limit")
    try:
        payload = response.json()
    except ValueError as exc:
        raise CrowdStrikePayloadError(f"{label} response was not JSON") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("resources"), list):
        raise CrowdStrikePayloadError(f"{label} response had an invalid schema")
    return payload["resources"]


class CrowdStrikeIntelCollector(BaseCollector):
    name = "crowdstrike_intel"
    poll_interval_seconds = 300

    def __init__(self, client_id: str, client_secret: str, base_url: str) -> None:
        # Auth instance can be shared with the Recon collector if the same
        # credentials are used — each collector creates its own here for
        # simplicity; the token endpoint handles concurrent requests fine.
        self._auth = CrowdStrikeAuth(client_id, client_secret, base_url)
        self._base_url = base_url.rstrip("/")
        self._client = httpx.AsyncClient(timeout=30)
        # Optional paid collector: only active when credentials are supplied.
        self._configured = bool(client_id and client_secret)

    # ------------------------------------------------------------------
    # Auth header helper
    # ------------------------------------------------------------------

    async def _auth_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {await self._auth.get_token()}"}

    # ------------------------------------------------------------------
    # collect()
    # ------------------------------------------------------------------

    async def collect(self, since=None) -> list[RawDetection]:
        """Fetch recent Intel reports and return as RawDetection list."""
        # Auto-disable when no credentials are configured (matches the
        # github_advisory pattern) — avoids a 401 on every poll for the common
        # case where the operator hasn't wired up the optional paid CrowdStrike feed.
        if not self._configured:
            return []
        ids = await self._fetch_report_ids()
        if not ids:
            return []
        reports = await self._fetch_report_details(ids)
        return self.parse_reports(reports)

    async def _fetch_report_ids(self) -> list[str]:
        resp = await self._client.get(
            f"{self._base_url}/intel/queries/reports/v1",
            headers=await self._auth_headers(),
        )
        resp.raise_for_status()
        resources = _resources_from_response(resp, label="report query")
        if len(resources) > _MAX_TOTAL_REPORTS:
            raise CrowdStrikePayloadError("report query exceeded aggregate report limit")
        ids: list[str] = []
        for value in resources:
            if not isinstance(value, (str, int)):
                raise CrowdStrikePayloadError("report query returned a non-scalar ID")
            normalized = str(value)
            if not normalized or len(normalized) > 128:
                raise CrowdStrikePayloadError("report query returned an invalid ID")
            ids.append(normalized)
        return ids

    async def _fetch_report_details(self, ids: list[str]) -> list[dict]:
        """Batch-fetch full report objects. CS allows up to 100 IDs per call."""
        if len(ids) > _MAX_TOTAL_REPORTS:
            raise CrowdStrikePayloadError("report detail request exceeded aggregate limit")
        resources = []
        for chunk_start in range(0, len(ids), _MAX_IDS_PER_REQUEST):
            chunk = ids[chunk_start: chunk_start + _MAX_IDS_PER_REQUEST]
            params = [("ids", id_) for id_ in chunk]
            resp = await self._client.get(
                f"{self._base_url}/intel/entities/reports/v1",
                headers=await self._auth_headers(),
                params=params,
            )
            resp.raise_for_status()
            chunk_resources = _resources_from_response(resp, label="report detail")
            if len(resources) + len(chunk_resources) > _MAX_TOTAL_REPORTS:
                raise CrowdStrikePayloadError("report detail response exceeded aggregate limit")
            resources.extend(chunk_resources)
        return resources

    # ------------------------------------------------------------------
    # parse_reports()
    # ------------------------------------------------------------------

    def parse_reports(self, data: list[dict]) -> list[RawDetection]:
        """Map CrowdStrike Intel report dicts to RawDetection objects.

        Actual CS Intel report fields (verified 2026-03):
          id               — unique report ID (numeric)
          name             — report title
          short_description — executive summary
          summary          — longer report summary (no 'description' field)
          url              — link to the report in the Falcon console
          actors           — list of dicts with 'id', 'name', 'slug', 'animal_classifier'
          tags             — list of dicts with 'id', 'slug', 'value'
          target_industries — list of strings
          target_countries  — list of strings
          motivations       — list of strings
          created_date     — Unix timestamp
        """
        detections = []
        for report in data:
            try:
                if not isinstance(report, dict):
                    raise CrowdStrikePayloadError("report was not an object")
                report_id = report.get("id", "")
                if not isinstance(report_id, (str, int)):
                    raise CrowdStrikePayloadError("report ID was not scalar")
                report_id = str(report_id)[:128]
                default_name = f"Intel report {report_id}"

                def text_field(name: str, limit: int) -> str:
                    value = report.get(name, "")
                    if value is None:
                        return ""
                    if not isinstance(value, str):
                        raise CrowdStrikePayloadError(f"{name} was not text")
                    return value[:limit]

                name = text_field("name", 500) or default_name
                short_desc = text_field("short_description", 5000)
                summary = text_field("summary", 10000)
                url = text_field("url", 2000)

                actors_raw = report.get("actors") or []
                if not isinstance(actors_raw, list) or any(
                    not isinstance(actor, dict) for actor in actors_raw
                ):
                    raise CrowdStrikePayloadError("actors was not a list of objects")
                actor_names = [
                    actor_name[:200]
                    for actor_row in actors_raw[:50]
                    if isinstance((actor_name := actor_row.get("name")), str)
                    and actor_name
                ]
                actor = ", ".join(actor_names) if actor_names else None

                tags_raw = report.get("tags") or []
                if not isinstance(tags_raw, list):
                    raise CrowdStrikePayloadError("tags was not a list")
                tag_values = []
                for tag in tags_raw[:100]:
                    if isinstance(tag, dict) and isinstance(tag.get("value"), str):
                        tag_values.append(tag["value"][:200])
                    elif isinstance(tag, str):
                        tag_values.append(tag[:200])
                tags_str = ", ".join(filter(None, tag_values))

                content = "\n".join(
                    filter(
                        None,
                        [
                            short_desc,
                            summary,
                            f"Actors: {actor}" if actor else "",
                            f"Tags: {tags_str}" if tags_str else "",
                        ],
                    )
                )
                detections.append(
                    RawDetection(
                        source=self.name,
                        source_url=sanitize_source_url(self.name, url),
                        title=name,
                        content=content,
                        raw_payload=report,
                        actor=actor,
                    )
                )
            except CrowdStrikePayloadError as exc:
                logger.warning(
                    "Skipping malformed CrowdStrike report: %s",
                    type(exc).__name__,
                )
        return detections

    # ------------------------------------------------------------------
    # health_check()
    # ------------------------------------------------------------------

    async def close(self) -> None:
        """Close the underlying HTTP client to release connections."""
        await self._client.aclose()

    async def health_check(self) -> bool:
        """Return True if we can successfully obtain a bearer token."""
        try:
            await self._auth.get_token()
            return True
        except Exception:
            return False

"""
CrowdStrike Recon collector.

Falcon Recon monitors the dark web and paste sites for mentions matching
configured keyword rules. This collector:
  1. Fetches notification IDs from the query endpoint
  2. Fetches full notification details by ID
  3. Parses them into RawDetection objects for the detection engine

It also manages the server-side monitoring rules (configure_watches) so Slink
can keep Recon's keyword rules in sync with its own watch list.

CrowdStrike Recon Premium rule limit: 50 rules. We warn at 40.

API response envelope shape (used throughout):
  {"meta": {...}, "resources": [...], "errors": [...]}

Pagination:
  The notifications query endpoint supports ?filter=created_date:>'...'&limit=100&offset=N.
  When a `since` timestamp is provided, we filter server-side and page through
  all results. On first run (no since), we pull the most recent 100 as before.
"""
import logging
from datetime import datetime

import httpx

from app.collectors.base import BaseCollector, RawDetection
from app.collectors.crowdstrike_auth import CrowdStrikeAuth

logger = logging.getLogger(__name__)

_RULE_WARN_THRESHOLD = 40
_MAX_IDS_PER_REQUEST = 100  # CS API limit for entities batch fetch
_PAGE_SIZE = 100             # notifications query page size


class CrowdStrikeReconCollector(BaseCollector):
    name = "crowdstrike_recon"
    poll_interval_seconds = 60

    def __init__(self, client_id: str, client_secret: str, base_url: str) -> None:
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

    async def collect(self, since: datetime | None = None) -> list[RawDetection]:
        """Fetch Recon notifications and return as RawDetection list.

        Args:
            since: When provided, filters to notifications with
                   created_date after this timestamp and paginates through
                   all results. When None (first run), falls back to the
                   most recent 100 notifications.
        """
        # Auto-disable when no credentials are configured (matches the
        # github_advisory pattern) — avoids a 401 on every poll for the common
        # case where the operator hasn't wired up the optional paid CrowdStrike feed.
        if not self._configured:
            return []
        ids = await self._fetch_notification_ids(since=since)
        if not ids:
            return []
        notifications = await self._fetch_notification_details(ids)
        return self.parse_notifications(notifications)

    async def _fetch_notification_ids(self, since: datetime | None = None) -> list[str]:
        """Fetch all notification IDs matching the given time filter.

        When `since` is set, pages through results using offset until all
        IDs are retrieved. Without `since`, returns whatever the API returns
        in a single unfiltered call (the most recent 100).
        """
        if since is None:
            # First run — no filter, grab the default most-recent page
            resp = await self._client.get(
                f"{self._base_url}/recon/queries/notifications/v1",
                headers=await self._auth_headers(),
            )
            resp.raise_for_status()
            return resp.json().get("resources", [])

        # Incremental run — filter by created_date and page through all results
        # The CS FQL timestamp format is ISO-8601 UTC without fractional seconds.
        since_str = since.strftime("%Y-%m-%dT%H:%M:%SZ")
        fql_filter = f"created_date:>'{since_str}'"

        all_ids: list[str] = []
        offset = 0

        while True:
            resp = await self._client.get(
                f"{self._base_url}/recon/queries/notifications/v1",
                headers=await self._auth_headers(),
                params={
                    "filter": fql_filter,
                    "limit": _PAGE_SIZE,
                    "offset": offset,
                },
            )
            resp.raise_for_status()
            body = resp.json()

            page_ids = body.get("resources", [])
            all_ids.extend(page_ids)

            # meta.pagination.total tells us how many notifications match the filter
            total = body.get("meta", {}).get("pagination", {}).get("total", 0)
            offset += len(page_ids)

            if offset >= total or not page_ids:
                # All pages consumed
                break

        logger.debug(
            "CS Recon: fetched %d notification IDs since %s",
            len(all_ids), since_str,
        )
        return all_ids

    async def _fetch_notification_details(self, ids: list[str]) -> list[dict]:
        """Batch-fetch notification details. CS allows up to 100 IDs per call."""
        resources = []
        for chunk_start in range(0, len(ids), _MAX_IDS_PER_REQUEST):
            chunk = ids[chunk_start: chunk_start + _MAX_IDS_PER_REQUEST]
            params = [("ids", id_) for id_ in chunk]
            resp = await self._client.get(
                f"{self._base_url}/recon/entities/notifications/v1",
                headers=await self._auth_headers(),
                params=params,
            )
            resp.raise_for_status()
            resources.extend(resp.json().get("resources", []))
        return resources

    # ------------------------------------------------------------------
    # parse_notifications()
    # ------------------------------------------------------------------

    def parse_notifications(self, data: list[dict]) -> list[RawDetection]:
        """Map CrowdStrike Recon notification dicts to RawDetection objects.

        Actual CS Recon notification fields (verified 2026-03):
          id              — unique notification ID (base64-encoded)
          rule_name       — name of the matching monitoring rule
          rule_topic      — rule type (SA_DOMAIN, SA_BRAND, etc.)
          rule_priority   — high / medium / low
          item_type       — exposed_data, forum_post, etc.
          item_site       — source site (e.g. telegram.org)
          item_date       — ISO timestamp of the exposure event
          actor_slug      — threat actor slug (may be empty)
          source_category — chat_medium, paste_site, etc.
          breach_summary  — dict with name, description, credentials_domains, fields
          created_date    — ISO timestamp when CS created the notification
        """
        detections = []
        for item in data:
            notification_id = item.get("id", "")
            rule_name = item.get("rule_name", "")
            item_site = item.get("item_site", "")
            actor_slug = item.get("actor_slug", "")
            item_type = item.get("item_type", "")
            source_category = item.get("source_category", "")

            # Extract breach summary details if present
            breach = item.get("breach_summary") or {}
            breach_desc = breach.get("description", "")
            cred_domains = breach.get("credentials_domains") or []

            title = f"Recon alert: {rule_name}" if rule_name else f"Recon notification {notification_id}"

            # Build a content block rich enough for keyword matching
            content_parts = filter(None, [
                breach_desc,
                f"Rule: {rule_name}" if rule_name else "",
                f"Site: {item_site}" if item_site else "",
                f"Type: {item_type}" if item_type else "",
                f"Category: {source_category}" if source_category else "",
                f"Actor: {actor_slug}" if actor_slug else "",
                f"Credential domains: {', '.join(cred_domains)}" if cred_domains else "",
            ])
            full_content = "\n".join(content_parts)

            # Use the source's created_date for accurate first_seen
            from datetime import datetime, timezone
            created_str = item.get("created_date", "")
            try:
                collected = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                collected = datetime.now(timezone.utc)

            detections.append(
                RawDetection(
                    source=self.name,
                    source_url="",  # CS Recon doesn't provide a public URL
                    title=title,
                    content=full_content,
                    raw_payload=item,
                    actor=actor_slug or None,
                    collected_at=collected,
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
        """Return True if we can successfully obtain a bearer token."""
        try:
            await self._auth.get_token()
            return True
        except Exception:
            return False

    # ------------------------------------------------------------------
    # configure_watches() — manage server-side monitoring rules
    # ------------------------------------------------------------------

    async def configure_watches(self, keywords: list[str]) -> None:
        """Sync Recon monitoring rules to match the given keyword list.

        Strategy:
          - Fetch all existing rules from the API.
          - Create rules for keywords that don't have one yet.
          - Delete rules for keywords that are no longer in the list.
          - Warn if total rule count approaches the 50-rule limit.
        """
        existing = await self._get_existing_rules()
        existing_names = {r["name"] for r in existing}
        wanted_names = set(keywords)

        to_create = wanted_names - existing_names
        to_delete = [r["id"] for r in existing if r["name"] not in wanted_names]

        for keyword in to_create:
            await self._create_rule(keyword)

        if to_delete:
            await self._delete_rules(to_delete)

        total = len(existing) + len(to_create) - len(to_delete)
        if total >= _RULE_WARN_THRESHOLD:
            logger.warning(
                "CrowdStrike Recon rule count is %d (limit 50). "
                "Consider consolidating keywords.",
                total,
            )

    async def _get_existing_rules(self) -> list[dict]:
        """Return list of rule dicts with at minimum 'id' and 'value' keys."""
        # Step 1: get IDs
        resp = await self._client.get(
            f"{self._base_url}/recon/queries/rules/v1",
            headers=await self._auth_headers(),
        )
        resp.raise_for_status()
        rule_ids = resp.json().get("resources", [])
        if not rule_ids:
            return []

        # Step 2: get full rule objects
        params = [("ids", id_) for id_ in rule_ids]
        resp = await self._client.get(
            f"{self._base_url}/recon/entities/rules/v1",
            headers=await self._auth_headers(),
            params=params,
        )
        resp.raise_for_status()
        return resp.json().get("resources", [])

    async def _create_rule(self, keyword: str) -> None:
        resp = await self._client.post(
            f"{self._base_url}/recon/entities/rules/v1",
            headers=await self._auth_headers(),
            json={
                "name": keyword,
                "value": keyword,
                "filter": f'"{keyword}"',
                "priority": "medium",
                "topic": "generic",
            },
        )
        resp.raise_for_status()
        logger.info("Created a Recon watch rule")

    async def _delete_rules(self, rule_ids: list[str]) -> None:
        params = [("ids", id_) for id_ in rule_ids]
        resp = await self._client.delete(
            f"{self._base_url}/recon/entities/rules/v1",
            headers=await self._auth_headers(),
            params=params,
        )
        resp.raise_for_status()
        logger.info("Deleted %d orphaned Recon rules.", len(rule_ids))

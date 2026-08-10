"""
Notifier — sends detection alerts via multiple channels.

Channels (all fire in parallel when configured):
  1. Teams Graph API — Adaptive Card to a chat (preferred)
  2. Teams Webhook — Adaptive Card to a channel (fallback)
  3. Teams DB webhooks — additional destinations managed from the admin UI
  4. Pushover — Push notification to mobile/desktop

If no channels are configured (common in dev), the notifier logs a warning
and skips silently. It never raises — notification failure must never crash
the scheduler or app startup.

DB webhooks: each row in the `webhooks` table has its own severity_filter.
The notifier checks whether the detection's severity matches before sending.
The .env TEAMS_WEBHOOK_URL remains as a fallback and is always included if set.
"""
import asyncio
import logging
import time
from typing import TYPE_CHECKING

import httpx
from sqlalchemy import select

from app.config import settings
from app.metrics import notifications_sent
from app.models.detection import Detection
from app.utils.source_url import sanitize_source_url
from app.utils.url_validator import WebhookURLError, post_webhook_json

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Severity → Adaptive Card color mapping
# ---------------------------------------------------------------------------
_SEVERITY_STYLE: dict[str, str] = {
    "critical": "attention",   # red
    "high": "warning",         # orange/yellow
    "medium": "accent",        # blue
    "low": "good",             # green
}


# ---------------------------------------------------------------------------
# Card builder
# ---------------------------------------------------------------------------

_FALCON_BASE = settings.cs_falcon_console_base


def _build_investigation_links(
    source: str, title: str, source_url: str | None = None, raw_data: dict | None = None,
) -> list[dict[str, str]]:
    """Build context-aware deep links to external investigation tools.

    Only uses URL patterns verified to resolve (as of 2026-03):
      - ransomlook.io/group/{name}  → 200
      - falcon.<region>.crowdstrike.com/intelligence-v2/recon → login then Recon dashboard
      - otx.alienvault.com/pulse/{id} → 200
      - ransomware.live → SPA (fragments unreliable from cards, link to homepage)

    Returns Action.OpenUrl dicts.
    """
    from urllib.parse import quote
    links: list[dict[str, str]] = []
    rd = raw_data or {}

    if source == "crowdstrike_recon":
        # Link to Falcon Recon dashboard (verified URL as of 2026-03)
        links.append({"type": "Action.OpenUrl", "title": "Falcon Recon",
                      "url": f"{_FALCON_BASE}/intelligence-v2/recon"})

    elif source == "ransomwatch":
        # Actor group page on Ransomlook (verified 200)
        actor = rd.get("group") or rd.get("group_name", "")
        if actor:
            links.append({"type": "Action.OpenUrl", "title": f"Ransomlook: {actor}",
                          "url": f"https://www.ransomlook.io/group/{quote(actor)}"})
        links.append({"type": "Action.OpenUrl", "title": "Falcon Recon",
                      "url": f"{_FALCON_BASE}/intelligence-v2/recon"})

    elif source == "ransomlook":
        # Actor group page on Ransomlook (verified 200)
        actor = rd.get("group_name", "")
        if actor:
            links.append({"type": "Action.OpenUrl", "title": f"Ransomlook: {actor}",
                          "url": f"https://www.ransomlook.io/group/{quote(actor)}"})
        else:
            links.append({"type": "Action.OpenUrl", "title": "Ransomlook Recent",
                          "url": "https://www.ransomlook.io/recent"})
        links.append({"type": "Action.OpenUrl", "title": "Falcon Recon",
                      "url": f"{_FALCON_BASE}/intelligence-v2/recon"})

    elif source == "crowdstrike_intel":
        links.append({"type": "Action.OpenUrl", "title": "Falcon Intel",
                      "url": f"{_FALCON_BASE}/intelligence-v2/reports"})

    elif source == "alienvault_otx":
        pulse_id = rd.get("id", "")
        if pulse_id:
            links.append({"type": "Action.OpenUrl", "title": "OTX Pulse",
                          "url": f"https://otx.alienvault.com/pulse/{pulse_id}"})
        else:
            links.append({"type": "Action.OpenUrl", "title": "OTX Dashboard",
                          "url": "https://otx.alienvault.com/dashboard"})

    # Always include Falcon Recon as last resort
    if not links:
        links.append({"type": "Action.OpenUrl", "title": "Falcon Console",
                      "url": f"{_FALCON_BASE}/intelligence-v2/recon"})

    return links


def build_adaptive_card(
    *,
    severity: str,
    source: str,
    title: str,
    matched_keywords: list[str],
    first_seen: str,
    snippet: str,
    detection_id: int,
    base_url: str,
    actor: str | None = None,
    source_url: str | None = None,
    raw_data: dict | None = None,
) -> dict:
    """Build a Teams Adaptive Card dict for a single detection.

    The card layout:
      - Coloured header bar with severity label
      - Source, matched keywords, actor (if present), title, timestamp
      - Snippet block
      - Action buttons linking to external investigation tools (not Slink)

    Returns a plain Python dict ready to serialise to JSON.
    """
    style = _SEVERITY_STYLE.get(severity.lower(), "default")
    keywords_str = ", ".join(matched_keywords)

    # Build the facts list dynamically so we can omit Actor when absent
    facts = [
        {"title": "Source", "value": source},
        {"title": "Keywords", "value": keywords_str},
    ]
    if actor:
        facts.append({"title": "Actor", "value": actor})
    facts.append({"title": "First Seen", "value": first_seen})

    # Build action buttons — deep links to external investigation tools
    actions = _build_investigation_links(source, title, source_url, raw_data)

    return {
        "type": "AdaptiveCard",
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "version": "1.4",
        "body": [
            # Severity header with colour
            {
                "type": "Container",
                "style": style,
                "items": [
                    {
                        "type": "TextBlock",
                        "text": f"🔔 SLINK ALERT — {severity.upper()}",
                        "weight": "Bolder",
                        "size": "Medium",
                        "color": "Light",
                    }
                ],
            },
            # Title
            {
                "type": "TextBlock",
                "text": title,
                "weight": "Bolder",
                "wrap": True,
            },
            # Facts: source, keywords, actor, timestamp
            {
                "type": "FactSet",
                "facts": facts,
            },
            # Snippet
            {
                "type": "TextBlock",
                "text": snippet,
                "wrap": True,
                "isSubtle": True,
                "maxLines": 4,
            },
        ],
        "actions": actions,
    }


# ---------------------------------------------------------------------------
# Notifier class
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Pushover priority mapping (severity → Pushover priority)
# ---------------------------------------------------------------------------
_PUSHOVER_PRIORITY: dict[str, int] = {
    "critical": 1,   # high priority — bypasses quiet hours
    "high": 1,
    "medium": 0,      # normal priority
    "low": -1,        # low priority — no sound/vibration
}

_PUSHOVER_URL = "https://api.pushover.net/1/messages.json"

# ---------------------------------------------------------------------------
# Channel state cache — avoids a DB round-trip on every notification send
# ---------------------------------------------------------------------------

# {channel_type: (enabled, expires_at_monotonic)}
_channel_cache: dict[str, tuple[bool, float]] = {}
_CHANNEL_CACHE_TTL_SECONDS = 60.0
_cache_lock = asyncio.Lock()


async def _get_cached_channel_state(db: "AsyncSession | None", channel_type: str) -> bool:
    """Return channel enabled state, consulting a 60s in-memory TTL cache.

    Cache miss path hits the DB and populates the cache. Missing state, a
    missing session, or a database failure fails closed so an administrative
    disable cannot be bypassed by an availability fault.
    """
    now = time.monotonic()

    # Fast path — serve from cache if still fresh
    cached = _channel_cache.get(channel_type)
    if cached is not None:
        enabled, expires_at = cached
        if now < expires_at:
            return enabled

    # Cache miss or expired — load from DB
    if db is None:
        return False

    try:
        from app.models.notification_channel import NotificationChannel
        result = await db.execute(
            select(NotificationChannel).where(
                NotificationChannel.channel_type == channel_type
            )
        )
        channel = result.scalar_one_or_none()
        enabled = False if channel is None else channel.enabled

        # Populate cache under lock to prevent a race between concurrent senders
        async with _cache_lock:
            _channel_cache[channel_type] = (enabled, now + _CHANNEL_CACHE_TTL_SECONDS)
        return enabled
    except Exception as exc:
        logger.debug(
            "Failed to check channel %s state: %s — assuming disabled",
            channel_type,
            type(exc).__name__,
        )
        return False


def invalidate_channel_cache(channel_type: str | None = None) -> None:
    """Invalidate cached channel state.

    Called by the admin toggle endpoint so the change takes effect on the very
    next notification rather than waiting for the 60s TTL to expire.

    Pass channel_type=None to flush the entire cache (e.g. on startup).
    """
    if channel_type is None:
        _channel_cache.clear()
    else:
        _channel_cache.pop(channel_type, None)


class TeamsNotifier:
    """Send detection alerts via Teams and/or Pushover.

    Config is read from settings at construction time so the notifier is
    cheap to instantiate repeatedly (e.g. in tests with mocked settings).

    All configured channels fire in parallel — Pushover provides fast mobile
    push while Teams provides rich cards in the team chat.

    Channel enabled state is checked at send time from the notification_channels
    DB table, allowing runtime toggles without restarting the container.
    """

    def __init__(self) -> None:
        self._tenant_id = settings.teams_tenant_id
        self._client_id = settings.teams_client_id
        self._client_secret = settings.teams_client_secret
        self._chat_id = settings.teams_chat_id
        self._webhook_url = settings.teams_webhook_url
        self._base_url = settings.slink_base_url
        self._pushover_token = settings.pushover_api_token
        self._pushover_user = settings.pushover_user_key
        # Shared HTTP client — reuses TLS connections across all notification calls
        self._client = httpx.AsyncClient(timeout=15)
        # Graph API token cache — tokens are valid for ~1 hour, no need to re-auth each call
        self._graph_token: str | None = None
        self._graph_token_expires_at: float = 0.0

    async def close(self) -> None:
        """Close the shared httpx client. Called on app shutdown."""
        await self._client.aclose()

    async def _is_channel_enabled(self, db: "AsyncSession | None", channel_type: str) -> bool:
        """Check if a notification channel is enabled, using the module-level TTL cache."""
        return await _get_cached_channel_state(db, channel_type)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def send_detection(self, detection: Detection, db: "AsyncSession | None" = None) -> None:
        """Send alerts for a single critical/high severity detection."""
        card = build_adaptive_card(
            severity=detection.severity,
            source=detection.source,
            title=detection.title,
            matched_keywords=detection.matched_keywords or [],
            first_seen=detection.first_seen.isoformat() if detection.first_seen else "",
            snippet=detection.snippet,
            detection_id=detection.id,
            base_url=self._base_url,
            actor=getattr(detection, "actor", None),
            source_url=detection.source_url if detection.source_url else None,
            raw_data=detection.raw_data,
        )
        await self._dispatch_teams(card, severity=detection.severity, db=db)
        # Pushover URL = the original source (ransomlook, ransomwatch, etc.)
        # so the user can verify directly from their phone
        if await self._is_channel_enabled(db, "pushover"):
            source_url = sanitize_source_url(
                detection.source, detection.source_url
            ) or None
            await self._send_pushover(
                title=f"Slink {detection.severity.upper()}: {detection.source}",
                message=f"{detection.title}\nKeywords: {', '.join(detection.matched_keywords or [])}\n{detection.snippet[:200]}",
                severity=detection.severity,
                url=source_url,
                url_title=f"View on {detection.source}",
            )
        else:
            logger.debug("Pushover disabled via UI — skipping")

    async def send_batch(self, detections: list[Detection], db: "AsyncSession | None" = None) -> None:
        """Send a digest card for a batch of medium-severity detections."""
        if not detections:
            return

        count = len(detections)
        titles = "\n".join(f"- {d.title}" for d in detections[:10])
        if count > 10:
            titles += f"\n…and {count - 10} more"

        # Build a simplified summary card — not a per-detection card
        card = {
            "type": "AdaptiveCard",
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
            "version": "1.4",
            "body": [
                {
                    "type": "Container",
                    "style": "accent",
                    "items": [
                        {
                            "type": "TextBlock",
                            "text": f"📋 SLINK DIGEST — {count} medium-severity detection(s)",
                            "weight": "Bolder",
                            "size": "Medium",
                            "color": "Light",
                        }
                    ],
                },
                {
                    "type": "TextBlock",
                    "text": titles,
                    "wrap": True,
                },
            ],
            "actions": [
                {"type": "Action.OpenUrl", "title": "RansomWatch", "url": "https://ransomware.live/#/recent"},
                {"type": "Action.OpenUrl", "title": "Ransomlook", "url": "https://www.ransomlook.io/recent"},
                {"type": "Action.OpenUrl", "title": "Falcon Console", "url": f"{_FALCON_BASE}/intelligence-v2/recon"},
            ],
        }
        # Dispatch digest card to Teams (both .env webhook and DB webhooks)
        await self._dispatch_teams(card, severity="medium", db=db)
        if await self._is_channel_enabled(db, "pushover"):
            await self._send_pushover(
                title=f"Slink Digest: {count} medium detection(s)",
                message=titles,
                severity="medium",
                url="https://ransomware.live/#/recent",
                url_title="View on RansomWatch",
            )

    async def send_emergency(self, detection: "Detection", triage_result: str = "", db: "AsyncSession | None" = None) -> None:
        """Send emergency Pushover notification (priority 2).

        Priority 2 = emergency: bypasses quiet hours, retries every 3 minutes
        until the user acknowledges on their device. Expires after 3 hours.
        Also sends Teams card if configured.

        Only used for detections AI-triaged as matching a tracked incident.
        """
        card = build_adaptive_card(
            severity=detection.severity,
            source=detection.source,
            title=detection.title,
            matched_keywords=detection.matched_keywords or [],
            first_seen=detection.first_seen.isoformat() if detection.first_seen else "",
            snippet=detection.snippet,
            detection_id=detection.id,
            base_url=self._base_url,
            actor=getattr(detection, "actor", None),
            source_url=detection.source_url if detection.source_url else None,
            raw_data=detection.raw_data,
        )
        await self._dispatch_teams(card, severity=detection.severity, db=db)

        # Emergency Pushover — priority 2, retry every 3 min, expire after 3 hours
        if not await self._is_channel_enabled(db, "pushover"):
            logger.debug("Pushover disabled via UI — skipping emergency alert")
            return
        if not self._pushover_token or not self._pushover_user:
            logger.warning("Pushover not configured — cannot send emergency alert")
            return

        data: dict[str, str | int] = {
            "token": self._pushover_token,
            "user": self._pushover_user,
            "title": f"🚨 SLINK EMERGENCY: {detection.source}",
            "message": (
                f"{detection.title}\n"
                f"Keywords: {', '.join(detection.matched_keywords or [])}\n"
                f"{detection.snippet[:500]}"
            )[:1024],
            "priority": 2,       # Emergency — requires acknowledgment
            "retry": 180,        # Retry every 3 minutes
            "expire": 10800,     # Stop after 3 hours
            "sound": "alien",    # Distinct emergency sound
        }
        # Link to the original source (DLS site, ransomlook, etc.) so the
        # user can verify directly from their phone without needing VPN to Slink
        safe_source_url = sanitize_source_url(
            detection.source, detection.source_url
        )
        if safe_source_url:
            data["url"] = safe_source_url
            data["url_title"] = f"View on {detection.source}"
        else:
            data["url"] = f"{self._base_url.rstrip('/')}/detections/{detection.id}"
            data["url_title"] = "View in Slink"

        try:
            resp = await self._client.post(_PUSHOVER_URL, data=data)
            if resp.is_success:
                logger.info(
                    "EMERGENCY Pushover sent for detection %d — "
                    "will retry every 3 min until acknowledged",
                    detection.id,
                )
            else:
                logger.error(
                    "Emergency Pushover failed with status %s",
                    resp.status_code,
                )
        except Exception as exc:
            logger.error("Emergency Pushover error: %s", type(exc).__name__)

    async def send_health_alert(
        self,
        source_name: str,
        message: str,
        db: "AsyncSession | None" = None,
    ) -> None:
        """Send a source failure alert through the enabled Pushover channel."""
        if not await self._is_channel_enabled(db, "pushover"):
            logger.debug("Pushover disabled via UI — skipping health alert")
            return
        await self._send_pushover(
            title=f"Slink Health: {source_name}",
            message=message,
            severity="low",  # low = no sound, just badge
        )

    # ------------------------------------------------------------------
    # Internal dispatch
    # ------------------------------------------------------------------

    async def _dispatch_teams(
        self,
        card: dict,
        *,
        severity: str = "all",
        db: "AsyncSession | None" = None,
    ) -> None:
        """Route card to Graph API, .env webhook, and/or DB webhooks.

        Priority order:
          1. If Graph API is configured, send via Graph (to the chat).
          2. If TEAMS_WEBHOOK_URL (.env) is set, send to that URL.
          3. For each enabled DB webhook whose severity_filter matches, send there.

        Graph and webhooks are NOT mutually exclusive — all configured destinations
        receive the card independently.

        severity: the detection severity string ("critical", "high", …) or "all"
                  to match every webhook regardless of its filter.
        db: optional async DB session for loading DB webhooks. If None, only the
            .env webhook and Graph are used (backwards-compatible for callers that
            don't have a session available).
        """
        graph_configured = all([
            self._tenant_id,
            self._client_id,
            self._client_secret,
            self._chat_id,
        ])
        sent_any = False

        if graph_configured and await self._is_channel_enabled(db, "teams_graph"):
            await self._send_via_graph(card)
            sent_any = True
        elif graph_configured:
            logger.debug("Teams Graph channel disabled via UI — skipping")

        if self._webhook_url and await self._is_channel_enabled(db, "teams_env_webhook"):
            await self._send_via_webhook(card, self._webhook_url)
            sent_any = True
        elif self._webhook_url:
            logger.debug("Teams .env webhook disabled via UI — skipping")

        # Load additional webhook destinations from the database
        if db is not None:
            db_webhooks = await self._load_db_webhooks(db, severity)
            for wh in db_webhooks:
                await self._send_via_webhook(card, wh.url, name=wh.name)
                sent_any = True

        if not sent_any:
            logger.warning(
                "Teams notifier is not configured — "
                "set TEAMS_TENANT_ID/CLIENT_ID/CLIENT_SECRET/CHAT_ID "
                "or TEAMS_WEBHOOK_URL to enable alerts, "
                "or add webhooks via the admin UI."
            )

    async def _load_db_webhooks(self, db: "AsyncSession", severity: str) -> list:
        """Return enabled DB webhooks whose severity_filter includes `severity`.

        severity_filter values:
          "all" — receives every severity
          "critical,high" — receives critical and high only
          "critical" — receives critical only
        """
        from app.models.webhook import Webhook

        try:
            result = await db.execute(select(Webhook).where(Webhook.enabled == True))  # noqa: E712
            all_webhooks = result.scalars().all()
        except Exception as exc:
            logger.error("Failed to load DB webhooks: %s", type(exc).__name__)
            return []

        if severity == "all":
            # Caller doesn't know the severity (e.g. health alerts) — send everywhere
            return list(all_webhooks)

        matched = []
        for wh in all_webhooks:
            if wh.severity_filter == "all":
                matched.append(wh)
            else:
                allowed = {s.strip() for s in wh.severity_filter.split(",") if s.strip()}
                if severity.lower() in allowed:
                    matched.append(wh)
        return matched

    async def _send_via_graph(self, card: dict) -> None:
        """POST card to a Teams chat via Microsoft Graph API.

        OAuth2 client credentials flow: obtain a bearer token from the
        tenant-specific token endpoint, then POST the Adaptive Card as an
        attachment to the target chat.

        Security note: client_secret is never logged.
        """
        token = await self._get_graph_token()
        body = {
            "body": {
                "contentType": "html",
                "content": "<attachment id=\"slink-card\"></attachment>",
            },
            "attachments": [
                {
                    "id": "slink-card",
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": card,
                }
            ],
        }
        url = f"https://graph.microsoft.com/v1.0/chats/{self._chat_id}/messages"
        resp = await self._client.post(
            url,
            json=body,
            headers={"Authorization": f"Bearer {token}"},
        )
        if not resp.is_success:
            logger.error(
                "Graph API POST failed with status %s", resp.status_code
            )
        else:
            logger.debug("Teams alert sent via Graph API")

    async def _get_graph_token(self) -> str:
        """Obtain an OAuth2 bearer token using client credentials, cached until near expiry.

        Tokens are valid for ~1 hour. We refresh when less than 5 minutes remain
        to avoid races where a token expires mid-request.

        Security note: client_secret is never logged.
        """
        # Return cached token if it still has more than 5 minutes of life left
        if self._graph_token and time.monotonic() < self._graph_token_expires_at - 300:
            return self._graph_token

        url = (
            f"https://login.microsoftonline.com/{self._tenant_id}"
            "/oauth2/v2.0/token"
        )
        resp = await self._client.post(
            url,
            data={
                "grant_type": "client_credentials",
                "client_id": self._client_id,
                "client_secret": self._client_secret,  # never logged
                "scope": "https://graph.microsoft.com/.default",
            },
        )
        resp.raise_for_status()
        body = resp.json()
        self._graph_token = body["access_token"]
        expires_in = body.get("expires_in", 3600)  # default 1 hour if field absent
        self._graph_token_expires_at = time.monotonic() + expires_in
        return self._graph_token

    async def _send_via_webhook(self, card: dict, url: str, *, name: str = "") -> None:
        """POST card to a Teams Incoming Webhook URL (no OAuth required).

        Webhook payload wraps the Adaptive Card in a MessageCard-compatible
        envelope that Teams Incoming Webhooks understand.

        url: full webhook URL (from .env or DB)
        name: optional marker indicating this is a named database destination;
              the name itself is never logged
        """
        label = "named webhook" if name else "configured webhook"

        payload = {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "contentUrl": None,
                    "content": card,
                }
            ],
        }
        try:
            resp = await post_webhook_json(url, payload, timeout=15)
            if not resp.is_success:
                logger.error(
                    "Teams webhook POST failed [%s] with status %s",
                    label,
                    resp.status_code,
                )
                notifications_sent.labels(channel="webhook", status="failure").inc()
            else:
                logger.debug("Teams alert sent via webhook [%s]", label)
                notifications_sent.labels(channel="webhook", status="success").inc()
        except (WebhookURLError, httpx.HTTPError) as exc:
            logger.error("Teams webhook error [%s]: %s", label, type(exc).__name__)
            notifications_sent.labels(channel="webhook", status="failure").inc()

    async def _send_pushover(
        self,
        title: str,
        message: str,
        severity: str = "medium",
        url: str | None = None,
        url_title: str | None = None,
    ) -> None:
        """Send a push notification via Pushover API.

        Fires independently of Teams — both channels are used in parallel.
        If Pushover is not configured, logs a debug message and returns.
        """
        if not self._pushover_token or not self._pushover_user:
            logger.debug("Pushover not configured — skipping push notification")
            return

        data: dict[str, str | int] = {
            "token": self._pushover_token,
            "user": self._pushover_user,
            "title": title[:250],
            "message": message[:1024],
            "priority": _PUSHOVER_PRIORITY.get(severity.lower(), 0),
            "sound": "siren" if severity in ("critical", "high") else "pushover",
        }
        if url:
            data["url"] = url
            data["url_title"] = url_title or "View source"

        try:
            resp = await self._client.post(_PUSHOVER_URL, data=data)
            if resp.is_success:
                logger.debug("Pushover notification sent")
                notifications_sent.labels(channel="pushover", status="success").inc()
            else:
                logger.error(
                    "Pushover POST failed with status %s", resp.status_code
                )
                notifications_sent.labels(channel="pushover", status="failure").inc()
        except Exception as exc:
            logger.error("Pushover send error: %s", type(exc).__name__)
            notifications_sent.labels(channel="pushover", status="failure").inc()

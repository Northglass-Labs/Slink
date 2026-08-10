"""
Scheduler — APScheduler-based collector orchestration for Slink.

Each registered collector runs on its own interval (defined by poll_interval_seconds
on the collector class). The scheduler also handles:
  - Batching medium-severity notifications every 15 minutes
  - Pruning old detections daily at 3 AM (with JSONL export before deletion)
  - Reconciling CrowdStrike Recon monitoring rules on startup

Failure handling:
  - consecutive_failures is incremented on each poll failure
  - At 3 failures: health alert sent to Teams
  - At 10 failures: source is auto-disabled to prevent noise

The scheduler is a module-level singleton started by main.py lifespan.
"""
import json
import logging
import os
import time
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, select, update
from apscheduler.schedulers.asyncio import AsyncIOScheduler

from app.collectors import COLLECTOR_REGISTRY
from app.database import async_session
from app.models.detection import Detection
from app.models.keyword import Keyword
from app.models.source_status import SourceStatus
from app.metrics import collector_errors, collector_poll_duration, detections_created
from app.services.detection_engine import process_raw_detection
from app.services.ioc_extractor import extract_indicators
from app.services.notifier import TeamsNotifier
from app.services.triage import should_triage, triage_detection
from app.config import settings

logger = logging.getLogger(__name__)


def should_page_incident_candidate(ai_supports_emergency: bool) -> bool:
    """AI is advisory-only and may never downgrade an incident-keyword match."""
    return True

scheduler = AsyncIOScheduler()
notifier = TeamsNotifier()

# Thresholds for failure handling
# Health alert at 6 consecutive failures (~30 min for a 5-min collector)
# to avoid alerting on brief API outages
_HEALTH_ALERT_THRESHOLD = 6
_AUTO_DISABLE_THRESHOLD = 20


# ---------------------------------------------------------------------------
# Collector runner
# ---------------------------------------------------------------------------

async def run_collector(collector_cls) -> None:
    """Execute one full poll cycle for a single collector.

    Steps:
      1. Instantiate collector (constructor reads settings directly).
      2. Check if source is enabled in SourceStatus; skip if disabled.
      3. Stamp last_poll.
      4. Run collect(), match against active keywords, persist detections.
      5. Fire immediate Teams alerts for critical/high detections.
      6. On success: clear consecutive_failures counter.
      7. On failure: increment counter, alert at threshold, disable at limit.
    """
    source_name: str = collector_cls.name

    # Capture last_success before closing the DB session so we can pass it to
    # collect() outside the connection context.
    last_success: datetime | None = None

    async with async_session() as db:
        # Step 1: fetch or create the SourceStatus row
        result = await db.execute(
            select(SourceStatus).where(SourceStatus.source_name == source_name)
        )
        status_row: SourceStatus | None = result.scalar_one_or_none()
        if status_row is None:
            logger.warning("No SourceStatus row for %s — skipping poll.", source_name)
            return

        # Step 2: skip if disabled
        if not status_row.enabled:
            logger.debug("Collector %s is disabled — skipping.", source_name)
            return

        # Capture last_success timestamp before the session closes
        last_success = status_row.last_success

        # Step 3: stamp last_poll
        status_row.last_poll = datetime.now(timezone.utc)
        await db.commit()

    # Step 4: instantiate and collect (with one retry on timeout).
    # Construction is outside the DB session to avoid holding the connection
    # during potentially slow network I/O.
    #
    # We pass last_success to collect() so collectors that support incremental
    # polling (e.g. CrowdStrike Recon) can filter to new-only notifications
    # instead of re-fetching the most recent 100. Collectors that don't use
    # this parameter (RansomWatch, Ransomlook, OTX) simply ignore it.
    import httpx as _httpx
    collector = _instantiate_collector(collector_cls)
    poll_start_time = time.time()
    try:
        raw_detections = None
        for attempt in range(2):
            try:
                raw_detections = await collector.collect(since=last_success)
                break
            except _httpx.ReadTimeout:
                if attempt == 0:
                    logger.warning("Collector %s timed out — retrying once", source_name)
                    continue
                logger.error("Collector %s timed out on retry — marking as failure", source_name)
                collector_errors.labels(source=source_name).inc()
                await _handle_failure(source_name)
                return
            except Exception as exc:
                logger.error(
                    "Collector %s failed during collect(): %s",
                    source_name,
                    type(exc).__name__,
                )
                collector_errors.labels(source=source_name).inc()
                await _handle_failure(source_name)
                return
        if raw_detections is None:
            return

        # Step 5: load keywords and process each raw detection
        try:
            async with async_session() as db:
                kw_result = await db.execute(
                    select(Keyword).where(Keyword.enabled == True)  # noqa: E712
                )
                keyword_rows = kw_result.scalars().all()
                keywords = [
                    {"term": kw.term, "category": kw.category}
                    for kw in keyword_rows
                ]

                new_detections: list[Detection] = []
                for raw in raw_detections:
                    try:
                        detection = await process_raw_detection(raw, db, keywords)
                        if detection is not None:
                            new_detections.append(detection)
                            detections_created.labels(
                                source=detection.source,
                                severity=detection.severity,
                            ).inc()
                            # Extract IOC indicators from newly created detections
                            if detection.status == "new":
                                try:
                                    await extract_indicators(detection, db)
                                except Exception as ioc_exc:
                                    logger.error(
                                        "IOC extraction failed for detection %d: %s",
                                        detection.id,
                                        type(ioc_exc).__name__,
                                    )
                    except Exception as exc:
                        logger.error(
                            "Failed to process detection from %s: %s",
                            raw.source,
                            type(exc).__name__,
                        )

                # Single commit for the whole batch — replaces the per-item
                # commits that previously fired inside process_raw_detection()
                # and extract_indicators(). Reduces 100 round-trips to 1.
                await db.commit()

            # Step 6: fire notifications for critical/high detections
            # Two tiers:
            #   - Incident emergency: AI-triaged detections matching active incidents →
            #     Pushover priority 2 (retries every 3 min until acknowledged on phone)
            #   - Standard urgent: everything else → throttled digest notification
            #
            # Cross-source duplicates (status="duplicate") are excluded from notifications —
            # they are stored for completeness but the original source already notified.
            urgent = [
                d for d in new_detections
                if d.severity in ("critical", "high") and d.status != "duplicate"
            ]
            if urgent:
                try:
                    # Open a short-lived session for triage checks and notifications.
                    # We use a fresh session here rather than reusing the detection-processing
                    # session, which is already committed and closed above.
                    async with async_session() as notify_db:
                        # Partition detections: those matching active incidents get AI triage
                        incident_candidates = []
                        standard_urgent = []
                        for d in urgent:
                            if await should_triage(d, notify_db):
                                incident_candidates.append(d)
                            else:
                                standard_urgent.append(d)

                        # AI triage is advisory. Keyword-linked incident candidates
                        # retain emergency handling regardless of model output.
                        for detection in incident_candidates:
                            try:
                                ai_supports_emergency = await triage_detection(
                                    detection, notify_db
                                )
                                if not ai_supports_emergency:
                                    logger.warning(
                                        "AI marked incident-linked detection %d routine; "
                                        "deterministic policy retains emergency handling",
                                        detection.id,
                                    )
                                if should_page_incident_candidate(ai_supports_emergency):
                                    await notifier.send_emergency(detection, db=notify_db)
                            except Exception as triage_exc:
                                logger.error(
                                    "Triage failed for detection %d: %s — treating as emergency",
                                    detection.id,
                                    type(triage_exc).__name__,
                                )
                                await notifier.send_emergency(detection, db=notify_db)

                        # Standard urgent: throttled digest (gated by Pushover channel toggle —
                        # when disabled, only send_emergency still fires so admins can silence
                        # routine credential-exposure noise while keeping incident alerts live)
                        if standard_urgent:
                            if await notifier._is_channel_enabled(notify_db, "pushover"):
                                await _send_urgent_digest(standard_urgent, db=notify_db)
                            else:
                                logger.info(
                                    "Pushover channel disabled — suppressing %d standard urgent detections",
                                    len(standard_urgent),
                                )

                    # Mark all as notified with one bulk UPDATE instead of
                    # re-SELECTing every row and mutating ORM instances.
                    async with async_session() as db:
                        urgent_ids = [d.id for d in urgent]
                        if urgent_ids:
                            await db.execute(
                                update(Detection)
                                .where(Detection.id.in_(urgent_ids))
                                .values(notified_at=datetime.now(timezone.utc))
                            )
                            await db.commit()
                except Exception as notify_exc:
                    logger.error(
                        "Failed to process alerts for %d detections: %s",
                        len(urgent),
                        type(notify_exc).__name__,
                    )

            # Step 7: mark success and record poll duration
            collector_poll_duration.labels(source=source_name).observe(
                time.time() - poll_start_time
            )
            await _handle_success(source_name)
            logger.info(
                "Collector %s: %d raw items → %d new detections",
                source_name, len(raw_detections), len(new_detections),
            )

        except Exception as exc:
            logger.error(
                "Collector %s failed during processing: %s",
                source_name,
                type(exc).__name__,
            )
            collector_errors.labels(source=source_name).inc()
            await _handle_failure(source_name)
    finally:
        await collector.close()


def _instantiate_collector(collector_cls):
    """Instantiate a collector, injecting credentials from settings as needed.

    Collectors that require credentials (CrowdStrike, OTX) expect them in
    their constructors. Public collectors (RansomWatch, Ransomlook) take no args.
    """
    name: str = collector_cls.name

    if name in ("crowdstrike_recon", "crowdstrike_intel"):
        return collector_cls(
            client_id=settings.cs_client_id,
            client_secret=settings.cs_client_secret,
            base_url=settings.cs_base_url,
        )
    if name == "alienvault_otx":
        return collector_cls(api_key=settings.otx_api_key)
    if name == "nvd":
        # NVD works anonymously; the key just raises the rate-limit ceiling.
        return collector_cls(api_key=settings.nvd_api_key)
    if name == "github_advisory":
        # No token = collector auto-disables (returns []) — see the collector docstring.
        return collector_cls(token=settings.github_token)

    return collector_cls()


# ---------------------------------------------------------------------------
# Throttled urgent notification (one digest per poll cycle)
# ---------------------------------------------------------------------------

async def _send_urgent_digest(
    detections: list[Detection],
    db=None,
) -> None:
    """Send Pushover-only notification for standard urgent (critical/high) detections.

    Teams is intentionally excluded here — routine credential exposures from CS Recon
    are noisy and only Pushover is needed for standard urgent detections.
    Teams cards are reserved for AI-triaged emergencies and medium batches.

    For 1 detection: sends a detailed Pushover.
    For 2+: sends a digest Pushover with count and top entries.
    """
    if len(detections) == 1:
        # Single detection — Pushover only (no Teams for standard urgent Recon hits)
        d = detections[0]
        from app.utils.source_url import sanitize_source_url

        source_url = sanitize_source_url(d.source, d.source_url) or None
        await notifier._send_pushover(
            title=f"SLINK-{d.id} {d.severity.upper()}: {d.source}",
            message=f"{d.title}\nKeywords: {', '.join(d.matched_keywords or [])}\n{d.snippet[:200]}",
            severity=d.severity,
            url=source_url,
            url_title=f"View on {d.source}",
        )
        return

    # Multiple detections — digest format
    count = len(detections)
    source = detections[0].source

    # Group by severity
    critical_count = sum(1 for d in detections if d.severity == "critical")

    # Build summary lines (top 10)
    lines = []
    for d in detections[:10]:
        keywords = ", ".join(d.matched_keywords or [])
        lines.append(f"• SLINK-{d.id}: {d.title[:80]} [{keywords}]")
    if count > 10:
        lines.append(f"…and {count - 10} more")
    summary = "\n".join(lines)

    severity_label = "CRITICAL" if critical_count > 0 else "HIGH"
    severity_str = "critical" if critical_count > 0 else "high"

    # Pushover only — Teams is reserved for AI-triaged emergencies and medium
    # batches. Standard urgent Recon hits go to Pushover only.
    await notifier._send_pushover(
        title=f"Slink: {count} {severity_label.lower()} detections from {source}",
        message=summary[:1024],
        severity=severity_str,
        url=f"{notifier._base_url.rstrip('/')}/detections",
    )


# ---------------------------------------------------------------------------
# Failure/success helpers
# ---------------------------------------------------------------------------

async def _handle_success(source_name: str) -> None:
    """Update last_success and reset consecutive_failures."""
    async with async_session() as db:
        result = await db.execute(
            select(SourceStatus).where(SourceStatus.source_name == source_name)
        )
        row: SourceStatus | None = result.scalar_one_or_none()
        if row:
            row.last_success = datetime.now(timezone.utc)
            row.consecutive_failures = 0
            await db.commit()


async def _handle_failure(source_name: str) -> None:
    """Increment consecutive_failures; alert at 3, auto-disable at 10."""
    async with async_session() as db:
        result = await db.execute(
            select(SourceStatus).where(SourceStatus.source_name == source_name)
        )
        row: SourceStatus | None = result.scalar_one_or_none()
        if not row:
            return

        row.consecutive_failures += 1
        failures = row.consecutive_failures

        if failures >= _AUTO_DISABLE_THRESHOLD:
            row.enabled = False
            logger.error(
                "Collector %s auto-disabled after %d consecutive failures.",
                source_name, failures,
            )
            try:
                await notifier.send_health_alert(
                    source_name,
                    f"Source auto-disabled after {failures} consecutive failures.",
                    db=db,
                )
            except Exception:
                pass  # health alert failure must not cause further issues

        elif failures == _HEALTH_ALERT_THRESHOLD:
            logger.warning(
                "Collector %s has %d consecutive failures — sending health alert.",
                source_name, failures,
            )
            try:
                await notifier.send_health_alert(
                    source_name,
                    f"Collector has failed {failures} times in a row.",
                    db=db,
                )
            except Exception:
                pass

        await db.commit()


# ---------------------------------------------------------------------------
# Batch medium notifications (15-minute interval)
# ---------------------------------------------------------------------------

async def batch_medium_notifications() -> None:
    """Send a digest card for all un-notified medium-severity detections.

    Runs on a 15-minute fixed interval. Only sends if there is at least one
    qualifying detection; marks each as notified afterwards.
    """
    async with async_session() as db:
        result = await db.execute(
            select(Detection).where(
                Detection.severity == "medium",
                Detection.status == "new",
                Detection.notified_at.is_(None),
            )
        )
        detections = result.scalars().all()

        if not detections:
            return

        try:
            await notifier.send_batch(list(detections), db=db)
        except Exception as exc:
            logger.error(
                "batch_medium_notifications failed to send: %s",
                type(exc).__name__,
            )
            return

        # Single UPDATE for all medium detections instead of one-mutation-per-row.
        await db.execute(
            update(Detection)
            .where(Detection.id.in_([d.id for d in detections]))
            .values(notified_at=datetime.now(timezone.utc))
        )
        await db.commit()
        logger.info("Batched %d medium detections into Teams digest.", len(detections))


# ---------------------------------------------------------------------------
# Prune expired detections (daily at 3 AM)
# ---------------------------------------------------------------------------

async def _export_expiring(db, cutoff: datetime) -> None:
    """Export detections about to be pruned as JSONL for archival.

    Writes to ARCHIVE_PATH (env var, default ./data/archive). Each prune
    cycle creates a timestamped .jsonl file so exports are never overwritten.
    """
    result = await db.execute(
        select(Detection).where(Detection.created_at < cutoff)
    )
    expired = result.scalars().all()

    if not expired:
        return

    archive_dir = os.environ.get("ARCHIVE_PATH", "./data/archive")
    os.makedirs(archive_dir, exist_ok=True)

    filename = f"pruned-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.jsonl"
    filepath = os.path.join(archive_dir, filename)

    with open(filepath, "w") as f:
        for det in expired:
            record = {
                "id": det.id,
                "source": det.source,
                "title": det.title,
                "snippet": det.snippet,
                "source_url": det.source_url,
                "severity": det.severity,
                "status": det.status,
                "matched_keywords": det.matched_keywords,
                "first_seen": det.first_seen.isoformat() if det.first_seen else None,
                "last_seen": det.last_seen.isoformat() if det.last_seen else None,
                "created_at": det.created_at.isoformat() if det.created_at else None,
            }
            f.write(json.dumps(record) + "\n")

    logger.info("Exported %d expiring detections to %s", len(expired), filepath)


async def prune_expired_detections() -> None:
    """Delete detection rows older than retention_days (from app_settings).

    Runs as a daily cron job at 03:00 UTC. Reads retention_days from the
    app_settings DB table, falling back to config.py if the row is missing.
    Exports expiring detections as JSONL before deletion.
    """
    from app.models.app_setting import AppSetting

    async with async_session() as db:
        # Read retention_days from DB, fallback to env-based config
        result = await db.execute(
            select(AppSetting).where(AppSetting.key == "retention_days")
        )
        setting = result.scalar_one_or_none()
        retention_days = int(setting.value) if setting else settings.retention_days

        cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)

        # Export before deleting
        await _export_expiring(db, cutoff)

        # Bulk DELETE is O(1) round trips instead of one DELETE per row;
        # at 90-day retention on a noisy feed this is tens of thousands of
        # rows per prune cycle. Returning "rowcount" avoids loading the
        # soon-to-be-dead rows into memory just to count them.
        result = await db.execute(
            delete(Detection).where(Detection.created_at < cutoff)
        )
        count = result.rowcount or 0
        await db.commit()

    if count:
        logger.info("Pruned %d detections older than %d days.", count, retention_days)


# ---------------------------------------------------------------------------
# Reconcile CrowdStrike Recon rules (startup)
# ---------------------------------------------------------------------------

async def reconcile_recon_rules() -> None:
    """Sync CrowdStrike Recon monitoring rules to match the keyword table.

    Only runs if cs_client_id is configured. Loads enabled keywords and calls
    configure_watches() on the Recon collector. Runs once at startup.
    """
    from app.collectors.crowdstrike_recon import CrowdStrikeReconCollector

    try:
        async with async_session() as db:
            result = await db.execute(
                select(Keyword).where(Keyword.enabled == True)  # noqa: E712
            )
            keywords = [row.term for row in result.scalars().all()]

        collector = CrowdStrikeReconCollector(
            client_id=settings.cs_client_id,
            client_secret=settings.cs_client_secret,
            base_url=settings.cs_base_url,
        )
        try:
            await collector.configure_watches(keywords)
            logger.info("Recon rules reconciled: %d keywords active.", len(keywords))
        finally:
            await collector.close()

    except Exception as exc:
        logger.error("reconcile_recon_rules failed: %s", type(exc).__name__)


# ---------------------------------------------------------------------------
# Scheduler setup — called from main.py lifespan
# ---------------------------------------------------------------------------

def setup_scheduler() -> None:
    """Register all jobs with the APScheduler instance.

    Called once during FastAPI startup before scheduler.start().
    """
    for source_name, collector_cls in COLLECTOR_REGISTRY.items():
        interval = getattr(collector_cls, "poll_interval_seconds", 300)

        # Recurring interval job
        scheduler.add_job(
            run_collector,
            trigger="interval",
            seconds=interval,
            args=[collector_cls],
            id=f"collector_{source_name}",
            replace_existing=True,
        )

        # Immediate startup job — runs once as soon as scheduler starts
        scheduler.add_job(
            run_collector,
            trigger="date",
            args=[collector_cls],
            id=f"collector_{source_name}_startup",
            replace_existing=True,
        )

    # Medium-severity batch digest every 15 minutes
    scheduler.add_job(
        batch_medium_notifications,
        trigger="interval",
        minutes=15,
        id="batch_medium_notifications",
        replace_existing=True,
    )

    # Daily prune at 03:00 UTC
    scheduler.add_job(
        prune_expired_detections,
        trigger="cron",
        hour=3,
        minute=0,
        id="prune_expired_detections",
        replace_existing=True,
    )

    # Reconcile CrowdStrike Recon rules on startup (only if credentials set)
    if settings.cs_client_id:
        scheduler.add_job(
            reconcile_recon_rules,
            trigger="date",
            id="reconcile_recon_rules_startup",
            replace_existing=True,
        )

    logger.info(
        "Scheduler configured: %d collectors + batch + prune jobs.",
        len(COLLECTOR_REGISTRY),
    )

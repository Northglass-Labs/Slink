from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import cast, Date, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.middleware.auth import get_current_user
from app.models.detection import Detection
from app.models.source_status import SourceStatus
from app.models.user import User
from app.schemas.dashboard import (
    DashboardDetectionSummary,
    DashboardStats,
    SeverityDistribution,
    TimeSeriesPoint,
)

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("/stats", response_model=DashboardStats)
async def get_dashboard_stats(
    days: int = Query(30, ge=1, le=90),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """Return aggregated stats for the dashboard page."""

    # --- Grouped status + severity counts (1 query replaces 5) ---
    # Single GROUP BY (status, severity) lets us derive all status counts,
    # severity counts, and the severity distribution from one round trip.
    grouped_result = await db.execute(
        select(Detection.status, Detection.severity, func.count().label("cnt"))
        .group_by(Detection.status, Detection.severity)
    )
    grouped_rows = grouped_result.all()

    new_count = 0
    acknowledged_count = 0
    critical_count = 0
    high_count = 0
    severity_dist = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    for status_val, severity_val, cnt in grouped_rows:
        # Status counts: active = new + acknowledged
        # (excludes dismissed/escalated/duplicate, matching prior behavior)
        if status_val == "new":
            new_count += cnt
        elif status_val == "acknowledged":
            acknowledged_count += cnt

        # Severity counts and distribution exclude dismissed only
        # (escalated/duplicate are still counted, matching prior behavior)
        if status_val != "dismissed":
            if severity_val == "critical":
                critical_count += cnt
            elif severity_val == "high":
                high_count += cnt

            if severity_val in severity_dist:
                severity_dist[severity_val] += cnt

    active_count = new_count + acknowledged_count
    severity_distribution = SeverityDistribution(**severity_dist)

    # --- Last critical detection (needs ORDER BY + LIMIT) ---
    last_crit_result = await db.execute(
        select(Detection)
        .where(Detection.severity == "critical")
        .order_by(Detection.first_seen.desc())
        .limit(1)
    )
    last_crit = last_crit_result.scalar_one_or_none()
    last_critical = DashboardDetectionSummary.model_validate(last_crit) if last_crit else None

    # --- Source health (1 query replaces 2) ---
    # Denominator counts enabled sources only — a disabled source was
    # intentionally paused by an admin, not "failing". This matches the
    # Sources page, which shows disabled/healthy/failing as distinct pills.
    source_rows_result = await db.execute(
        select(SourceStatus.enabled, SourceStatus.consecutive_failures)
    )
    source_rows = source_rows_result.all()
    enabled_rows = [(e, f) for e, f in source_rows if e]
    sources_total = len(enabled_rows)
    sources_healthy = sum(1 for _enabled, failures in enabled_rows if failures == 0)
    sources_failing = sources_total - sources_healthy

    # --- Time series (detections per day by severity, last N days) ---
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    ts_result = await db.execute(
        select(
            cast(Detection.created_at, Date).label("date"),
            Detection.severity,
            func.count().label("count"),
        )
        .where(Detection.created_at >= cutoff)
        .group_by(cast(Detection.created_at, Date), Detection.severity)
        .order_by(cast(Detection.created_at, Date))
    )
    ts_rows = ts_result.all()

    # Build a dict keyed by date string, then convert to list
    ts_map: dict[str, dict[str, int]] = {}
    for row in ts_rows:
        date_str = row[0].isoformat() if hasattr(row[0], "isoformat") else str(row[0])
        if date_str not in ts_map:
            ts_map[date_str] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        ts_map[date_str][row[1]] = row[2]

    time_series = [
        TimeSeriesPoint(date=date_str, **counts)
        for date_str, counts in ts_map.items()
    ]

    # --- Needs attention: top 5 untriaged critical+high ---
    attention_result = await db.execute(
        select(Detection)
        .where(
            Detection.status == "new",
            Detection.severity.in_(["critical", "high"]),
        )
        .order_by(Detection.first_seen.desc())
        .limit(5)
    )
    attention_items = attention_result.scalars().all()
    needs_attention = [DashboardDetectionSummary.model_validate(d) for d in attention_items]

    return DashboardStats(
        active_count=active_count,
        new_count=new_count,
        acknowledged_count=acknowledged_count,
        critical_count=critical_count,
        high_count=high_count,
        last_critical=last_critical,
        sources_healthy=sources_healthy,
        sources_total=sources_total,
        sources_failing=sources_failing,
        severity_distribution=severity_distribution,
        time_series=time_series,
        needs_attention=needs_attention,
    )

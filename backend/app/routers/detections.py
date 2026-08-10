import csv
import io
from datetime import date, datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.middleware.auth import get_current_user, require_admin
from app.models.detection import Detection
from app.models.user import User
from app.schemas.detection import (
    DetectionBulkStatusUpdate,
    DetectionDetail,
    DetectionListItem,
    DetectionListResponse,
    DetectionStatusUpdate,
)
from app.services.audit import log_action
from app.services.ai_summary import (
    _CACHE_KEY as AI_SUMMARY_KEY,
    AiSummaryNotConfigured,
    generate_summary as ai_generate_summary,
    get_cached as ai_get_cached,
)
from app.services.ai_budget import (
    AiBudgetExceeded,
    AiConcurrencyExceeded,
    finish_ai_summary,
    reserve_ai_summary,
)
from app.utils.source_url import sanitize_source_url

router = APIRouter(prefix="/api/detections", tags=["detections"])


def _csv_safe(value: str | None) -> str:
    """Neutralize CSV formula injection.

    Excel / Google Sheets evaluate any cell starting with =, +, -, @, TAB,
    or CR as a formula. An attacker who can get hostile text into a feed
    (DLS post title, CrowdStrike rule hit) could add =WEBSERVICE(...) and
    exfiltrate the analyst's sheet the moment the export is opened. We
    prepend a single apostrophe to leading trigger chars — viewers see
    the literal text, the formula engine doesn't fire.
    """
    if value is None:
        return ""
    if value and value[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


# Columns the UI is allowed to sort by. Mapped explicitly to the SQLAlchemy
# column rather than resolved via getattr(Model, user_input) — prevents
# ordering on private/relationship attributes and silently falling back to
# nothing when callers typo a column name.
_SORT_COLUMNS = {
    "first_seen": Detection.first_seen,
    "last_seen": Detection.last_seen,
    "created_at": Detection.created_at,
    "severity": Detection.severity,
    "source": Detection.source,
    "status": Detection.status,
    "title": Detection.title,
}


def _build_detection_filters(
    source: str | None,
    severity: str | None,
    status: str | None,
    keyword: str | None,
    search: str | None,
    after: datetime | None,
    before: datetime | None,
) -> list:
    """Build list of SQLAlchemy filter clauses from query params.

    Filters are applied to both count and list queries to avoid subquery materialization
    and allow index use by the database.
    """
    filters = []
    if source:
        filters.append(Detection.source == source)
    if severity:
        filters.append(Detection.severity == severity)
    if status:
        filters.append(Detection.status == status)
    # keyword filter: check if the keyword term appears in the matched_keywords JSON array
    if keyword:
        filters.append(Detection.matched_keywords.contains([keyword]))
    if search:
        search_term = f"%{search}%"
        filters.append(
            Detection.title.ilike(search_term) | Detection.snippet.ilike(search_term)
        )
    if after:
        filters.append(Detection.created_at >= after)
    if before:
        filters.append(Detection.created_at <= before)
    return filters


@router.get("", response_model=DetectionListResponse)
async def list_detections(
    source: str | None = Query(None),
    severity: str | None = Query(None),
    status: str | None = Query(None),
    keyword: str | None = Query(None),
    search: str | None = Query(None),
    after: datetime | None = Query(None),
    before: datetime | None = Query(None),
    sort_by: str = Query("first_seen"),
    sort_dir: str = Query("desc"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """List detections with optional filters and pagination. Any authenticated user."""
    # Build filter clauses once to apply to both count and list queries
    filters = _build_detection_filters(source, severity, status, keyword, search, after, before)

    # Count query uses filters directly (can hit indexes)
    count_q = select(func.count()).select_from(Detection)
    if filters:
        count_q = count_q.where(*filters)
    count_result = await db.execute(count_q)
    total = count_result.scalar_one()

    # List query uses same filters with ordering/pagination
    query = select(Detection)
    if filters:
        query = query.where(*filters)

    # Dynamic sorting — explicit allowlist. Using getattr with arbitrary
    # user input would let callers sort on internal fields (e.g. raw_data)
    # or relationships, which is at best noisy and at worst a side channel.
    sort_column = _SORT_COLUMNS.get(sort_by, Detection.first_seen)
    if sort_dir == "asc":
        query = query.order_by(sort_column.asc())
    else:
        query = query.order_by(sort_column.desc())

    query = query.limit(limit).offset(offset)
    result = await db.execute(query)
    items = result.scalars().all()

    return DetectionListResponse(
        items=[DetectionListItem.model_validate(d) for d in items],
        total=total,
    )


@router.post("/bulk-status")
async def bulk_update_status(
    body: DetectionBulkStatusUpdate,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """Update status for multiple detections at once."""
    result = await db.execute(
        select(Detection).where(Detection.id.in_(body.ids))
    )
    detections = result.scalars().all()
    for det in detections:
        old_status = det.status
        det.status = body.status
        await log_action(
            db, user_id=_user.id, action="detection.status_changed",
            target_type="detection", target_id=det.id,
            detail={"old_status": old_status, "new_status": body.status},
        )
    await db.commit()
    return {"updated": len(detections)}


@router.get("/export")
async def export_detections(
    source: str | None = Query(None),
    severity: str | None = Query(None),
    status: str | None = Query(None),
    search: str | None = Query(None),
    after: datetime | None = Query(None),
    before: datetime | None = Query(None),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """Export filtered detections as CSV. Max 10,000 rows."""
    # Build filter clauses once
    filters = _build_detection_filters(source, severity, status, None, search, after, before)

    query = select(Detection)
    if filters:
        query = query.where(*filters)

    query = query.order_by(Detection.first_seen.desc()).limit(10000)
    result = await db.execute(query)
    detections = result.scalars().all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "source", "title", "severity", "status", "matched_keywords", "first_seen", "last_seen", "source_url"])
    for d in detections:
        writer.writerow([
            d.id,
            _csv_safe(d.source),
            _csv_safe(d.title),
            _csv_safe(d.severity),
            _csv_safe(d.status),
            _csv_safe(",".join(d.matched_keywords or [])),
            d.first_seen.isoformat() if d.first_seen else "",
            d.last_seen.isoformat() if d.last_seen else "",
            _csv_safe(sanitize_source_url(d.source, d.source_url)),
        ])

    filename = f"slink-detections-{date.today().isoformat()}.csv"
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/{detection_id}", response_model=DetectionDetail)
async def get_detection(
    detection_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get full detection detail. raw_data is only included for admin users."""
    result = await db.execute(select(Detection).where(Detection.id == detection_id))
    detection = result.scalar_one_or_none()
    if detection is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Detection not found")

    detail = DetectionDetail.model_validate(detection)
    # Redact raw_data for non-admin users — it may contain raw API payloads with PII
    if current_user.role != "admin":
        detail.raw_data = None

    return detail


@router.patch("/{detection_id}/status", response_model=DetectionDetail)
async def update_detection_status(
    detection_id: int,
    body: DetectionStatusUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Update the triage status on a detection. Any authenticated user."""
    result = await db.execute(select(Detection).where(Detection.id == detection_id))
    detection = result.scalar_one_or_none()
    if detection is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Detection not found")

    old_status = detection.status
    detection.status = body.status
    await log_action(
        db, user_id=current_user.id, action="detection.status_changed",
        target_type="detection", target_id=detection.id,
        detail={"old_status": old_status, "new_status": body.status},
    )
    await db.commit()
    await db.refresh(detection)

    detail = DetectionDetail.model_validate(detection)
    if current_user.role != "admin":
        detail.raw_data = None

    return detail


@router.post("/{detection_id}/ai-summary")
async def detection_ai_summary(
    detection_id: int,
    refresh: bool = Query(False, description="Bypass cache and re-call the LLM"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Generate (or return cached) Claude-Haiku summary for a detection.

    Cached inside ``detection.raw_data[_slink_ai_summary]`` for 24h. Pass
    ``?refresh=true`` to force a fresh call. Returns 503 if the deployment
    has no ``ANTHROPIC_API_KEY`` configured.
    """
    result = await db.execute(select(Detection).where(Detection.id == detection_id))
    detection = result.scalar_one_or_none()
    if detection is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Detection not found")

    if not refresh:
        cached = ai_get_cached(detection)
        if cached is not None:
            return {"cached": True, **cached}

    try:
        usage_id = await reserve_ai_summary(
            db, user_id=current_user.id, detection_id=detection.id
        )
    except (AiBudgetExceeded, AiConcurrencyExceeded) as exc:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=str(exc),
            headers={"Retry-After": "60"},
        )

    try:
        summary = await ai_generate_summary(detection)
    except AiSummaryNotConfigured:
        await finish_ai_summary(db, usage_id, status="failed")
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="AI summary disabled — ANTHROPIC_API_KEY is not configured.",
        )
    except Exception:
        await finish_ai_summary(db, usage_id, status="failed")
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="AI summary upstream call failed.",
        )

    raw = dict(detection.raw_data or {})
    raw[AI_SUMMARY_KEY] = summary
    detection.raw_data = raw
    await finish_ai_summary(db, usage_id, status="succeeded")
    await log_action(
        db,
        user_id=current_user.id,
        action="detection.ai_summary_generated",
        target_type="detection",
        target_id=detection.id,
        detail={"refresh": refresh, "model": summary.get("model", "unknown")},
    )
    await db.commit()

    return {"cached": False, **summary}

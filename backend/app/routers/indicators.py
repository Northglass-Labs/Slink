from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.middleware.auth import get_current_user
from app.models.indicator import Indicator
from app.models.user import User
from app.schemas.indicator import IndicatorResponse, IndicatorSearchResult

router = APIRouter(tags=["indicators"])


@router.get("/api/detections/{detection_id}/indicators", response_model=list[IndicatorResponse])
async def list_detection_indicators(
    detection_id: int,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """List all IOC indicators extracted from a specific detection."""
    result = await db.execute(
        select(Indicator)
        .where(Indicator.detection_id == detection_id)
        .order_by(Indicator.type, Indicator.value)
    )
    return result.scalars().all()


def _escape_like(value: str) -> str:
    """Escape SQL LIKE wildcards in user input.

    Without this, a query like `%` becomes a full-table regex that scans
    every indicator and returns everything, burning DB time. Worse, a
    well-timed set of `_`/`%` patterns can be used as a side channel.
    Backslash is our escape char (matches the companion `escape="\\"`
    argument on .ilike()).
    """
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


@router.get("/api/indicators/search", response_model=list[IndicatorSearchResult])
async def search_indicators(
    value: str = Query(..., min_length=3, max_length=200),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """Search indicators across all detections by value (case-insensitive partial match)."""
    pattern = f"%{_escape_like(value)}%"
    result = await db.execute(
        select(Indicator)
        .where(Indicator.value.ilike(pattern, escape="\\"))
        .order_by(Indicator.last_seen.desc())
        .limit(100)
    )
    return result.scalars().all()

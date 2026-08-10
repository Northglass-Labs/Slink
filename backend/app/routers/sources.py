from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.middleware.auth import get_current_user, require_admin
from app.models.source_status import SourceStatus
from app.models.user import User
from app.schemas.source import SourceStatusResponse, SourceUpdate

router = APIRouter(prefix="/api/sources", tags=["sources"])


@router.get("", response_model=list[SourceStatusResponse])
async def list_sources(
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """List all source statuses. Any authenticated user."""
    result = await db.execute(select(SourceStatus).order_by(SourceStatus.source_name))
    return result.scalars().all()


@router.patch("/{source_name}", response_model=SourceStatusResponse)
async def update_source(
    source_name: str,
    body: SourceUpdate,
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_admin),
):
    """Update enabled flag or poll interval for a source. Admin only."""
    result = await db.execute(select(SourceStatus).where(SourceStatus.source_name == source_name))
    source = result.scalar_one_or_none()
    if source is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Source not found")

    if body.enabled is not None:
        source.enabled = body.enabled
    if body.poll_interval_seconds is not None:
        source.poll_interval_seconds = body.poll_interval_seconds

    await db.commit()
    await db.refresh(source)
    return source

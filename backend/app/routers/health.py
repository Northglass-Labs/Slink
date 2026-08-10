from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.source_status import SourceStatus

router = APIRouter(prefix="/api", tags=["health"])


@router.get("/health")
async def health(db: AsyncSession = Depends(get_db)):
    """Health check — no auth required. Returns overall status and a per-source summary."""
    result = await db.execute(select(SourceStatus))
    sources = result.scalars().all()

    summary = [
        {
            "name": s.source_name,
            "enabled": s.enabled,
            "consecutive_failures": s.consecutive_failures,
            # A source is healthy if it has had no consecutive failures
            "healthy": s.consecutive_failures == 0,
        }
        for s in sources
    ]

    return {"status": "ok", "sources": summary}

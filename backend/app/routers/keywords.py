from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.middleware.auth import get_current_user, require_admin
from app.models.keyword import Keyword
from app.models.user import User
from app.schemas.keyword import KeywordCreate, KeywordResponse, KeywordUpdate
from app.services.audit import log_action
from app.services.scheduler import reconcile_recon_rules

router = APIRouter(prefix="/api/keywords", tags=["keywords"])


@router.get("", response_model=list[KeywordResponse])
async def list_keywords(
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """List all keywords. Any authenticated user."""
    result = await db.execute(select(Keyword).order_by(Keyword.id))
    return result.scalars().all()


@router.post("", response_model=KeywordResponse, status_code=status.HTTP_201_CREATED)
async def create_keyword(
    body: KeywordCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_admin),
):
    """Create a new keyword. Admin only."""
    keyword = Keyword(term=body.term, category=body.category, enabled=body.enabled)
    db.add(keyword)
    await db.flush()
    await log_action(
        db, user_id=_admin.id, action="keyword.created",
        target_type="keyword", target_id=keyword.id,
        detail={"term": keyword.term, "category": keyword.category},
    )
    await db.commit()
    await db.refresh(keyword)

    # Sync the updated keyword list to CrowdStrike Recon after the commit.
    # Fire-and-forget: reconcile_recon_rules() has its own try/except and never
    # raises, so a CS API failure will not affect the keyword create response.
    background_tasks.add_task(reconcile_recon_rules)

    return keyword


@router.put("/{keyword_id}", response_model=KeywordResponse)
async def update_keyword(
    keyword_id: int,
    body: KeywordUpdate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_admin),
):
    """Update a keyword. Admin only."""
    result = await db.execute(select(Keyword).where(Keyword.id == keyword_id))
    keyword = result.scalar_one_or_none()
    if keyword is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Keyword not found")

    changes = {}
    if body.term is not None:
        changes["old_term"] = keyword.term
        keyword.term = body.term
        changes["new_term"] = body.term
    if body.category is not None:
        changes["old_category"] = keyword.category
        keyword.category = body.category
        changes["new_category"] = body.category
    if body.enabled is not None:
        changes["old_enabled"] = keyword.enabled
        keyword.enabled = body.enabled
        changes["new_enabled"] = body.enabled

    await log_action(
        db, user_id=_admin.id, action="keyword.updated",
        target_type="keyword", target_id=keyword.id,
        detail=changes if changes else None,
    )
    await db.commit()
    await db.refresh(keyword)

    # Sync the updated keyword list to CrowdStrike Recon after the commit.
    # Fire-and-forget: reconcile_recon_rules() has its own try/except and never
    # raises, so a CS API failure will not affect the keyword update response.
    background_tasks.add_task(reconcile_recon_rules)

    return keyword


@router.delete("/{keyword_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_keyword(
    keyword_id: int,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_admin),
):
    """Delete a keyword. Admin only."""
    result = await db.execute(select(Keyword).where(Keyword.id == keyword_id))
    keyword = result.scalar_one_or_none()
    if keyword is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Keyword not found")

    await log_action(
        db, user_id=_admin.id, action="keyword.deleted",
        target_type="keyword", target_id=keyword.id,
        detail={"term": keyword.term, "category": keyword.category},
    )
    await db.delete(keyword)
    await db.commit()

    # Sync the updated keyword list to CrowdStrike Recon after the commit.
    # Fire-and-forget: reconcile_recon_rules() has its own try/except and never
    # raises, so a CS API failure will not affect the keyword delete response.
    background_tasks.add_task(reconcile_recon_rules)

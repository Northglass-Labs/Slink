from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.middleware.auth import get_current_user, require_admin
from app.models.severity_rule import SeverityRule
from app.models.user import User
from app.schemas.severity_rule import (
    SeverityRuleCreate,
    SeverityRuleResponse,
    SeverityRuleUpdate,
)

router = APIRouter(prefix="/api/severity-rules", tags=["severity-rules"])


@router.get("", response_model=list[SeverityRuleResponse])
async def list_severity_rules(
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """List all severity rules ordered by priority (highest first). Any authenticated user."""
    result = await db.execute(
        select(SeverityRule).order_by(SeverityRule.priority.desc())
    )
    return result.scalars().all()


@router.post("", response_model=SeverityRuleResponse, status_code=status.HTTP_201_CREATED)
async def create_severity_rule(
    body: SeverityRuleCreate,
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_admin),
):
    """Create a new severity rule. Admin only."""
    rule = SeverityRule(
        source_pattern=body.source_pattern,
        keyword_category=body.keyword_category,
        base_severity=body.base_severity,
        priority=body.priority,
        enabled=body.enabled,
    )
    db.add(rule)
    await db.commit()
    await db.refresh(rule)
    return rule


@router.put("/{rule_id}", response_model=SeverityRuleResponse)
async def update_severity_rule(
    rule_id: int,
    body: SeverityRuleUpdate,
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_admin),
):
    """Update a severity rule. Admin only."""
    result = await db.execute(select(SeverityRule).where(SeverityRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if rule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Severity rule not found")

    if body.source_pattern is not None:
        rule.source_pattern = body.source_pattern
    if body.keyword_category is not None:
        rule.keyword_category = body.keyword_category
    if body.base_severity is not None:
        rule.base_severity = body.base_severity
    if body.priority is not None:
        rule.priority = body.priority
    if body.enabled is not None:
        rule.enabled = body.enabled

    await db.commit()
    await db.refresh(rule)
    return rule


@router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_severity_rule(
    rule_id: int,
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_admin),
):
    """Delete a severity rule. Admin only."""
    result = await db.execute(select(SeverityRule).where(SeverityRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if rule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Severity rule not found")

    await db.delete(rule)
    await db.commit()

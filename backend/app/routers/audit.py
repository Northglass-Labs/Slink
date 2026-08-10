from fastapi import APIRouter, Depends, Query
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.middleware.auth import require_admin
from app.models.audit_log import AuditLog
from app.models.user import User
from app.schemas.audit import AuditLogListResponse, AuditLogResponse

router = APIRouter(prefix="/api/audit", tags=["audit"])


@router.get("", response_model=AuditLogListResponse)
async def list_audit_logs(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    action: str | None = Query(None),
    target_type: str | None = Query(None),
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_admin),
):
    query = select(AuditLog, User.username).outerjoin(User, AuditLog.user_id == User.id)

    if action:
        query = query.where(AuditLog.action == action)
    if target_type:
        query = query.where(AuditLog.target_type == target_type)

    # Count
    count_q = select(func.count()).select_from(AuditLog)
    if action:
        count_q = count_q.where(AuditLog.action == action)
    if target_type:
        count_q = count_q.where(AuditLog.target_type == target_type)
    total = (await db.execute(count_q)).scalar_one()

    query = query.order_by(AuditLog.created_at.desc()).limit(limit).offset(offset)
    rows = (await db.execute(query)).all()

    items = [
        AuditLogResponse(
            id=log.id,
            user_id=log.user_id,
            username=username or "system",
            action=log.action,
            target_type=log.target_type,
            target_id=log.target_id,
            detail=log.detail,
            created_at=log.created_at,
        )
        for log, username in rows
    ]
    return AuditLogListResponse(items=items, total=total)

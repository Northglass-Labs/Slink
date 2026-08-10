"""Audit trail -- records who did what and when."""

import logging

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_log import AuditLog

logger = logging.getLogger(__name__)


async def log_action(
    db: AsyncSession,
    *,
    user_id: int | None,
    action: str,
    target_type: str,
    target_id: int | None = None,
    detail: dict | None = None,
) -> None:
    """Record an audit event. Never raises -- audit failures must not break the app."""
    try:
        entry = AuditLog(
            user_id=user_id,
            action=action,
            target_type=target_type,
            target_id=target_id,
            detail=detail,
        )
        db.add(entry)
        await db.flush()  # flush but don't commit -- caller manages the transaction
    except Exception as exc:
        logger.error("Failed to write audit log: %s", type(exc).__name__)

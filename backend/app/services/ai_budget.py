"""PostgreSQL-backed AI summary budget and concurrency reservations."""

from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.ai_usage import AiSummaryUsage

_AI_BUDGET_LOCK_KEY = 0x534C494E4B4149


class AiBudgetExceeded(RuntimeError):
    pass


class AiConcurrencyExceeded(RuntimeError):
    pass


async def reserve_ai_summary(
    db: AsyncSession, *, user_id: int, detection_id: int
) -> int:
    """Atomically reserve daily budget and a cross-worker concurrency slot."""
    await db.execute(
        text("SELECT pg_advisory_xact_lock(:lock_key)"),
        {"lock_key": _AI_BUDGET_LOCK_KEY},
    )
    now = datetime.now(timezone.utc)
    day_start = now.replace(hour=0, minute=0, second=0, microsecond=0)

    global_count = (
        await db.execute(
            select(func.count())
            .select_from(AiSummaryUsage)
            .where(AiSummaryUsage.created_at >= day_start)
        )
    ).scalar_one()
    user_count = (
        await db.execute(
            select(func.count())
            .select_from(AiSummaryUsage)
            .where(
                AiSummaryUsage.created_at >= day_start,
                AiSummaryUsage.user_id == user_id,
            )
        )
    ).scalar_one()
    active_count = (
        await db.execute(
            select(func.count())
            .select_from(AiSummaryUsage)
            .where(
                AiSummaryUsage.status == "running",
                AiSummaryUsage.lease_expires_at > now,
            )
        )
    ).scalar_one()

    if (
        global_count >= settings.ai_summary_daily_limit
        or user_count >= settings.ai_summary_user_daily_limit
    ):
        await db.rollback()
        raise AiBudgetExceeded("AI summary daily budget exhausted")
    if active_count >= settings.ai_summary_max_concurrency:
        await db.rollback()
        raise AiConcurrencyExceeded("AI summary concurrency limit reached")

    usage = AiSummaryUsage(
        user_id=user_id,
        detection_id=detection_id,
        status="running",
        lease_expires_at=now + timedelta(seconds=settings.ai_summary_lease_seconds),
    )
    db.add(usage)
    await db.flush()
    usage_id = usage.id
    await db.commit()
    return usage_id


async def finish_ai_summary(
    db: AsyncSession, usage_id: int, *, status: str
) -> None:
    if status not in {"succeeded", "failed"}:
        raise ValueError("invalid AI usage status")
    result = await db.execute(
        select(AiSummaryUsage).where(AiSummaryUsage.id == usage_id)
    )
    usage = result.scalar_one_or_none()
    if usage is not None:
        usage.status = status
        usage.lease_expires_at = None

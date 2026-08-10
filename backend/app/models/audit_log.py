from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # ON DELETE SET NULL: deleting a user preserves their audit trail rather
    # than cascade-deleting or failing with FK error.
    user_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    action: Mapped[str] = mapped_column(String(50), nullable=False)  # e.g. "detection.status_changed", "keyword.created", "user.deleted"
    target_type: Mapped[str] = mapped_column(String(50), nullable=False)  # e.g. "detection", "keyword", "user", "incident", "source"
    target_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    detail: Mapped[dict | None] = mapped_column(JSONB, nullable=True)  # e.g. {"old_status": "new", "new_status": "acknowledged"}
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)

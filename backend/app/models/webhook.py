from datetime import datetime, timezone
from sqlalchemy import Boolean, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from app.database import Base


class Webhook(Base):
    __tablename__ = "webhooks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # Human-friendly label shown in the admin UI — e.g. "SOC Chat", "CISO Chat"
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    # The full Power Automate / Teams incoming webhook URL
    url: Mapped[str] = mapped_column(Text, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    # Which severity levels this webhook receives.
    # Examples: "all", "critical", "critical,high"
    severity_filter: Mapped[str] = mapped_column(String(50), default="all", nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

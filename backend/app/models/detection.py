from datetime import datetime, timezone
from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from app.database import Base


class Detection(Base):
    __tablename__ = "detections"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    snippet: Mapped[str] = mapped_column(Text, nullable=False)
    source_url: Mapped[str] = mapped_column(String(2000), nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    # victim_hash: SHA-256 of the normalised title only (no source prefix).
    # Used for cross-source dedup — the same victim reported by RansomWatch
    # and Ransomlook will share a victim_hash even though their content_hashes differ.
    # Nullable for backwards compatibility with existing rows.
    victim_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    matched_keywords: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    # Valid values: critical, high, medium, low
    severity: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    # Valid values: new, acknowledged, dismissed, escalated, duplicate
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="new", index=True)
    # JSONB over JSON: identical ergonomics in application code, but the
    # storage is binary + indexable so future queries against raw_data
    # (e.g. filter by raw.severity) don't require a full-table scan.
    raw_data: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    notified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

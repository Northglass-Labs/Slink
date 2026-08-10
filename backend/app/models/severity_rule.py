from sqlalchemy import Boolean, Integer, String
from sqlalchemy.orm import Mapped, mapped_column
from app.database import Base


class SeverityRule(Base):
    __tablename__ = "severity_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source_pattern: Mapped[str | None] = mapped_column(String(100), nullable=True)
    keyword_category: Mapped[str | None] = mapped_column(String(100), nullable=True)
    base_severity: Mapped[str] = mapped_column(String(20), nullable=False)
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

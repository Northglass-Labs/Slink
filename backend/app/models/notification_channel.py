from sqlalchemy import Boolean, String
from sqlalchemy.orm import Mapped, mapped_column
from app.database import Base


class NotificationChannel(Base):
    __tablename__ = "notification_channels"

    channel_type: Mapped[str] = mapped_column(String(50), primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    display_name: Mapped[str] = mapped_column(String(100), nullable=False)

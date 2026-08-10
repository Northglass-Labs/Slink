from datetime import datetime

from pydantic import BaseModel


class SourceStatusResponse(BaseModel):
    source_name: str
    last_poll: datetime | None
    last_success: datetime | None
    consecutive_failures: int
    enabled: bool
    poll_interval_seconds: int

    model_config = {"from_attributes": True}


class SourceUpdate(BaseModel):
    enabled: bool | None = None
    poll_interval_seconds: int | None = None

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, model_validator

from app.utils.source_url import sanitize_source_url


class DetectionListItem(BaseModel):
    """Detection summary used in list views — raw_data is intentionally excluded."""

    id: int
    source: str
    title: str
    snippet: str
    severity: str
    status: str
    matched_keywords: list[str]
    first_seen: datetime
    last_seen: datetime

    model_config = {"from_attributes": True}


class DetectionDetail(DetectionListItem):
    """Full detection detail — raw_data is populated only for admin users."""

    source_url: str
    content_hash: str
    notified_at: datetime | None
    created_at: datetime
    # None means the caller is not an admin and should not see this field
    raw_data: dict | None = None

    @model_validator(mode="after")
    def sanitize_external_link(self):
        self.source_url = sanitize_source_url(self.source, self.source_url)
        return self


class DetectionStatusUpdate(BaseModel):
    status: Literal["new", "acknowledged", "dismissed", "escalated"]


class DetectionBulkStatusUpdate(BaseModel):
    # Upper bound avoids both DoS via enormous lists and the Postgres
    # parameter limit (bound variables cap around 32k — way above what a
    # triager would ever legitimately select at once).
    ids: list[int] = Field(..., min_length=1, max_length=500)
    status: Literal["new", "acknowledged", "dismissed", "escalated"]


class DetectionListResponse(BaseModel):
    items: list[DetectionListItem]
    total: int

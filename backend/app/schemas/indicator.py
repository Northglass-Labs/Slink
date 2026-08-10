from datetime import datetime

from pydantic import BaseModel


class IndicatorResponse(BaseModel):
    id: int
    detection_id: int
    type: str
    value: str
    source: str
    first_seen: datetime
    last_seen: datetime

    model_config = {"from_attributes": True}


class IndicatorSearchResult(IndicatorResponse):
    pass  # Same shape, different semantic meaning

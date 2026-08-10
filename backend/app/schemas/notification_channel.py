from pydantic import BaseModel


class NotificationChannelResponse(BaseModel):
    channel_type: str
    enabled: bool
    display_name: str

    model_config = {"from_attributes": True}


class NotificationChannelUpdate(BaseModel):
    enabled: bool

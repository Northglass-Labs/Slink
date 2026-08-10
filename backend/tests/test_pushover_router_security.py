import logging
from unittest.mock import patch

from fastapi import HTTPException
from pydantic import ValidationError
import pytest

from app.routers.pushover import PushoverCustomMessage, PushoverUserAdd, get_group


pytestmark = pytest.mark.no_db


def test_pushover_request_fields_are_bounded():
    with pytest.raises(ValidationError):
        PushoverUserAdd(user_key="bad key", memo="x")
    with pytest.raises(ValidationError):
        PushoverUserAdd(user_key="a" * 30, memo="x" * 201)
    with pytest.raises(ValidationError):
        PushoverCustomMessage(title="x" * 251, message="ok")
    with pytest.raises(ValidationError):
        PushoverCustomMessage(title="ok", message="x" * 1025)


@pytest.mark.asyncio
async def test_pushover_response_body_is_not_returned_or_logged(httpx_mock, caplog):
    httpx_mock.add_response(
        url="https://api.pushover.net/1/groups/group-key.json?token=api-token",
        status_code=400,
        text="arbitrary-provider-secret",
    )

    with patch("app.routers.pushover.settings") as mock_settings:
        mock_settings.pushover_api_token = "api-token"
        mock_settings.pushover_user_key = "group-key"
        with caplog.at_level(logging.ERROR, logger="app.routers.pushover"):
            with pytest.raises(HTTPException) as exc_info:
                await get_group(None)

    assert exc_info.value.detail == "Pushover rejected the request"
    assert "arbitrary-provider-secret" not in caplog.text

"""
CrowdStrike OAuth2 token manager.

CrowdStrike uses client credentials OAuth2 — we POST client_id + client_secret
to the token endpoint and receive a bearer token valid for 30 minutes. This
helper caches the token and auto-refreshes it before it expires so multiple
collectors can share one auth instance without redundant token requests.

Security note: tokens are held in memory only, never logged or written to disk.
"""
import asyncio
import time

import httpx


_REFRESH_BUFFER_SECONDS = 60
_TOKEN_LIFETIME_SECONDS = 1800  # CrowdStrike tokens last 30 minutes


class CrowdStrikeAuth:
    """Shared OAuth2 bearer-token helper for CrowdStrike collectors."""

    def __init__(self, client_id: str, client_secret: str, base_url: str) -> None:
        self._client_id = client_id
        self._client_secret = client_secret
        self._base_url = base_url.rstrip("/")
        self._token: str | None = None
        self._expires_at: float = 0.0
        self._lock = asyncio.Lock()

    async def get_token(self) -> str:
        """Return a valid bearer token, refreshing if near expiry."""
        async with self._lock:
            if self._token is None or self._seconds_until_expiry() < _REFRESH_BUFFER_SECONDS:
                await self._authenticate()
            return self._token  # type: ignore[return-value]

    def _seconds_until_expiry(self) -> float:
        return self._expires_at - time.monotonic()

    async def _authenticate(self) -> None:
        """POST client credentials to the token endpoint and cache the result."""
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                f"{self._base_url}/oauth2/token",
                data={
                    "client_id": self._client_id,
                    "client_secret": self._client_secret,
                },
            )
        resp.raise_for_status()
        body = resp.json()
        self._token = body["access_token"]
        expires_in = body.get("expires_in", _TOKEN_LIFETIME_SECONDS)
        self._expires_at = time.monotonic() + expires_in

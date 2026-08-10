"""Shared auth helper for abuse.ch collectors.

abuse.ch made the ``Auth-Key`` HTTP header mandatory across all of its feeds
(ThreatFox, URLhaus, MalwareBazaar, Feodo Tracker, SSLBL) in 2025. A single
free Auth-Key — registered at https://auth.abuse.ch — authenticates every
feed they publish. Routing all four collectors through one helper means we
have exactly one place to update if abuse.ch changes the auth scheme again.

Behaviour:
  - When the key is set, every outbound request gets ``Auth-Key: <key>``.
  - When the key is empty, headers are returned untouched. Each collector
    is responsible for short-circuiting its own ``collect()`` to return
    an empty list — this matches the rest of the registry, where missing
    credentials disable the collector instead of crashing the scheduler.
"""

from __future__ import annotations

import httpx


class AbuseChAuth:
    """Holds the abuse.ch Auth-Key and attaches it to outbound requests."""

    HEADER_NAME = "Auth-Key"

    def __init__(self, auth_key: str) -> None:
        # Store as a stripped string so blank/whitespace values count as missing.
        self._auth_key = (auth_key or "").strip()

    @property
    def auth_key(self) -> str:
        return self._auth_key

    @property
    def configured(self) -> bool:
        """True when an Auth-Key is set; collectors should no-op otherwise."""
        return bool(self._auth_key)

    def headers(self, extra: dict | None = None) -> dict:
        """Return a header dict with Auth-Key added when configured.

        Used at httpx.AsyncClient construction so every request through that
        client carries the header automatically — no need to remember it on
        each call site.
        """
        result: dict = dict(extra or {})
        if self._auth_key:
            result[self.HEADER_NAME] = self._auth_key
        return result

    def attach(self, request: httpx.Request) -> httpx.Request:
        """Attach the Auth-Key header to an existing httpx.Request in place.

        Useful for one-off requests built outside an AsyncClient.
        """
        if self._auth_key:
            request.headers[self.HEADER_NAME] = self._auth_key
        return request

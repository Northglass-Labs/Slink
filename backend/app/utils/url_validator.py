"""HTTPS provider allowlisting and DNS-pinned webhook delivery."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import ipaddress
import socket
import ssl
from urllib.parse import urlsplit

import httpcore
import httpx
from httpcore._backends.auto import AutoBackend
from httpcore._backends.base import (
    SOCKET_OPTION,
    AsyncNetworkBackend,
    AsyncNetworkStream,
)


class WebhookURLError(ValueError):
    pass


_ALLOWED_HOSTS = (
    ".webhook.office.com",
    ".logic.azure.com",
    ".environment.api.powerplatform.com",
    ".powerautomate.com",
    "hooks.slack.com",
    "discord.com",
    "discordapp.com",
)


@dataclass(frozen=True)
class WebhookTarget:
    url: str
    hostname: str
    port: int
    ip: str


def _host_is_allowed(hostname: str) -> bool:
    for pattern in _ALLOWED_HOSTS:
        if pattern.startswith("."):
            if hostname.endswith(pattern) and hostname != pattern[1:]:
                return True
        elif hostname == pattern:
            return True
    return False


def _parse(url: str) -> tuple[str, int]:
    if not url or any(ord(character) < 32 for character in url):
        raise WebhookURLError("Webhook URL contains invalid control characters")
    try:
        parsed = urlsplit(url)
        hostname = (parsed.hostname or "").encode("idna").decode("ascii").lower()
        port = parsed.port or 443
    except (UnicodeError, ValueError) as exc:
        raise WebhookURLError("Invalid webhook URL") from exc
    if parsed.scheme != "https":
        raise WebhookURLError("Webhook URL must use HTTPS")
    if not hostname:
        raise WebhookURLError("Webhook URL must have a hostname")
    if parsed.username is not None or parsed.password is not None:
        raise WebhookURLError("Webhook URL must not include user information")
    if port != 443:
        raise WebhookURLError("Webhook URL must use the standard HTTPS port")
    if not _host_is_allowed(hostname):
        raise WebhookURLError("Webhook hostname is not an approved provider")
    return hostname, port


def _public_addresses(address_info: list) -> list[str]:
    if not address_info:
        raise WebhookURLError("Webhook hostname did not resolve")
    addresses: list[str] = []
    for info in address_info:
        value = info[4][0].split("%", 1)[0]
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise WebhookURLError("Webhook hostname returned an invalid address") from exc
        if not address.is_global:
            raise WebhookURLError("Webhook hostname resolved to a non-public address")
        normalized = str(address)
        if normalized not in addresses:
            addresses.append(normalized)
    if not addresses:
        raise WebhookURLError("Webhook hostname did not resolve")
    return addresses


def resolve_webhook_target(url: str) -> WebhookTarget:
    hostname, port = _parse(url)
    try:
        info = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise WebhookURLError("Could not resolve webhook hostname") from exc
    return WebhookTarget(
        url=url,
        hostname=hostname,
        port=port,
        ip=_public_addresses(info)[0],
    )


async def resolve_webhook_target_async(url: str) -> WebhookTarget:
    hostname, port = _parse(url)
    loop = asyncio.get_running_loop()
    try:
        info = await loop.getaddrinfo(
            hostname, port, type=socket.SOCK_STREAM
        )
    except socket.gaierror as exc:
        raise WebhookURLError("Could not resolve webhook hostname") from exc
    return WebhookTarget(
        url=url,
        hostname=hostname,
        port=port,
        ip=_public_addresses(info)[0],
    )


def validate_webhook_url(url: str) -> str:
    resolve_webhook_target(url)
    return url


async def validate_webhook_url_async(url: str) -> str:
    await resolve_webhook_target_async(url)
    return url


class PinnedAsyncNetworkBackend(AsyncNetworkBackend):
    """Connect one approved hostname to exactly the address already validated."""

    def __init__(
        self,
        *,
        hostname: str,
        pinned_ip: str,
        delegate: AsyncNetworkBackend | None = None,
    ) -> None:
        self._hostname = hostname
        self._pinned_ip = pinned_ip
        self._delegate = delegate or AutoBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: list[SOCKET_OPTION] | None = None,
    ) -> AsyncNetworkStream:
        if host.lower() != self._hostname:
            raise WebhookURLError("Webhook transport attempted an unpinned hostname")
        return await self._delegate.connect_tcp(
            host=self._pinned_ip,
            port=port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: list[SOCKET_OPTION] | None = None,
    ) -> AsyncNetworkStream:
        raise WebhookURLError("Unix sockets are not valid webhook destinations")

    async def sleep(self, seconds: float) -> None:
        await self._delegate.sleep(seconds)


class PinnedAsyncHTTPTransport(httpx.AsyncHTTPTransport):
    def __init__(self, target: WebhookTarget) -> None:
        super().__init__(verify=True, trust_env=False, retries=0)
        backend = PinnedAsyncNetworkBackend(
            hostname=target.hostname,
            pinned_ip=target.ip,
        )
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=ssl.create_default_context(),
            max_connections=1,
            max_keepalive_connections=0,
            retries=0,
            network_backend=backend,
        )


async def post_webhook_json(
    url: str, payload: dict, *, timeout: float = 15
) -> httpx.Response:
    """Validate once, then POST over a connection pinned to that exact IP."""
    target = await resolve_webhook_target_async(url)
    transport = PinnedAsyncHTTPTransport(target)
    async with httpx.AsyncClient(
        transport=transport,
        timeout=timeout,
        follow_redirects=False,
        trust_env=False,
    ) as client:
        return await client.post(url, json=payload)

"""
Rate limiting middleware for Slink.

Uses slowapi (a Starlette/FastAPI wrapper around the `limits` library) to
enforce per-IP request rate limits on security-sensitive endpoints.

Why rate-limit login?
  An unprotected login endpoint is the easiest brute-force vector. Without
  rate limiting, an attacker can try millions of passwords in minutes.
  5 attempts per minute per IP makes offline password attacks impractical
  while not impacting legitimate users.

Forwarding headers are accepted only when the direct peer belongs to an
explicitly configured trusted-proxy CIDR. The chain is then walked from
right to left and the first untrusted address is used. A direct client cannot
create arbitrary buckets by supplying X-Forwarded-For.
"""
from functools import lru_cache
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import ipaddress

from fastapi import HTTPException, status
from sqlalchemy import case
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import Request
from slowapi import Limiter

from app.config import settings
from app.models.auth_session import AuthRateLimit


@lru_cache(maxsize=16)
def _trusted_networks(value: str) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    networks = []
    for item in value.split(","):
        item = item.strip()
        if item:
            networks.append(ipaddress.ip_network(item, strict=False))
    return tuple(networks)


def _parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    value = value.strip()
    if value.startswith("[") and "]" in value:
        value = value[1:value.index("]")]
    elif value.count(":") == 1 and "." in value:
        value = value.split(":", 1)[0]
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _is_trusted(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
    networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...],
) -> bool:
    return any(address.version == network.version and address in network for network in networks)


def _client_ip(request: Request) -> str:
    peer = _parse_ip(request.client.host) if request.client else None
    if peer is None:
        return "unknown"

    networks = _trusted_networks(settings.trusted_proxy_cidrs)
    if not _is_trusted(peer, networks):
        return str(peer)

    chain = []
    for item in request.headers.get("x-forwarded-for", "").split(","):
        address = _parse_ip(item)
        if address is None:
            return str(peer)
        chain.append(address)
    chain.append(peer)

    for address in reversed(chain):
        if not _is_trusted(address, networks):
            return str(address)
    return str(peer)


async def enforce_shared_auth_limit(
    db: AsyncSession,
    request: Request,
    *,
    bucket: str,
    limit: int,
    window_seconds: int,
) -> None:
    """Atomically enforce an auth limit in PostgreSQL across all workers/pods."""
    client = _client_ip(request)
    key = hmac.new(
        settings.secret_key.encode("utf-8"),
        f"{bucket}:{client}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(seconds=window_seconds)
    expired = AuthRateLimit.window_started_at <= cutoff

    statement = (
        pg_insert(AuthRateLimit)
        .values(key=key, window_started_at=now, attempt_count=1)
        .on_conflict_do_update(
            index_elements=[AuthRateLimit.key],
            set_={
                "window_started_at": case(
                    (expired, now), else_=AuthRateLimit.window_started_at
                ),
                "attempt_count": case(
                    (expired, 1), else_=AuthRateLimit.attempt_count + 1
                ),
            },
        )
        .returning(AuthRateLimit.attempt_count)
    )
    attempts = (await db.execute(statement)).scalar_one()
    # Commit before rejecting so the shared counter cannot be rolled back by
    # FastAPI's exception path.
    await db.commit()
    if attempts > limit:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests",
            headers={"Retry-After": str(window_seconds)},
        )


limiter = Limiter(key_func=_client_ip)

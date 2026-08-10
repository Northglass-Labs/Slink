from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from prometheus_fastapi_instrumentator import Instrumentator
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from sqlalchemy import func, select

from app.config import ConfigurationError, settings
from app.database import async_session
from app.logging_config import setup_logging
from app.middleware.rate_limit import limiter
from app.models.keyword import Keyword
from app.routers.audit import router as audit_router
from app.routers.auth import router as auth_router
from app.routers.dashboard import router as dashboard_router
from app.routers.detections import router as detections_router
from app.routers.health import router as health_router
from app.routers.keywords import router as keywords_router
from app.routers.sources import router as sources_router
from app.routers.webhooks import router as webhooks_router
from app.routers.pushover import router as pushover_router
from app.routers.notes import router as notes_router
from app.routers.notification_channels import router as notification_channels_router
from app.routers.incidents import router as incidents_router
from app.routers.indicators import router as indicators_router
from app.routers.severity_rules import router as severity_rules_router
from app.routers.app_settings import router as app_settings_router

setup_logging()


_INSECURE_ADMIN_PASSWORDS = {"changeme", "admin", "password", "slink", ""}


async def bootstrap_admin() -> None:
    """Create the admin user from settings if it does not already exist.

    In production, reject known bootstrap passwords even when a development
    instance already persisted the account before being promoted.
    """
    # Import here to avoid circular imports during startup
    from app.models.user import User
    from app.utils.security import hash_password, verify_password

    async with async_session() as db:
        if settings.app_env == "production":
            admin_result = await db.execute(select(User).where(User.role == "admin"))
            for existing_admin in admin_result.scalars().all():
                for weak_password in _INSECURE_ADMIN_PASSWORDS:
                    if weak_password and await verify_password(
                        weak_password, existing_admin.hashed_password
                    ):
                        raise ConfigurationError(
                            "A persisted administrator still uses a known bootstrap "
                            "password; rotate it before production startup"
                        )

        result = await db.execute(select(User).where(User.username == settings.admin_username))
        if not result.scalar_one_or_none():
            if (
                settings.app_env == "production"
                and settings.admin_password.lower() in _INSECURE_ADMIN_PASSWORDS
            ):
                raise ConfigurationError(
                    "ADMIN_PASSWORD is a known bootstrap default; set a strong value"
                )
            user = User(
                username=settings.admin_username,
                hashed_password=await hash_password(settings.admin_password),
                role="admin",
            )
            db.add(user)
            await db.commit()


async def init_source_status() -> None:
    """Ensure a SourceStatus row exists for every registered collector.

    Called on startup so the scheduler can always find a row to update.
    Rows are created with enabled=True and the collector's poll_interval_seconds.
    """
    from app.collectors import COLLECTOR_REGISTRY
    from app.models.source_status import SourceStatus

    async with async_session() as db:
        for source_name, collector_cls in COLLECTOR_REGISTRY.items():
            result = await db.execute(
                select(SourceStatus).where(SourceStatus.source_name == source_name)
            )
            if result.scalar_one_or_none() is None:
                row = SourceStatus(
                    source_name=source_name,
                    poll_interval_seconds=getattr(collector_cls, "poll_interval_seconds", 300),
                    enabled=True,
                    consecutive_failures=0,
                )
                db.add(row)
        await db.commit()


async def seed_default_keywords() -> None:
    """Seed example keywords on first boot so operators can see the flow.

    These are placeholders — delete them and add your own brand keywords,
    threat actor names, or incident identifiers from the Watchlist page.
    """
    async with async_session() as db:
        result = await db.execute(select(func.count()).select_from(Keyword))
        if result.scalar() > 0:
            return  # Already has keywords

        defaults = [
            ("acme-corp", "brand"),
            ("acme.example", "brand"),
            ("example-threat-actor", "threat_actor"),
        ]
        for term, category in defaults:
            db.add(Keyword(term=term, category=category, enabled=True))
        await db.commit()


async def init_notification_channels() -> None:
    """Seed notification channel rows if they don't exist."""
    from app.models.notification_channel import NotificationChannel

    defaults = [
        ("pushover", "Pushover"),
        ("teams_graph", "Teams Graph"),
        ("teams_env_webhook", "Teams Webhook (.env)"),
    ]
    async with async_session() as db:
        for channel_type, display_name in defaults:
            result = await db.execute(
                select(NotificationChannel).where(
                    NotificationChannel.channel_type == channel_type
                )
            )
            if result.scalar_one_or_none() is None:
                db.add(NotificationChannel(
                    channel_type=channel_type,
                    enabled=True,
                    display_name=display_name,
                ))
        await db.commit()


async def seed_initial_incident() -> None:
    """No-op by default — operators define their own incidents in the UI.

    Kept as a named function so deployments that want to ship a
    pre-populated incident can monkey-patch this call during startup
    without forking the lifespan.
    """
    return None


async def init_app_settings() -> None:
    """Seed default app_settings rows if they don't exist.

    The migration creates the retention_days row, but this covers
    the case where the app starts before migrations run (e.g. dev)
    or new settings are added in code before a migration is written.
    """
    from app.models.app_setting import AppSetting

    defaults = [
        ("retention_days", "90", "Days to keep detections before pruning"),
    ]
    async with async_session() as db:
        for key, value, description in defaults:
            result = await db.execute(
                select(AppSetting).where(AppSetting.key == key)
            )
            if result.scalar_one_or_none() is None:
                db.add(AppSetting(key=key, value=value, description=description))
        await db.commit()


@asynccontextmanager
async def lifespan(app: FastAPI):
    from app.services.scheduler import notifier, scheduler, setup_scheduler
    from app.services.triage import triage_close
    from app.services.ai_summary import ai_summary_close

    await bootstrap_admin()
    await init_source_status()
    await seed_default_keywords()
    await init_notification_channels()
    await init_app_settings()
    await seed_initial_incident()
    setup_scheduler()
    scheduler.start()
    yield
    scheduler.shutdown()
    await notifier.close()
    await triage_close()
    await ai_summary_close()


app = FastAPI(title="Slink", version="0.1.0", lifespan=lifespan)

# Attach the slowapi limiter state and register the 429 handler.
# The limiter instance is imported here and used via @limiter.limit() decorators
# on individual route handlers (currently /api/auth/login).
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

# CORS: allow the Vite dev server in local development.
# In production, the frontend and API share the same origin through the nginx
# reverse proxy, so no cross-origin requests occur and this list is effectively
# unused — but keeping it narrow is defense-in-depth.
_ALLOWED_ORIGINS = [
    "http://localhost:5173",   # Vite dev server
    "http://127.0.0.1:5173",
    "http://localhost:5180",   # Alternate Vite dev port
    "http://127.0.0.1:5180",
    settings.slink_base_url,   # e.g. https://slink.internal
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_ALLOWED_ORIGINS,
    allow_credentials=True,      # required for httpOnly refresh-token cookie
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)

# Prometheus metrics — auto-instruments HTTP latency/count/status and exposes /metrics
Instrumentator().instrument(app).expose(app, endpoint="/metrics")

app.include_router(audit_router)
app.include_router(auth_router)
app.include_router(dashboard_router)
app.include_router(detections_router)
app.include_router(incidents_router)
app.include_router(keywords_router)
app.include_router(sources_router)
app.include_router(health_router)
app.include_router(webhooks_router)
app.include_router(notes_router)
app.include_router(notification_channels_router)
app.include_router(indicators_router)
app.include_router(pushover_router)
app.include_router(severity_rules_router)
app.include_router(app_settings_router)

from typing import Literal
from urllib.parse import unquote, urlsplit

from pydantic import field_validator
from pydantic_settings import BaseSettings

from app.utils.username import normalize_username

# Known-weak defaults that must not run in production
_INSECURE_VALUES = {
    "",
    "changeme",
    "changeme-in-production",
    "change_me",
    "change_me_too",
    "generate-with-openssl-rand-hex-32",
    "replace-with-openssl-rand-hex-32",
    "secret",
    "slink",
    "slink-password",
    "your_db_password",
}


class ConfigurationError(RuntimeError):
    """Raised when a deployment would start with an unsafe runtime contract."""


class Settings(BaseSettings):
    # Database
    database_url: str = ""  # Set via DATABASE_URL env var

    # CrowdStrike
    cs_client_id: str = ""
    cs_client_secret: str = ""
    cs_base_url: str = "https://api.crowdstrike.com"
    # Falcon *console* base for the "open in Falcon" deep links in Teams cards.
    # Region-specific (us-1 / us-2 / eu-1 / us-gov-1). Defaults to us-1, the
    # region CrowdStrike uses in its own docs; self-hosters on another cloud
    # override via CS_FALCON_CONSOLE_BASE. This is a UI link target, not an API
    # endpoint — a wrong value only sends the deep link to the wrong region.
    cs_falcon_console_base: str = "https://falcon.us-1.crowdstrike.com"

    # AlienVault OTX
    otx_api_key: str = ""

    # abuse.ch — single Auth-Key authenticates every abuse.ch feed
    # (ThreatFox, URLhaus, MalwareBazaar, Feodo Tracker). Free signup at
    # https://auth.abuse.ch — Auth-Key became mandatory across all feeds in 2025.
    abusech_auth_key: str = ""

    # NVD CVE API 2.0 — optional, lifts rate limit from 5 req / 30 s to 50.
    # Free signup at https://nvd.nist.gov/developers/request-an-api-key.
    nvd_api_key: str = ""

    # GitHub Advisory Database — required to make this collector usable.
    # Unauthenticated GraphQL is capped at 60 req/h (with-token: 5,000 req/h).
    # A read-only personal access token (no scopes needed for public data) is enough.
    github_token: str = ""

    # Teams - Graph API (preferred)
    teams_tenant_id: str = ""
    teams_client_id: str = ""
    teams_client_secret: str = ""
    teams_chat_id: str = ""

    # Teams - Webhook (fallback)
    teams_webhook_url: str = ""

    # Pushover
    pushover_api_token: str = ""
    pushover_user_key: str = ""

    # Anthropic API (for AI triage of critical detections)
    anthropic_api_key: str = ""
    ai_summary_daily_limit: int = 100
    ai_summary_user_daily_limit: int = 25
    ai_summary_max_concurrency: int = 2
    ai_summary_lease_seconds: int = 90

    # Auth
    secret_key: str = "changeme-in-production"
    admin_username: str = "admin"
    admin_password: str = "changeme"
    access_token_expire_minutes: int = 15
    refresh_token_expire_hours: int = 8
    # Comma-separated CIDRs for the *direct* reverse proxies allowed to supply
    # forwarding headers. Empty means never trust client-supplied forwarding
    # headers, which is the safe local-development default.
    trusted_proxy_cidrs: str = ""

    # Set to True when running behind HTTPS (i.e. the nginx prod reverse proxy).
    # Marks the refresh-token cookie as Secure so browsers only send it over TLS.
    # Leave False for local HTTP dev only.
    secure_cookies: bool = False

    # Retention
    retention_days: int = 90

    # App
    app_env: Literal["development", "test", "production"] = "development"
    slink_base_url: str = "https://localhost"

    model_config = {"env_file": ".env", "extra": "ignore"}

    @field_validator("admin_username")
    @classmethod
    def admin_username_boundary(cls, value: str) -> str:
        return normalize_username(value)


def _is_placeholder(value: str) -> bool:
    normalized = value.strip().lower()
    return (
        normalized in _INSECURE_VALUES
        or "change_me" in normalized
        or "placeholder" in normalized
        or normalized.startswith("your_")
    )


def validate_runtime_settings(configured: Settings) -> None:
    """Enforce explicit production invariants independent of cookie settings."""
    if configured.app_env != "production":
        return

    errors: list[str] = []
    secret_bytes = configured.secret_key.encode("utf-8")
    if _is_placeholder(configured.secret_key) or len(secret_bytes) < 32:
        errors.append("SECRET_KEY must be at least 32 random bytes and not a placeholder")

    password_bytes = configured.admin_password.encode("utf-8")
    if (
        _is_placeholder(configured.admin_password)
        or len(configured.admin_password) < 12
        or len(password_bytes) > 72
    ):
        errors.append("ADMIN_PASSWORD must be 12-72 UTF-8 bytes and not a placeholder")

    try:
        parsed_db = urlsplit(configured.database_url)
        db_password = unquote(parsed_db.password or "")
    except ValueError:
        parsed_db = None
        db_password = ""
    if (
        parsed_db is None
        or parsed_db.scheme not in {"postgresql", "postgresql+asyncpg"}
        or not parsed_db.hostname
        or not parsed_db.path.strip("/")
        or _is_placeholder(db_password)
        or len(db_password) < 12
    ):
        errors.append("DATABASE_URL must contain a non-placeholder PostgreSQL credential")

    if not configured.secure_cookies:
        errors.append("SECURE_COOKIES must be true")

    try:
        parsed_base = urlsplit(configured.slink_base_url)
    except ValueError:
        parsed_base = None
    if (
        parsed_base is None
        or parsed_base.scheme != "https"
        or not parsed_base.hostname
        or parsed_base.hostname in {"localhost", "127.0.0.1", "::1"}
    ):
        errors.append("SLINK_BASE_URL must be a non-local HTTPS URL")

    if errors:
        raise ConfigurationError("Unsafe production configuration: " + "; ".join(errors))


settings = Settings()
validate_runtime_settings(settings)

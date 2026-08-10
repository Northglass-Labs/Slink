import pytest
from app.config import ConfigurationError, Settings, validate_runtime_settings

pytestmark = pytest.mark.no_db


def _valid_production_settings(**overrides) -> Settings:
    values = {
        "app_env": "production",
        "database_url": (
            "postgresql+asyncpg://slink:"
            "a-strong-database-password@slink-postgres:5432/slink"
        ),
        "secret_key": "ab" * 32,
        "admin_password": "correct horse battery staple",
        "secure_cookies": True,
        "slink_base_url": "https://slink.example.com",
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("secret_key", "replace-with-openssl-rand-hex-32"),
        ("secret_key", "short"),
        ("admin_password", "CHANGE_ME_TOO"),
        (
            "database_url",
            "postgresql+asyncpg://slink:CHANGE_ME@slink-postgres:5432/slink",
        ),
        ("secure_cookies", False),
        ("slink_base_url", "http://slink.example.com"),
    ],
)
def test_production_rejects_shipped_placeholders_and_insecure_transport(field, value):
    configured = _valid_production_settings(**{field: value})
    with pytest.raises(ConfigurationError):
        validate_runtime_settings(configured)


def test_valid_production_configuration_passes():
    validate_runtime_settings(_valid_production_settings())


def test_development_defaults_remain_available():
    validate_runtime_settings(Settings(_env_file=None, app_env="development"))

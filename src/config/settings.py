"""Application settings and configuration."""

import logging

from pydantic import ValidationInfo, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from src.config.cors_config import CORSConfiguration, CORSConfigurationError

logger = logging.getLogger(__name__)


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # Application (hardcoded constants)
    app_name: str = "Mindflow API"
    app_version: str = "0.1.0"

    # Environment-specific settings
    debug: bool = False
    environment: str  # development, staging, production

    # PostgreSQL
    postgres_user: str = "mindflow"
    postgres_password: str = "mindflow"
    postgres_db: str = "mindflow"
    postgres_port: int = 5432
    postgres_test_port: int = 5433
    postgres_url: str = ""
    postgres_pool_size: int = 10
    postgres_max_overflow: int = 20
    postgres_pool_timeout: int = 30
    postgres_pool_recycle: int = 3600
    postgres_echo: bool = False

    # API
    api_prefix: str = "/api"
    api_port: int = 8000

    # CORS Configuration (environment-aware)
    cors_allow_origins: str | None = None
    cors_allow_origin_regex: str | None = None
    cors_allow_methods: str | None = None
    cors_allow_headers: str | None = None
    cors_allow_credentials: bool = False
    cors_max_age: int = 600

    # Security
    secret_key: str
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 30

    # Logging
    log_level: str = "INFO"
    log_format: str = "json"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    @field_validator("environment", mode="before")
    @classmethod
    def validate_environment(cls, v: str) -> str:
        """Validate environment value."""
        valid_envs = {"development", "staging", "production"}
        env = str(v).lower()
        if env not in valid_envs:
            raise ValueError(f"Environment must be one of {valid_envs}, got {env}")
        return env

    @field_validator("debug", mode="before")
    @classmethod
    def validate_debug(cls, v: bool | str) -> bool:
        """Normalize debug values from environment inputs."""
        if isinstance(v, bool):
            return v

        value = str(v).strip().lower()
        if value in {"1", "true", "yes", "on", "debug"}:
            return True
        if value in {"0", "false", "no", "off", "release", ""}:
            return False

        raise ValueError(f"Invalid debug value: {v}")

    @field_validator("postgres_url", mode="before")
    @classmethod
    def build_postgres_url(cls, v: str | None, info: ValidationInfo) -> str:
        """Build async SQLAlchemy PostgreSQL URL from component env vars."""
        if isinstance(v, str) and v.strip():
            return v

        user = str(info.data.get("postgres_user", "mindflow"))
        password = str(info.data.get("postgres_password", "mindflow"))
        db = str(info.data.get("postgres_db", "mindflow"))
        port = int(info.data.get("postgres_port", 5432))
        return f"postgresql+asyncpg://{user}:{password}@localhost:{port}/{db}"

    def get_cors_configuration(self) -> CORSConfiguration:
        """Get CORS configuration based on environment settings.

        Delegates all validation to CORSConfiguration factory methods.

        Returns:
            CORSConfiguration instance

        Raises:
            CORSConfigurationError: If CORS configuration is invalid or insecure.

        """
        try:
            if self.environment == "development":
                return CORSConfiguration.for_development(
                    allow_origins=self.cors_allow_origins,
                    allow_credentials=self.cors_allow_credentials,
                )
            elif self.environment == "staging":
                return CORSConfiguration.for_staging(
                    allow_origins=self.cors_allow_origins or "",
                )
            else:  # production
                return CORSConfiguration.for_production(
                    allow_origins=self.cors_allow_origins or "",
                    allow_origin_regex=self.cors_allow_origin_regex,
                )
        except CORSConfigurationError as exc:
            logger.error(f"Failed to create CORS configuration: {exc}")
            raise


settings = Settings()  # type: ignore[call-arg]

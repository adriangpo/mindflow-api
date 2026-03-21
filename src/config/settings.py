"""Application settings and configuration."""

import logging
from pathlib import Path

from pydantic import Field, ValidationInfo, field_validator
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
    testing: bool = False

    # PostgreSQL
    postgres_user: str = "mindflow"
    postgres_password: str = Field(default_factory=str)
    postgres_db: str = "mindflow"
    postgres_host: str = "localhost"
    postgres_port: int = 5432
    postgres_url: str = ""
    postgres_pool_size: int = 10
    postgres_max_overflow: int = 20
    postgres_pool_timeout: int = 30
    postgres_pool_recycle: int = 3600
    postgres_echo: bool = False

    # API
    api_prefix: str = "/api"
    api_port: int = 8000
    public_base_url: str = ""

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

    # Local file storage
    storage_backend: str = "local"
    storage_root: Path = Path("storage")
    s3_endpoint_url: str = ""
    s3_bucket_name: str = ""
    aws_access_key_id: str = ""
    aws_secret_access_key: str = ""
    aws_region: str = "auto"

    # Redis
    redis_url: str = "redis://localhost:6379/0"

    # Exports
    job_dispatch_mode: str = "redis_worker"
    export_worker_enabled: bool = True
    export_worker_block_ms: int = 1000
    export_worker_claim_idle_ms: int = 30000
    export_sse_keepalive_seconds: int = 15
    export_job_ttl_seconds: int = 86400
    export_event_stream_ttl_seconds: int = 3600
    export_event_stream_maxlen: int = 200

    # QStash
    qstash_url: str = "https://qstash.upstash.io"
    qstash_token: str = ""
    qstash_current_signing_key: str = ""
    qstash_next_signing_key: str = ""

    # Notifications
    notification_provider: str = "auto"
    notification_background_dispatch_enabled: bool = True
    notification_dispatch_interval_seconds: int = 60
    notification_delivery_block_ms: int = 1000
    notification_delivery_claim_idle_ms: int = 30000
    notification_default_country_code: str = "+55"
    twilio_account_sid: str = ""
    twilio_auth_token: str = ""
    twilio_whatsapp_from_number: str = ""

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

    @field_validator("notification_provider", mode="before")
    @classmethod
    def validate_notification_provider(cls, v: str) -> str:
        """Validate outbound notification provider selection."""
        valid_providers = {"auto", "stub", "twilio"}
        provider = str(v).strip().lower()
        if provider not in valid_providers:
            raise ValueError(f"notification_provider deve ser um de {valid_providers}, recebido: {provider}")
        return provider

    @field_validator("notification_default_country_code", mode="before")
    @classmethod
    def validate_notification_default_country_code(cls, v: str) -> str:
        """Validate and normalize the default country code used for phone formatting."""
        country_code = str(v).strip()
        if not country_code.startswith("+") or not country_code[1:].isdigit():
            raise ValueError("notification_default_country_code deve estar no formato +<dígitos>")
        return country_code

    @field_validator("job_dispatch_mode", mode="before")
    @classmethod
    def validate_job_dispatch_mode(cls, v: str) -> str:
        """Validate background job dispatch mode."""
        valid_modes = {"redis_worker", "qstash"}
        mode = str(v).strip().lower()
        if mode not in valid_modes:
            raise ValueError(f"job_dispatch_mode deve ser um de {valid_modes}, recebido: {mode}")
        return mode

    @field_validator("storage_backend", mode="before")
    @classmethod
    def validate_storage_backend(cls, v: str) -> str:
        """Validate binary storage backend selection."""
        valid_backends = {"local", "s3"}
        backend = str(v).strip().lower()
        if backend not in valid_backends:
            raise ValueError(f"storage_backend deve ser um de {valid_backends}, recebido: {backend}")
        return backend

    @field_validator("postgres_url", mode="before")
    @classmethod
    def build_postgres_url(cls, v: str | None, info: ValidationInfo) -> str:
        """Build async SQLAlchemy PostgreSQL URL from component env vars."""
        if isinstance(v, str) and v.strip():
            return v

        user = str(info.data.get("postgres_user", "mindflow"))
        password = str(info.data.get("postgres_password", "mindflow"))
        db = str(info.data.get("postgres_db", "mindflow"))
        host = str(info.data.get("postgres_host", "localhost"))
        port = int(info.data.get("postgres_port", 5432))
        return f"postgresql+asyncpg://{user}:{password}@{host}:{port}/{db}"

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
            if self.environment == "staging":
                return CORSConfiguration.for_staging(
                    allow_origins=self.cors_allow_origins or "",
                )
            return CORSConfiguration.for_production(
                allow_origins=self.cors_allow_origins or "",
                allow_origin_regex=self.cors_allow_origin_regex,
            )
        except CORSConfigurationError as exc:
            logger.error("Failed to create CORS configuration: %s", exc)
            raise

    @field_validator("storage_root", mode="before")
    @classmethod
    def validate_storage_root(cls, v: str | Path) -> Path:
        """Normalize and validate the local storage root path."""
        storage_root = v if isinstance(v, Path) else Path(str(v).strip())

        if not str(storage_root):
            raise ValueError("storage_root cannot be empty")

        return storage_root

    @field_validator("public_base_url", "qstash_url", mode="before")
    @classmethod
    def normalize_url(cls, v: str) -> str:
        """Normalize optional base URLs by trimming whitespace and trailing slashes."""
        value = str(v).strip()
        return value.rstrip("/")

    @property
    def qstash_enabled(self) -> bool:
        """Whether the deployment dispatches jobs via QStash callbacks."""
        return self.job_dispatch_mode == "qstash"


settings = Settings()  # type: ignore[call-arg]

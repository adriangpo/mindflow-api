"""CORS configuration for production-grade, environment-aware setup."""

import logging
import re
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class CORSConfigurationError(Exception):
    """Raised when CORS configuration is invalid or insecure."""

    pass


def normalize_origin(origin: str) -> str:
    """Normalize an origin URL by stripping whitespace and trailing slashes.

    Args:
        origin: The origin URL to normalize

    Returns:
        Normalized origin URL

    Raises:
        CORSConfigurationError: If origin is invalid.

    """
    origin = origin.strip()

    if not origin:
        raise CORSConfigurationError("Origin cannot be empty")

    # Allow wildcard origin
    if origin == "*":
        return origin

    # Allow regex patterns starting with '^'
    if origin.startswith("^"):
        return origin

    # Validate URL format for non-regex origins
    try:
        parsed = urlparse(origin)
        if not parsed.scheme or not parsed.netloc:
            raise CORSConfigurationError(f"Invalid origin URL: {origin}")
    except Exception as exc:
        raise CORSConfigurationError(f"Failed to parse origin: {origin}") from exc

    # Remove trailing slashes
    origin = origin.rstrip("/")

    return origin


def parse_comma_separated_list(value: str | list[str] | None) -> list[str]:
    """Parse comma-separated string or return as-is if already a list.

    Args:
        value: Comma-separated string or list

    Returns:
        List of values with whitespace stripped

    Raises:
        CORSConfigurationError: If value is invalid.

    """
    if value is None:
        return []

    if isinstance(value, list):
        return [v.strip() for v in value if v.strip()]

    if isinstance(value, str):
        return [v.strip() for v in value.split(",") if v.strip()]

    raise CORSConfigurationError(f"Invalid value type: {type(value)}")


def is_regex_pattern(value: str) -> bool:
    """Check if a value is a regex pattern (starts with ^).

    Args:
        value: The pattern to check

    Returns:
        True if value is a regex pattern.

    """
    return value.startswith("^")


def compile_regex_pattern(pattern: str) -> re.Pattern[str]:
    """Compile and validate a regex pattern.

    Args:
        pattern: The regex pattern to compile

    Returns:
        Compiled regex pattern

    Raises:
        CORSConfigurationError: If pattern is invalid.

    """
    try:
        # Ensure pattern starts with ^
        if not pattern.startswith("^"):
            pattern = "^" + pattern

        return re.compile(pattern)
    except re.error as exc:
        raise CORSConfigurationError(f"Invalid regex pattern: {pattern}") from exc


class CORSConfiguration:
    """Production-grade CORS configuration with validation and multi-tenancy support.

    This class handles:
    - Environment variable parsing
    - Configuration validation
    - Security rule enforcement
    - Multi-tenancy compatibility
    - Startup validation with fail-fast behavior
    """

    def __init__(
        self,
        allow_origins: str | list[str] | None = None,
        allow_origin_regex: str | None = None,
        allow_methods: str | list[str] | None = None,
        allow_headers: str | list[str] | None = None,
        allow_credentials: bool = False,
        max_age: int = 600,
        environment: str = "development",
    ):
        """Initialize CORS configuration.

        Args:
            allow_origins: Comma-separated string or list of allowed origins
            allow_origin_regex: Optional regex pattern for dynamic origin matching
            allow_methods: Comma-separated string or list of allowed methods
            allow_headers: Comma-separated string or list of allowed headers
            allow_credentials: Whether to allow credentials (cookies, auth headers, etc.)
            max_age: Max age for preflight cache in seconds
            environment: Environment name (development, staging, production)

        Raises:
            CORSConfigurationError: If configuration is invalid or insecure.

        """
        self.environment = environment.lower()
        self.allow_credentials = allow_credentials
        self.max_age = max_age

        # Parse and normalize origins
        self.allow_origins: list[str] = []
        self.origin_regex: re.Pattern[str] | None = None

        try:
            # Parse origins list
            # For development, default to localhost if not provided
            if allow_origins is None and self.environment == "development":
                origins = [
                    "http://localhost:3000",
                    "http://localhost:8000",
                    "http://127.0.0.1:3000",
                    "http://127.0.0.1:8000",
                ]
            else:
                origins = parse_comma_separated_list(allow_origins)
            self.allow_origins = [normalize_origin(o) for o in origins]

            # Parse and compile regex pattern if provided
            if allow_origin_regex:
                self.origin_regex = compile_regex_pattern(allow_origin_regex)

            # Validate security rules
            self._validate_security_rules()

            # Parse methods and headers
            self.allow_methods = parse_comma_separated_list(allow_methods) or [
                "GET",
                "POST",
                "PUT",
                "DELETE",
                "PATCH",
                "OPTIONS",
            ]

            self.allow_headers = parse_comma_separated_list(allow_headers) or [
                "authorization",
                "content-type",
                "x-tenant-id",
            ]

            logger.info(f"CORS configuration initialized for {self.environment} environment")

        except CORSConfigurationError as exc:
            logger.error(f"CORS configuration error: {exc}")
            raise

    def _validate_security_rules(self) -> None:
        """Validate CORS security rules.

        Rules:
        1. If allow_credentials=True, enforce explicit origins (no wildcard)
        2. Never allow "*" with credentials
        3. Warn if wildcard is used in non-development environments
        4. Ensure at least one origin is configured in production

        Raises:
            CORSConfigurationError: If security rules are violated.

        """
        has_wildcard = "*" in self.allow_origins
        has_regex = self.origin_regex is not None
        has_explicit_origins = len(self.allow_origins) > 0 and not has_wildcard

        # Rule 1 & 2: Credentials + wildcard = insecure
        if self.allow_credentials and has_wildcard:
            raise CORSConfigurationError(
                "Cannot enable credentials with wildcard origins (*). " "Provide explicit allowed origins instead."
            )

        # Rule 3: Warn about wildcard in staging/production
        if has_wildcard and self.environment != "development":
            raise CORSConfigurationError(
                f"Wildcard origins (*) are not allowed in {self.environment} environment. "
                f"Provide explicit allowed origins."
            )

        # Rule 4: Production requires explicit origins
        if self.environment == "production" and not has_explicit_origins and not has_regex:
            raise CORSConfigurationError(
                "Production environment requires explicit allowed origins. "
                "Wildcard or empty origins are not permitted."
            )

        # Rule 5: Staging should have explicit origins
        if self.environment == "staging" and not has_explicit_origins and not has_regex:
            logger.warning(
                "Staging environment detected with no explicit origins. "
                "Consider specifying explicit allowed origins."
            )

    def get_middleware_config(self) -> dict:
        """Get configuration dict for FastAPI CORSMiddleware.

        Returns:
            Dictionary with middleware configuration.

        """
        return {
            "allow_origins": self.allow_origins,
            "allow_origin_regex": self.origin_regex.pattern if self.origin_regex else None,
            "allow_credentials": self.allow_credentials,
            "allow_methods": self.allow_methods,
            "allow_headers": self.allow_headers,
            "max_age": self.max_age,
        }

    def log_configuration(self) -> None:
        """Log effective CORS configuration at startup.

        Logs all settings except sensitive data.
        """
        origins_display = (
            f"{self.allow_origins[0]} (+{len(self.allow_origins) - 1} more)"
            if len(self.allow_origins) > 1
            else str(self.allow_origins)
        )

        regex_display = "Enabled (pattern not logged for security)" if self.origin_regex else "Disabled"

        logger.info(
            f"CORS Configuration:\n"
            f"  Environment: {self.environment}\n"
            f"  Origins: {origins_display}\n"
            f"  Regex Pattern: {regex_display}\n"
            f"  Methods: {', '.join(self.allow_methods)}\n"
            f"  Headers: {', '.join(self.allow_headers)}\n"
            f"  Credentials: {self.allow_credentials}\n"
            f"  Preflight Max Age: {self.max_age}s"
        )

    @staticmethod
    def for_development(
        allow_origins: str | list[str] | None = None,
        allow_credentials: bool = False,
    ) -> CORSConfiguration:
        """Create CORS configuration optimized for development.

        Args:
            allow_origins: Allowed origins (defaults to localhost)
            allow_credentials: Whether to allow credentials

        Returns:
            CORSConfiguration instance.

        """
        if allow_origins is None:
            allow_origins = [
                "http://localhost:3000",
                "http://localhost:8000",
                "http://127.0.0.1:3000",
                "http://127.0.0.1:8000",
            ]

        return CORSConfiguration(
            allow_origins=allow_origins,
            allow_credentials=allow_credentials,
            environment="development",
        )

    @staticmethod
    def for_staging(
        allow_origins: str | list[str],
    ) -> CORSConfiguration:
        """Create CORS configuration optimized for staging.

        Args:
            allow_origins: Allowed origins (required)

        Returns:
            CORSConfiguration instance

        Raises:
            CORSConfigurationError: If no origins are provided.

        """
        if not allow_origins:
            raise CORSConfigurationError("Staging environment requires explicit allowed origins")

        return CORSConfiguration(
            allow_origins=allow_origins,
            allow_credentials=True,  # Typically enabled in staging
            environment="staging",
        )

    @staticmethod
    def for_production(
        allow_origins: str | list[str],
        allow_origin_regex: str | None = None,
    ) -> CORSConfiguration:
        """Create CORS configuration optimized for production.

        Args:
            allow_origins: Allowed origins (required)
            allow_origin_regex: Optional regex pattern for subdomains

        Returns:
            CORSConfiguration instance

        Raises:
            CORSConfigurationError: If no origins are provided or config is insecure.

        """
        if not allow_origins:
            raise CORSConfigurationError("Production environment requires explicit allowed origins")

        return CORSConfiguration(
            allow_origins=allow_origins,
            allow_origin_regex=allow_origin_regex,
            allow_credentials=True,
            allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
            allow_headers=["authorization", "content-type", "x-tenant-id"],
            max_age=3600,  # 1 hour for production
            environment="production",
        )

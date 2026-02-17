"""Tests for CORS configuration and security."""

import re

import pytest

from src.config.cors_config import (
    CORSConfiguration,
    CORSConfigurationError,
    compile_regex_pattern,
    is_regex_pattern,
    normalize_origin,
    parse_comma_separated_list,
)


class TestOriginNormalization:
    """Test origin URL normalization."""

    def test_normalize_removes_trailing_slash(self):
        """Test that trailing slashes are removed."""
        assert normalize_origin("https://example.com/") == "https://example.com"
        assert normalize_origin("https://example.com//") == "https://example.com"

    def test_normalize_strips_whitespace(self):
        """Test that whitespace is stripped."""
        assert normalize_origin("  https://example.com  ") == "https://example.com"

    def test_normalize_preserves_valid_origins(self):
        """Test that valid origins are preserved."""
        assert normalize_origin("https://example.com") == "https://example.com"
        assert normalize_origin("http://localhost:3000") == "http://localhost:3000"

    def test_normalize_allows_regex_patterns(self):
        """Test that regex patterns are allowed."""
        pattern = "^https://.*\\.example\\.com$"
        assert normalize_origin(pattern) == pattern

    def test_normalize_rejects_empty_origin(self):
        """Test that empty origins are rejected."""
        with pytest.raises(CORSConfigurationError, match="Origin cannot be empty"):
            normalize_origin("")

        with pytest.raises(CORSConfigurationError, match="Origin cannot be empty"):
            normalize_origin("   ")

    def test_normalize_rejects_invalid_urls(self):
        """Test that invalid URLs are rejected."""
        with pytest.raises(CORSConfigurationError):
            normalize_origin("not-a-url")

        with pytest.raises(CORSConfigurationError):
            normalize_origin("example.com")  # Missing scheme


class TestParseCommaSeparatedList:
    """Test parsing of comma-separated lists."""

    def test_parse_string_with_multiple_items(self):
        """Test parsing comma-separated string."""
        result = parse_comma_separated_list("https://example.com,https://test.com")
        assert result == ["https://example.com", "https://test.com"]

    def test_parse_string_with_whitespace(self):
        """Test that whitespace is trimmed."""
        result = parse_comma_separated_list(" https://example.com , https://test.com ")
        assert result == ["https://example.com", "https://test.com"]

    def test_parse_list_returns_as_is(self):
        """Test that lists are returned with whitespace trimmed."""
        result = parse_comma_separated_list(["https://example.com", " https://test.com "])
        assert result == ["https://example.com", "https://test.com"]

    def test_parse_none_returns_empty_list(self):
        """Test that None returns an empty list."""
        assert parse_comma_separated_list(None) == []

    def test_parse_invalid_type_raises_error(self):
        """Test that invalid types raise error."""
        with pytest.raises(CORSConfigurationError):
            parse_comma_separated_list(123)  # type: ignore


class TestRegexPatterns:
    """Test regex pattern handling."""

    def test_is_regex_pattern_identifies_patterns(self):
        """Test that regex patterns are correctly identified."""
        assert is_regex_pattern("^https://.*\\.example\\.com$") is True
        assert is_regex_pattern("https://example.com") is False

    def test_compile_regex_pattern_valid(self):
        """Test that valid regex patterns compile."""
        pattern = compile_regex_pattern("^https://.*\\.example\\.com$")
        assert isinstance(pattern, re.Pattern)

    def test_compile_regex_pattern_adds_prefix(self):
        """Test that pattern is prefixed with ^ if missing."""
        pattern = compile_regex_pattern("https://.*\\.example\\.com$")
        assert pattern.pattern.startswith("^")

    def test_compile_regex_pattern_invalid(self):
        """Test that invalid regex patterns raise error."""
        with pytest.raises(CORSConfigurationError):
            compile_regex_pattern("^[invalid(regex$")


class TestCORSConfigurationDevelopment:
    """Test CORS configuration for development environment."""

    def test_development_defaults_to_localhost(self):
        """Test that development defaults to localhost.'"""
        config = CORSConfiguration(environment="development")
        assert "localhost" in str(config.allow_origins)
        assert "127.0.0.1" in str(config.allow_origins)

    def test_development_allows_wildcard(self):
        """Test that development allows wildcard origins."""
        config = CORSConfiguration(allow_origins="*", environment="development")
        assert "*" in config.allow_origins

    def test_development_with_custom_origins(self):
        """Test development with custom origins."""
        config = CORSConfiguration(
            allow_origins="http://custom.local",
            environment="development",
        )
        assert "http://custom.local" in config.allow_origins

    def test_development_factory_method(self):
        """Test factory method for development."""
        config = CORSConfiguration.for_development()
        assert config.environment == "development"
        assert len(config.allow_origins) >= 2
        assert "localhost" in str(config.allow_origins)

    def test_development_factory_with_credentials(self):
        """Test development factory with credentials."""
        config = CORSConfiguration.for_development(allow_credentials=True)
        assert config.allow_credentials is True


class TestCORSConfigurationStaging:
    """Test CORS configuration for staging environment."""

    def test_staging_requires_explicit_origins(self):
        """Test that staging requires explicit origins via factory method."""
        # Direct init with no origins warns, but factory requires them
        with pytest.raises(CORSConfigurationError):
            CORSConfiguration.for_staging(allow_origins=None)

    def test_staging_rejects_wildcard(self):
        """Test that staging rejects wildcard origins."""
        with pytest.raises(CORSConfigurationError):
            CORSConfiguration(
                allow_origins="*",
                environment="staging",
            )

    def test_staging_accepts_explicit_origins(self):
        """Test that staging accepts explicit origins."""
        config = CORSConfiguration(
            allow_origins="https://staging.example.com",
            environment="staging",
        )
        assert config.environment == "staging"
        assert "staging.example.com" in str(config.allow_origins)

    def test_staging_enables_credentials(self):
        """Test that staging factory enables credentials by default."""
        config = CORSConfiguration.for_staging(allow_origins="https://staging.example.com")
        assert config.allow_credentials is True

    def test_staging_factory_method(self):
        """Test factory method for staging."""
        config = CORSConfiguration.for_staging(allow_origins="https://staging.example.com")
        assert config.environment == "staging"
        assert config.allow_credentials is True

    def test_staging_factory_requires_origins(self):
        """Test that factory method requires origins."""
        with pytest.raises(CORSConfigurationError):
            CORSConfiguration.for_staging(allow_origins=None)


class TestCORSConfigurationProduction:
    """Test CORS configuration for production environment."""

    def test_production_requires_explicit_origins(self):
        """Test that production requires explicit origins."""
        with pytest.raises(CORSConfigurationError):
            CORSConfiguration(environment="production")

    def test_production_rejects_wildcard(self):
        """Test that production rejects wildcard origins."""
        with pytest.raises(CORSConfigurationError):
            CORSConfiguration(
                allow_origins="*",
                environment="production",
            )

    def test_production_accepts_explicit_origins(self):
        """Test that production accepts explicit origins."""
        config = CORSConfiguration(
            allow_origins="https://example.com",
            environment="production",
        )
        assert config.environment == "production"
        assert "example.com" in str(config.allow_origins)

    def test_production_enables_credentials(self):
        """Test that production factory enables credentials."""
        config = CORSConfiguration.for_production(allow_origins="https://example.com")
        assert config.allow_credentials is True

    def test_production_with_regex_pattern(self):
        """Test that production accepts regex patterns for subdomains."""
        config = CORSConfiguration(
            allow_origins="https://example.com",
            allow_origin_regex="^https://.*\\.example\\.com$",
            environment="production",
        )
        assert config.origin_regex is not None

    def test_production_factory_method(self):
        """Test factory method for production."""
        config = CORSConfiguration.for_production(allow_origins="https://example.com")
        assert config.environment == "production"
        assert config.allow_credentials is True

    def test_production_factory_requires_origins(self):
        """Test that factory method requires origins."""
        with pytest.raises(CORSConfigurationError):
            CORSConfiguration.for_production(allow_origins=None)

    def test_production_factory_with_regex(self):
        """Test factory method with regex pattern."""
        config = CORSConfiguration.for_production(
            allow_origins="https://example.com",
            allow_origin_regex="^https://.*\\.example\\.com$",
        )
        assert config.origin_regex is not None


class TestCORSSecurityRules:
    """Test CORS security validation rules."""

    def test_credentials_with_wildcard_rejected(self):
        """Test that credentials + wildcard is rejected."""
        with pytest.raises(CORSConfigurationError, match="Cannot enable credentials"):
            CORSConfiguration(
                allow_origins="*",
                allow_credentials=True,
                environment="development",
            )

    def test_wildcard_in_staging_rejected(self):
        """Test that wildcard is rejected in staging."""
        with pytest.raises(CORSConfigurationError):
            CORSConfiguration(
                allow_origins="*",
                environment="staging",
            )

    def test_wildcard_in_production_rejected(self):
        """Test that wildcard is rejected in production."""
        with pytest.raises(CORSConfigurationError):
            CORSConfiguration(
                allow_origins="*",
                environment="production",
            )

    def test_development_allows_credentials_without_wildcard(self):
        """Test that credentials work with explicit origins in development."""
        config = CORSConfiguration(
            allow_origins="http://localhost:3000",
            allow_credentials=True,
            environment="development",
        )
        assert config.allow_credentials is True


class TestCORSMiddlewareConfig:
    """Test CORS middleware configuration generation."""

    def test_get_middleware_config_structure(self):
        """Test that middleware config has correct structure."""
        config = CORSConfiguration(
            allow_origins="https://example.com",
            environment="production",
        )
        middleware_config = config.get_middleware_config()

        assert "allow_origins" in middleware_config
        assert "allow_credentials" in middleware_config
        assert "allow_methods" in middleware_config
        assert "allow_headers" in middleware_config
        assert "max_age" in middleware_config

    def test_middleware_config_with_regex(self):
        """Test middleware config with regex pattern."""
        config = CORSConfiguration(
            allow_origins="https://example.com",
            allow_origin_regex="^https://.*\\.example\\.com$",
            environment="production",
        )
        middleware_config = config.get_middleware_config()

        assert middleware_config["allow_origin_regex"] is not None
        assert middleware_config["allow_origin_regex"].startswith("^")

    def test_middleware_config_without_regex(self):
        """Test middleware config without regex pattern."""
        config = CORSConfiguration(
            allow_origins="https://example.com",
            environment="production",
        )
        middleware_config = config.get_middleware_config()

        assert middleware_config["allow_origin_regex"] is None


class TestCORSLogging:
    """Test CORS logging and configuration display."""

    def test_log_configuration_does_not_raise(self):
        """Test that logging configuration doesn't raise errors."""
        config = CORSConfiguration(
            allow_origins="https://example.com",
            environment="production",
        )
        # Should not raise
        config.log_configuration()

    def test_log_configuration_with_regex(self):
        """Test logging with regex pattern (should mask pattern)."""
        config = CORSConfiguration(
            allow_origins="https://example.com",
            allow_origin_regex="^https://.*\\.example\\.com$",
            environment="production",
        )
        # Should not raise
        config.log_configuration()


class TestCORSMultipleMethods:
    """Test CORS with multiple methods and headers."""

    def test_custom_methods(self):
        """Test configuration with custom methods."""
        config = CORSConfiguration(
            allow_origins="https://example.com",
            allow_methods="GET,POST,PUT",
            environment="production",
        )
        assert "GET" in config.allow_methods
        assert "POST" in config.allow_methods
        assert "PUT" in config.allow_methods

    def test_custom_headers(self):
        """Test configuration with custom headers."""
        config = CORSConfiguration(
            allow_origins="https://example.com",
            allow_headers="authorization,content-type,x-custom-header",
            environment="production",
        )
        assert "authorization" in config.allow_headers
        assert "x-custom-header" in config.allow_headers

    def test_default_methods_and_headers(self):
        """Test that default methods and headers are set."""
        config = CORSConfiguration(
            allow_origins="https://example.com",
            environment="production",
        )
        assert "GET" in config.allow_methods
        assert "POST" in config.allow_methods
        assert "OPTIONS" in config.allow_methods
        assert "authorization" in config.allow_headers
        assert "content-type" in config.allow_headers


class TestCORSMaxAge:
    """Test CORS max age settings."""

    def test_default_max_age_development(self):
        """Test default max age in development."""
        config = CORSConfiguration(environment="development")
        assert config.max_age == 600

    def test_custom_max_age(self):
        """Test custom max age."""
        config = CORSConfiguration(
            allow_origins="https://example.com",
            max_age=3600,
            environment="production",
        )
        assert config.max_age == 3600

    def test_production_factory_max_age(self):
        """Test that production factory sets longer max age."""
        config = CORSConfiguration.for_production(allow_origins="https://example.com")
        assert config.max_age == 3600

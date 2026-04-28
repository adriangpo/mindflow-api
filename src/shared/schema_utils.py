"""Shared schema utility functions used across multiple feature schemas."""

from datetime import UTC, date, datetime


def _normalize_text(value: str | None, *, field_name: str) -> str | None:
    """Normalize optional text fields and reject blank values when provided."""
    if value is None:
        return None

    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{field_name} cannot be blank")
    return normalized


def _ensure_timezone_aware(value: datetime, *, field_name: str) -> datetime:
    """Ensure datetime values carry timezone information."""
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    return value


def default_reference_date() -> date:
    """Return current UTC date for use as a default in listing and reporting."""
    return datetime.now(UTC).date()

"""JWT utilities for authentication."""

from datetime import UTC, datetime, timedelta
from typing import Any

import jwt

from src.config.settings import settings


def create_access_token(data: dict[str, Any], expires_delta: timedelta | None = None) -> str:
    """Create a JWT access token.

    Args:
        data: Payload data to encode in the token
        expires_delta: Optional expiration time delta

    Returns:
        Encoded JWT token string

    """
    to_encode = data.copy()

    if expires_delta:
        expire = datetime.now(UTC) + expires_delta
    else:
        expire = datetime.now(UTC) + timedelta(minutes=settings.access_token_expire_minutes)

    to_encode.update({"exp": expire, "iat": datetime.now(UTC), "type": "access"})

    return jwt.encode(to_encode, settings.secret_key, algorithm=settings.jwt_algorithm)


def create_refresh_token(data: dict[str, Any], expires_delta: timedelta | None = None) -> str:
    """Create a JWT refresh token (longer expiration).

    Args:
        data: Payload data to encode in the token
        expires_delta: Optional expiration time delta

    Returns:
        Encoded JWT token string

    """
    to_encode = data.copy()

    expire = datetime.now(UTC) + expires_delta if expires_delta else datetime.now(UTC) + timedelta(days=7)

    to_encode.update({"exp": expire, "iat": datetime.now(UTC), "type": "refresh"})

    return jwt.encode(to_encode, settings.secret_key, algorithm=settings.jwt_algorithm)


def decode_token(token: str) -> dict[str, Any]:
    """Decode and verify a JWT token.

    Args:
        token: JWT token string

    Returns:
        Decoded token payload

    Raises:
        InvalidTokenError: If token is invalid or expired

    """
    return jwt.decode(token, settings.secret_key, algorithms=[settings.jwt_algorithm])


def verify_token_type(payload: dict[str, Any], expected_type: str) -> bool:
    """Verify the token type matches expected.

    Args:
        payload: Decoded token payload
        expected_type: Expected token type ('access' or 'refresh')

    Returns:
        True if type matches, False otherwise

    """
    return payload.get("type") == expected_type

"""Authentication service layer."""

import logging
from datetime import UTC, datetime, timedelta

from jwt.exceptions import InvalidTokenError
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.config.settings import settings
from src.features.user.models import User, UserStatus

from .exceptions import (
    InvalidTokenException,
    InvalidTokenPayloadException,
    InvalidTokenTypeException,
    RefreshTokenExpiredException,
    RefreshTokenNotFoundException,
)
from .jwt_utils import create_access_token, create_refresh_token, decode_token, verify_token_type
from .models import RefreshToken
from .schemas import TokenResponse

logger = logging.getLogger(__name__)


class AuthService:
    """Service for JWT authentication and token management."""

    @staticmethod
    async def authenticate_user(session: AsyncSession, credential: str, password: str) -> User | None:
        """Authenticate a user with either username or email and password.

        Args:
            session: Database session
            credential: Username or email address
            password: Plain text password

        Returns:
            User object if authentication successful, None otherwise

        """
        # Query for user by username or email
        stmt = select(User).where(or_(User.username == credential, User.email == credential))
        result = await session.execute(stmt)
        user = result.scalar_one_or_none()

        if not user:
            return None

        if not user.is_active:
            logger.warning(f"Login attempt for inactive account: {credential}")
            return None

        if user.is_locked():
            logger.warning(f"Login attempt for locked account: {credential}")
            return None

        if not user.verify_password(password):
            user.failed_login_attempts += 1

            if user.failed_login_attempts >= 5:
                user.locked_until = datetime.now(UTC) + timedelta(minutes=30)
                user.status = UserStatus.LOCKED.value
                logger.warning(f"Account locked due to failed attempts: {credential}")

            return None

        user.failed_login_attempts = 0
        user.last_login_at = datetime.now(UTC)
        user.locked_until = None
        user.is_logged_in = True

        return user

    @staticmethod
    async def create_tokens(
        session: AsyncSession, user: User, ip_address: str | None = None, user_agent: str | None = None
    ) -> TokenResponse:
        """Create access and refresh tokens for a user.

        Args:
            session: Database session
            user: User object (already has tenant_id)
            ip_address: Requester's IP address (optional)
            user_agent: Requester's User-Agent header (optional)

        Returns:
            TokenResponse with access token, refresh token, and expiration time

        """
        access_token_data = {
            "sub": str(user.id),
            "username": user.username,
            "roles": user.roles,
        }
        access_token = create_access_token(access_token_data)

        refresh_token_data = {"sub": str(user.id)}
        refresh_token_str = create_refresh_token(refresh_token_data)

        # Create refresh token (user-scoped, not tenant-scoped)
        refresh_token = RefreshToken(
            user_id=user.id,
            token=refresh_token_str,
            expires_at=datetime.now(UTC) + timedelta(days=7),
            ip_address=ip_address,
            user_agent=user_agent,
        )
        session.add(refresh_token)

        expires_in = settings.access_token_expire_minutes * 60

        return TokenResponse(access_token=access_token, refresh_token=refresh_token_str, expires_in=expires_in)

    @staticmethod
    async def refresh_access_token(session: AsyncSession, refresh_token: str) -> TokenResponse:
        """Refresh an access token using a refresh token."""
        try:
            payload = decode_token(refresh_token)

            if not verify_token_type(payload, "refresh"):
                raise InvalidTokenTypeException(expected="refresh")

            user_id = payload.get("sub")
            if not user_id:
                raise InvalidTokenPayloadException()

        except InvalidTokenError as err:
            raise InvalidTokenException(detail="Invalid or expired refresh token") from err

        # Query for refresh token
        stmt = select(RefreshToken).where(RefreshToken.token == refresh_token, ~RefreshToken.revoked)
        result = await session.execute(stmt)
        stored_token = result.scalar_one_or_none()

        if not stored_token:
            raise RefreshTokenNotFoundException()

        if stored_token.expires_at < datetime.now(UTC):
            raise RefreshTokenExpiredException()

        # Get user from database using token's user_id
        user_stmt = select(User).where(User.id == stored_token.user_id)
        user_result = await session.execute(user_stmt)
        user = user_result.scalar_one_or_none()

        if not user or not user.is_active:
            raise InvalidTokenException(detail="User not found or inactive")

        return await AuthService.create_tokens(session, user)

    @staticmethod
    async def revoke_refresh_token(session: AsyncSession, refresh_token: str) -> bool:
        """Revoke a refresh token (logout)."""
        # Query for refresh token
        stmt = select(RefreshToken).where(RefreshToken.token == refresh_token)
        result = await session.execute(stmt)
        stored_token = result.scalar_one_or_none()

        if stored_token and not stored_token.revoked:
            stored_token.revoked = True
            stored_token.revoked_at = datetime.now(UTC)
            return True

        return False

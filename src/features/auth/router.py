"""Authentication router (JWT token management endpoints)."""

import logging

from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from src.database.dependencies import get_db_session
from src.features.user.models import User

from .dependencies import get_current_active_user
from .exceptions import InvalidCredentialsException
from .schemas import RefreshTokenRequest, TokenResponse, UserLoginRequest
from .service import AuthService

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/login", response_model=TokenResponse)
async def login(data: UserLoginRequest, request: Request, session: AsyncSession = Depends(get_db_session)):
    """Login and get JWT tokens.

    - **username**: Username (optional, either username or email required)
    - **email**: Email address (optional, either username or email required)
    - **password**: Password (minimum 8 characters, must include uppercase, lowercase, and digit)

    Returns access_token and refresh_token.
    """
    # Authenticate user with provided credential (username or email)
    user = await AuthService.authenticate_user(session, data.credential, data.password)

    if not user:
        raise InvalidCredentialsException()

    # Get client info for audit
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    # Create tokens
    tokens = await AuthService.create_tokens(session, user, ip_address, user_agent)
    await session.commit()

    logger.info(f"User logged in: {user.username}")
    return tokens


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(data: RefreshTokenRequest, session: AsyncSession = Depends(get_db_session)):
    """Refresh access token using refresh token.

    - **refresh_token**: Valid refresh token

    Returns new access_token and refresh_token.
    """
    tokens = await AuthService.refresh_access_token(session, data.refresh_token)
    await session.commit()
    return tokens


@router.post("/logout")
async def logout(
    data: RefreshTokenRequest,
    current_user: User = Depends(get_current_active_user),
    session: AsyncSession = Depends(get_db_session),
):
    """Logout and revoke refresh token.

    - **refresh_token**: Refresh token to revoke
    """
    revoked = await AuthService.revoke_refresh_token(session, data.refresh_token)

    if revoked:
        current_user.is_logged_in = False
        await session.commit()
        logger.info(f"User logged out: {current_user.username}")
        return {"message": "Successfully logged out"}
    else:
        return {"message": "Token already revoked or not found"}

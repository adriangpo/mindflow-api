"""Authentication router (JWT token management endpoints)."""

import logging

from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from src.database.dependencies import get_db_session
from src.features.user.models import User

from .dependencies import get_current_active_user
from .exceptions import InvalidCredentialsException
from .openapi import (
    LOGIN_REQUEST_DESCRIPTION,
    LOGIN_RESPONSES,
    LOGOUT_REQUEST_DESCRIPTION,
    LOGOUT_RESPONSES,
    REFRESH_REQUEST_DESCRIPTION,
    REFRESH_RESPONSES,
    AuthMessageResponse,
)
from .schemas import RefreshTokenRequest, TokenResponse, UserLoginRequest
from .service import AuthService

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Authenticate user and issue tokens",
    description=LOGIN_REQUEST_DESCRIPTION,
    responses=LOGIN_RESPONSES,
)
async def login(data: UserLoginRequest, request: Request, session: AsyncSession = Depends(get_db_session)):
    """Authenticate a user and issue a new access/refresh token pair."""
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

    logger.info("User logged in: %s", user.username)
    return tokens


@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Rotate tokens using a refresh token",
    description=REFRESH_REQUEST_DESCRIPTION,
    responses=REFRESH_RESPONSES,
)
async def refresh_token(data: RefreshTokenRequest, session: AsyncSession = Depends(get_db_session)):
    """Exchange a refresh token for a fresh access/refresh token pair."""
    tokens = await AuthService.refresh_access_token(session, data.refresh_token)
    await session.commit()
    return tokens


@router.post(
    "/logout",
    response_model=AuthMessageResponse,
    summary="Revoke one refresh token",
    description=LOGOUT_REQUEST_DESCRIPTION,
    responses=LOGOUT_RESPONSES,
)
async def logout(
    data: RefreshTokenRequest,
    current_user: User = Depends(get_current_active_user),
    session: AsyncSession = Depends(get_db_session),
):
    """Revoke a specific refresh token for the authenticated user."""
    revoked = await AuthService.revoke_refresh_token(session, data.refresh_token)

    if revoked:
        current_user.is_logged_in = False
        await session.commit()
        logger.info("User logged out: %s", current_user.username)
        return {"message": "Successfully logged out"}
    return {"message": "Token already revoked or not found"}

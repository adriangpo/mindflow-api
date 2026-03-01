"""Authentication dependencies for FastAPI."""

from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt.exceptions import InvalidTokenError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.database.dependencies import get_db_session
from src.features.user.models import User, UserRole

from .exceptions import (
    InsufficientPermissionException,
    InsufficientRoleException,
    InvalidTokenException,
    UserInactiveException,
    UserLockedException,
)
from .jwt_utils import decode_token, verify_token_type

security = HTTPBearer()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    session: AsyncSession = Depends(get_db_session),
) -> User:
    """Get the current authenticated user from JWT token.

    Args:
        credentials: HTTP authorization credentials with bearer token
        session: Database session

    Returns:
        User object

    Raises:
        InvalidTokenException: If token is invalid or user not found

    """
    try:
        token = credentials.credentials
        payload = decode_token(token)

        # Verify it's an access token
        if not verify_token_type(payload, "access"):
            raise InvalidTokenException(detail="Invalid token type")

        user_id_raw = payload.get("sub")
        if user_id_raw is None:
            raise InvalidTokenException(detail="Invalid token payload")
        user_id: str = str(user_id_raw)

    except InvalidTokenError as err:
        raise InvalidTokenException() from err

    # Fetch user from database
    stmt = select(User).where(User.id == int(user_id))
    result = await session.execute(stmt)
    user = result.scalar_one_or_none()

    if user is None:
        raise InvalidTokenException(detail="User not found")

    # Check if user is active (computed property checks if status == ACTIVE)
    if not user.is_active:
        raise UserInactiveException()

    # Check if account is locked
    if user.is_locked():
        raise UserLockedException()

    return user


async def get_current_active_user(current_user: User = Depends(get_current_user)) -> User:
    """Get current active user (convenience wrapper).

    Args:
        current_user: Current user from get_current_user

    Returns:
        Active user

    """
    return current_user


def require_role(*required_roles: UserRole):
    """Dependency factory to require specific roles.

    Usage:
        # For single role
        Depends(require_role(UserRole.ADMIN))

        # For multiple roles (OR logic - user needs ANY of these)
        Depends(require_role(UserRole.ADMIN, UserRole.TENANT_OWNER))
    """

    async def role_checker(current_user: User = Depends(get_current_user)) -> User:
        if not any(role.value in current_user.roles for role in required_roles):
            raise InsufficientRoleException([r.value for r in required_roles])
        return current_user

    return role_checker


def require_permission(*required_permissions: str):
    """Dependency factory to require specific permissions.

    Usage:
        Depends(require_permission("read:assets", "write:assets"))
    """

    async def permission_checker(current_user: User = Depends(get_current_user)) -> User:
        # Admins have all permissions
        if UserRole.ADMIN.value in current_user.roles:
            return current_user

        if not any(perm in current_user.permissions for perm in required_permissions):
            raise InsufficientPermissionException(list(required_permissions))
        return current_user

    return permission_checker


async def get_optional_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(HTTPBearer(auto_error=False)),
) -> User | None:
    """Get current user if token is provided, otherwise return None.
    Useful for endpoints that work with or without authentication.

    Args:
        credentials: Optional HTTP authorization credentials

    Returns:
        User object if authenticated, None otherwise

    """
    if credentials is None:
        return None

    try:
        return await get_current_user(credentials)
    except InvalidTokenException, UserInactiveException, UserLockedException:
        return None

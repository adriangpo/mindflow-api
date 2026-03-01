"""User management router (API endpoints)."""

import logging

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from src.database.dependencies import get_db_session
from src.features.auth.dependencies import get_current_active_user, require_role
from src.shared.pagination.pagination import PaginationParams

from .exceptions import (
    CannotDeleteOwnAccount,
    UserNotFound,
)
from .models import User, UserRole
from .schemas import (
    AssignPermissionsRequest,
    AssignRolesRequest,
    PasswordChangeRequest,
    UserListResponse,
    UserRegisterRequest,
    UserResponse,
    UserUpdateRequest,
)
from .service import UserService

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/users", tags=["User Management"])


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(current_user: User = Depends(get_current_active_user)):
    """Get current user information."""
    return UserResponse.model_validate(current_user)


@router.put("/me", response_model=UserResponse)
async def update_current_user(
    data: UserUpdateRequest,
    current_user: User = Depends(get_current_active_user),
    session: AsyncSession = Depends(get_db_session),
):
    """Update current user's own profile (full_name, email only)."""
    user = await UserService.update_user(
        session,
        current_user,
        full_name=data.full_name,
        email=data.email,
    )
    await session.commit()
    return UserResponse.model_validate(user)


@router.post("/me/change-password")
async def change_password(
    data: PasswordChangeRequest,
    current_user: User = Depends(get_current_active_user),
    session: AsyncSession = Depends(get_db_session),
):
    """Change current user's password."""
    await UserService.change_password(current_user, data.current_password, data.new_password)
    await session.commit()
    return {"message": "Password changed successfully"}


# Admin endpoints
@router.post("", response_model=UserResponse, dependencies=[Depends(require_role(UserRole.ADMIN))])
async def register_user_admin(
    data: UserRegisterRequest,
    current_user: User = Depends(get_current_active_user),
    session: AsyncSession = Depends(get_db_session),
):
    """Register a new user (admin only).

    Creates a new user account with TENANT_OWNER role by default.
    Admin can use the `/users/{id}/roles` endpoint to assign ASSISTANT role or change roles as needed.
    """
    user = await UserService.register_user(session, data)
    await session.commit()
    logger.info(f"New user registered by admin {current_user.username}: {user.username}")
    return UserResponse.model_validate(user)


@router.get("", response_model=UserListResponse, dependencies=[Depends(require_role(UserRole.ADMIN))])
async def list_users(
    pagination: PaginationParams = Depends(),
    session: AsyncSession = Depends(get_db_session),
):
    """List all users (admin only).

    Pagination is enabled by default:
    - `page`: Page number (1-indexed, default: 1)
    - `page_size`: Items per page (default: 50, max: 1000)

    To disable pagination and get all users, set both page and page_size to None.
    """
    users, total = await UserService.get_users(session, pagination)
    return UserListResponse(
        users=[UserResponse.model_validate(u) for u in users],
        total=total,
        page=pagination.page or 1,
        page_size=pagination.page_size or 50,
    )


@router.get("/{user_id}", response_model=UserResponse, dependencies=[Depends(require_role(UserRole.ADMIN))])
async def get_user(user_id: int, session: AsyncSession = Depends(get_db_session)):
    """Get user by ID (admin only)."""
    user = await UserService.get_user(session, user_id)

    if not user:
        raise UserNotFound()

    return UserResponse.model_validate(user)


@router.put("/{user_id}", response_model=UserResponse, dependencies=[Depends(require_role(UserRole.ADMIN))])
async def update_user(
    user_id: int,
    data: UserUpdateRequest,
    current_user: User = Depends(get_current_active_user),
    session: AsyncSession = Depends(get_db_session),
):
    """Update user (admin only).

    Admin can update: full_name, email
    NOT allowed: status (use role assignment endpoints instead)
    """
    user = await UserService.get_user(session, user_id)

    if not user:
        raise UserNotFound()

    user = await UserService.update_user(
        session,
        user,
        full_name=data.full_name,
        email=data.email,
    )
    await session.commit()

    logger.info(f"User updated by admin {current_user.username}: {user.username}")
    return UserResponse.model_validate(user)


@router.post("/{user_id}/roles", response_model=UserResponse, dependencies=[Depends(require_role(UserRole.ADMIN))])
async def assign_roles(
    user_id: int,
    data: AssignRolesRequest,
    current_user: User = Depends(get_current_active_user),
    session: AsyncSession = Depends(get_db_session),
):
    """Assign roles to a user (admin only)."""
    user = await UserService.get_user(session, user_id)

    if not user:
        raise UserNotFound()

    user = await UserService.assign_roles(user, data.roles)
    await session.commit()
    logger.info(f"Roles assigned to {user.username} by admin {current_user.username}: {[r.value for r in data.roles]}")
    return UserResponse.model_validate(user)


@router.post(
    "/{user_id}/permissions", response_model=UserResponse, dependencies=[Depends(require_role(UserRole.ADMIN))]
)
async def assign_permissions(
    user_id: int,
    data: AssignPermissionsRequest,
    current_user: User = Depends(get_current_active_user),
    session: AsyncSession = Depends(get_db_session),
):
    """Assign permissions to a user (admin only)."""
    user = await UserService.get_user(session, user_id)

    if not user:
        raise UserNotFound()

    user = await UserService.assign_permissions(user, data.permissions)
    await session.commit()
    logger.info(f"Permissions assigned to {user.username} by admin {current_user.username}: {data.permissions}")
    return UserResponse.model_validate(user)


@router.delete("/{user_id}", dependencies=[Depends(require_role(UserRole.ADMIN))])
async def delete_user(
    user_id: int,
    current_user: User = Depends(get_current_active_user),
    session: AsyncSession = Depends(get_db_session),
):
    """Delete user (admin only)."""
    if current_user.id == user_id:
        raise CannotDeleteOwnAccount()

    success = await UserService.delete_user(session, user_id)
    await session.commit()

    if not success:
        raise UserNotFound()

    logger.info(f"User deleted by admin {current_user.username}: {user_id}")
    return {"message": "User deleted successfully"}

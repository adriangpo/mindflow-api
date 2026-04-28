"""User management router (API endpoints)."""

import logging

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from src.database.dependencies import get_db_session
from src.features.auth.dependencies import get_current_active_user, require_role
from src.shared.pagination.pagination import PaginationParams

from .exceptions import (
    CannotDeactivateOwnAccount,
    UserNotFound,
)
from .models import User, UserRole
from .openapi import (
    ASSIGN_PERMISSIONS_EXAMPLE,
    ASSIGN_ROLES_EXAMPLE,
    ASSIGN_TENANTS_EXAMPLE,
    COMMON_ADMIN_RESPONSES,
    COMMON_AUTH_RESPONSES,
    CURRENT_USER_EXAMPLE,
    UPDATED_USER_EXAMPLE,
    USER_LIST_EXAMPLE,
    USER_REGISTER_EXAMPLE,
    UserActionMessageResponse,
    json_response,
)
from .schemas import (
    AssignPermissionsRequest,
    AssignRolesRequest,
    AssignTenantsRequest,
    PasswordChangeRequest,
    UserListResponse,
    UserRegisterRequest,
    UserResponse,
    UserUpdateRequest,
)
from .service import UserService

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/users", tags=["User Management"])


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get the current user profile",
    description=(
        "Return the authenticated user's profile resolved from the bearer token. "
        "The dependency chain rejects missing tokens, inactive accounts, and locked accounts before the handler runs."
    ),
    response_description="Current authenticated user profile.",
    responses={
        **COMMON_AUTH_RESPONSES,
        200: json_response("Current authenticated user profile.", CURRENT_USER_EXAMPLE),
    },
)
async def get_current_user_info(current_user: User = Depends(get_current_active_user)):
    """Return the authenticated user's own profile."""
    return UserResponse.model_validate(current_user)


@router.put(
    "/me",
    response_model=UserResponse,
    summary="Update the current user profile",
    description=(
        "Update only the authenticated user's `full_name` and `email`. "
        "Fields set to `null` are ignored, and duplicate emails are rejected with a 400 response."
    ),
    response_description="Updated current user profile.",
    responses={
        **COMMON_AUTH_RESPONSES,
        400: {"description": "Email already registered."},
        200: json_response("Updated current user profile.", UPDATED_USER_EXAMPLE),
    },
)
async def update_current_user(
    data: UserUpdateRequest,
    current_user: User = Depends(get_current_active_user),
    session: AsyncSession = Depends(get_db_session),
):
    """Update the current user's `full_name` and `email` fields only."""
    user = await UserService.update_user(
        session,
        current_user,
        full_name=data.full_name,
        email=data.email,
    )
    await session.commit()
    return UserResponse.model_validate(user)


@router.post(
    "/me/change-password",
    response_model=UserActionMessageResponse,
    summary="Change the current user password",
    description=(
        "Verify the current password before replacing it with a new Argon2 hash. "
        "The new password must satisfy the shared strength policy, and reusing the same password is allowed "
        "as long as validation passes."
    ),
    response_description="Password change confirmation.",
    responses={
        **COMMON_AUTH_RESPONSES,
        400: {"description": "Current password is incorrect."},
        200: json_response("Password change confirmation.", {"message": "Password changed successfully"}),
    },
)
async def change_password(
    data: PasswordChangeRequest,
    current_user: User = Depends(get_current_active_user),
    session: AsyncSession = Depends(get_db_session),
):
    """Change the current user's password after validating the current credential."""
    await UserService.change_password(current_user, data.current_password, data.new_password)
    await session.commit()
    return {"message": "Password changed successfully"}


# Admin endpoints
@router.post(
    "",
    response_model=UserResponse,
    dependencies=[Depends(require_role(UserRole.ADMIN))],
    summary="Create a user as an administrator",
    description=(
        "Create a new global user record. New users are always created with the `tenant_owner` role, `active` status, "
        "`is_logged_in = false`, no permissions, and no tenant assignments."
    ),
    response_description="Created user profile.",
    responses={
        **COMMON_ADMIN_RESPONSES,
        400: {"description": "Username already registered or email already registered."},
        200: json_response("Created user profile.", USER_REGISTER_EXAMPLE),
    },
)
async def register_user_admin(
    data: UserRegisterRequest,
    current_user: User = Depends(get_current_active_user),
    session: AsyncSession = Depends(get_db_session),
):
    """Create a new user account with the default tenant-owner role."""
    user = await UserService.register_user(session, data)
    await session.commit()
    logger.info("New user registered by admin %s: %s", current_user.username, user.username)
    return UserResponse.model_validate(user)


@router.get(
    "",
    response_model=UserListResponse,
    dependencies=[Depends(require_role(UserRole.ADMIN))],
    summary="List users",
    description=(
        "Return all users with optional pagination. "
        "When both `page` and `page_size` are disabled, the handler returns the full list while the response still "
        "normalizes the paging fields to `1` and `50`."
    ),
    response_description="User list with total count and paging metadata.",
    responses={
        **COMMON_ADMIN_RESPONSES,
        200: json_response("User list with total count and paging metadata.", USER_LIST_EXAMPLE),
    },
)
async def list_users(
    pagination: PaginationParams = Depends(),
    session: AsyncSession = Depends(get_db_session),
):
    """Return the user list with optional pagination."""
    users, total = await UserService.get_users(session, pagination)
    return UserListResponse(
        users=[UserResponse.model_validate(u) for u in users],
        total=total,
        page=pagination.page or 1,
        page_size=pagination.page_size or 50,
    )


@router.get(
    "/{user_id}",
    response_model=UserResponse,
    dependencies=[Depends(require_role(UserRole.ADMIN))],
    summary="Get a user by ID",
    description="Return one user by numeric ID. Missing users produce a 404 response.",
    response_description="User profile.",
    responses={
        **COMMON_ADMIN_RESPONSES,
        404: {"description": "User not found."},
        200: json_response("User profile.", CURRENT_USER_EXAMPLE),
    },
)
async def get_user(user_id: int, session: AsyncSession = Depends(get_db_session)):
    """Return one user by ID."""
    user = await UserService.get_user(session, user_id)

    if not user:
        raise UserNotFound()

    return UserResponse.model_validate(user)


@router.put(
    "/{user_id}",
    response_model=UserResponse,
    dependencies=[Depends(require_role(UserRole.ADMIN))],
    summary="Update a user by ID",
    description=(
        "Update only `full_name` and `email` on the target user. "
        "Null values are ignored, duplicate emails are rejected, and other fields remain unchanged."
    ),
    response_description="Updated user profile.",
    responses={
        **COMMON_ADMIN_RESPONSES,
        400: {"description": "Email already registered."},
        404: {"description": "User not found."},
        200: json_response("Updated user profile.", UPDATED_USER_EXAMPLE),
    },
)
async def update_user(
    user_id: int,
    data: UserUpdateRequest,
    current_user: User = Depends(get_current_active_user),
    session: AsyncSession = Depends(get_db_session),
):
    """Update the target user's profile fields."""
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

    logger.info("User updated by admin %s: %s", current_user.username, user.username)
    return UserResponse.model_validate(user)


@router.post(
    "/{user_id}/roles",
    response_model=UserResponse,
    dependencies=[Depends(require_role(UserRole.ADMIN))],
    summary="Replace a user's roles",
    description=(
        "Replace the entire `roles` array for a user. "
        "This is not a merge operation: the provided list becomes the full set of roles."
    ),
    response_description="User profile with updated roles.",
    responses={
        **COMMON_ADMIN_RESPONSES,
        404: {"description": "User not found."},
        200: json_response(
            "User profile with updated roles.", {**CURRENT_USER_EXAMPLE, "roles": ASSIGN_ROLES_EXAMPLE["roles"]}
        ),
    },
)
async def assign_roles(
    user_id: int,
    data: AssignRolesRequest,
    current_user: User = Depends(get_current_active_user),
    session: AsyncSession = Depends(get_db_session),
):
    """Replace the target user's roles."""
    user = await UserService.get_user(session, user_id)

    if not user:
        raise UserNotFound()

    user = await UserService.assign_roles(user, data.roles)
    await session.commit()
    logger.info(
        "Roles assigned to %s by admin %s: %s",
        user.username,
        current_user.username,
        [r.value for r in data.roles],
    )
    return UserResponse.model_validate(user)


@router.post(
    "/{user_id}/permissions",
    response_model=UserResponse,
    dependencies=[Depends(require_role(UserRole.ADMIN))],
    summary="Replace a user's permissions",
    description=(
        "Replace the entire `permissions` array for a user. "
        "The endpoint requires at least one permission and does not merge with existing values."
    ),
    response_description="User profile with updated permissions.",
    responses={
        **COMMON_ADMIN_RESPONSES,
        404: {"description": "User not found."},
        200: json_response(
            "User profile with updated permissions.",
            {**CURRENT_USER_EXAMPLE, "permissions": ASSIGN_PERMISSIONS_EXAMPLE["permissions"]},
        ),
    },
)
async def assign_permissions(
    user_id: int,
    data: AssignPermissionsRequest,
    current_user: User = Depends(get_current_active_user),
    session: AsyncSession = Depends(get_db_session),
):
    """Replace the target user's permissions."""
    user = await UserService.get_user(session, user_id)

    if not user:
        raise UserNotFound()

    user = await UserService.assign_permissions(user, data.permissions)
    await session.commit()
    logger.info(
        "Permissions assigned to %s by admin %s: %s",
        user.username,
        current_user.username,
        data.permissions,
    )
    return UserResponse.model_validate(user)


@router.post(
    "/{user_id}/tenants",
    response_model=UserResponse,
    dependencies=[Depends(require_role(UserRole.ADMIN))],
    summary="Replace a user's tenant assignments",
    description=(
        "Replace the entire `tenant_ids` array for a user. "
        "An empty list is allowed and clears all tenant access for the user."
    ),
    response_description="User profile with updated tenant assignments.",
    responses={
        **COMMON_ADMIN_RESPONSES,
        404: {"description": "User not found."},
        200: json_response(
            "User profile with updated tenant assignments.",
            {**CURRENT_USER_EXAMPLE, "tenant_ids": ASSIGN_TENANTS_EXAMPLE["tenant_ids"]},
        ),
    },
)
async def assign_tenants(
    user_id: int,
    data: AssignTenantsRequest,
    current_user: User = Depends(get_current_active_user),
    session: AsyncSession = Depends(get_db_session),
):
    """Replace the target user's tenant assignments."""
    user = await UserService.get_user(session, user_id)

    if not user:
        raise UserNotFound()

    user = await UserService.assign_tenants(user, data.tenant_ids)
    await session.commit()
    logger.info(
        "Tenant access assigned to %s by admin %s: %s",
        user.username,
        current_user.username,
        data.tenant_ids,
    )
    return UserResponse.model_validate(user)


@router.delete(
    "/{user_id}",
    response_model=UserActionMessageResponse,
    dependencies=[Depends(require_role(UserRole.ADMIN))],
    summary="Deactivate a user",
    description=(
        "Deactivate a user account without deleting the row. "
        "The authenticated admin cannot deactivate their own account. "
        "When the user exists, the operation is idempotent from the API perspective "
        "and revokes all active refresh tokens."
    ),
    response_description="Deactivation confirmation.",
    responses={
        **COMMON_ADMIN_RESPONSES,
        400: {"description": "Cannot deactivate your own account."},
        404: {"description": "User not found."},
        200: json_response("Deactivation confirmation.", {"message": "User deactivated successfully"}),
    },
)
async def deactivate_user(
    user_id: int,
    current_user: User = Depends(get_current_active_user),
    session: AsyncSession = Depends(get_db_session),
):
    """Deactivate the target user account and revoke active refresh tokens."""
    if current_user.id == user_id:
        raise CannotDeactivateOwnAccount()

    success = await UserService.deactivate_user(session, user_id)
    await session.commit()

    if not success:
        raise UserNotFound()

    logger.info("User deactivated by admin %s: %s", current_user.username, user_id)
    return {"message": "User deactivated successfully"}


@router.post(
    "/{user_id}/reactivate",
    response_model=UserActionMessageResponse,
    dependencies=[Depends(require_role(UserRole.ADMIN))],
    summary="Reactivate a user",
    description=(
        "Reactivate a previously deactivated user account by restoring the `active` status. "
        "The operation is idempotent — calling it on an already-active user has no effect. "
        "The user must log in again to obtain new tokens."
    ),
    response_description="Reactivation confirmation.",
    responses={
        **COMMON_ADMIN_RESPONSES,
        404: {"description": "User not found."},
        200: json_response("Reactivation confirmation.", {"message": "User reactivated successfully"}),
    },
)
async def reactivate_user(
    user_id: int,
    current_user: User = Depends(get_current_active_user),
    session: AsyncSession = Depends(get_db_session),
):
    """Reactivate the target user account."""
    success = await UserService.reactivate_user(session, user_id)
    await session.commit()

    if not success:
        raise UserNotFound()

    logger.info("User reactivated by admin %s: %s", current_user.username, user_id)
    return {"message": "User reactivated successfully"}

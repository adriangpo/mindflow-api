"""User service layer."""

import logging
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.features.auth.service import AuthService
from src.shared.pagination.pagination import PaginationParams

from .exceptions import (
    EmailAlreadyExists,
    IncorrectPassword,
    UsernameAlreadyExists,
)
from .models import User, UserRole, UserStatus
from .schemas import UserRegisterRequest

logger = logging.getLogger(__name__)


class UserService:
    """Service for user operations."""

    @staticmethod
    async def register_user(session: AsyncSession, data: UserRegisterRequest) -> User:
        """Register a new user.

        All new users start with TENANT_OWNER role by default.
        Admins can assign ASSISTANT role via assign_roles endpoint.

        Args:
            session: Database session
            data: User registration data

        Returns:
            Created User object

        Raises:
            UsernameAlreadyExists: If username already exists
            EmailAlreadyExists: If email already exists

        """
        # Check if username exists
        stmt = select(User).where(User.username == data.username)
        result = await session.execute(stmt)
        existing_user = result.scalar_one_or_none()
        if existing_user:
            raise UsernameAlreadyExists()

        # Check if email exists
        stmt = select(User).where(User.email == data.email)
        result = await session.execute(stmt)
        existing_email = result.scalar_one_or_none()
        if existing_email:
            raise EmailAlreadyExists()

        # Hash password (salt handled automatically by pwdlib using Argon2)
        hashed_password = User.hash_password(data.password)

        # Create user with default TENANT_OWNER role, is_logged_in=False, and empty permissions
        user = User(
            email=data.email,
            username=data.username,
            full_name=data.full_name,
            hashed_password=hashed_password,
            roles=[UserRole.TENANT_OWNER.value],  # Default role - user is autonomous professional
            status=UserStatus.ACTIVE.value,  # Default status
            is_logged_in=False,  # Users start as not logged in
            permissions=[],  # Users start with no permissions
            tenant_ids=[],  # Users start without tenant assignments
        )

        session.add(user)
        logger.info("New user registered: %s (%s)", user.username, user.email)

        return user

    @staticmethod
    async def assign_roles(user: User, roles: list[UserRole]) -> User:
        """Assign roles to a user.

        Args:
            user: User to update
            roles: List of roles to assign

        Returns:
            Updated User object

        """
        user.roles = [role.value for role in roles]
        user.updated_at = datetime.now(UTC)
        logger.info("Roles assigned to user %s: %s", user.username, list(roles))
        return user

    @staticmethod
    async def assign_permissions(user: User, permissions: list[str]) -> User:
        """Assign permissions to a user.

        Args:
            user: User to update
            permissions: List of permissions to assign

        Returns:
            Updated User object

        """
        user.permissions = permissions
        user.updated_at = datetime.now(UTC)
        logger.info("Permissions assigned to user %s: %s", user.username, permissions)
        return user

    @staticmethod
    async def assign_tenants(user: User, tenant_ids: list[UUID]) -> User:
        """Assign tenant access to a user."""
        user.tenant_ids = tenant_ids
        user.updated_at = datetime.now(UTC)
        logger.info("Tenant access assigned to user %s: %s", user.username, tenant_ids)
        return user

    @staticmethod
    async def get_user(session: AsyncSession, user_id: int) -> User | None:
        """Get user by ID."""
        stmt = select(User).where(User.id == user_id)
        result = await session.execute(stmt)
        return result.scalar_one_or_none()

    @staticmethod
    async def get_users(session: AsyncSession, pagination: PaginationParams) -> tuple[list[User], int]:
        """Get paginated users list.

        Args:
            session: Database session
            pagination: PaginationParams with page and page_size

        Returns:
            Tuple of (users, total_count)

        """
        # Get total count
        count_stmt = select(func.count()).select_from(User)
        total_result = await session.execute(count_stmt)
        total = total_result.scalar_one()

        # Get paginated items
        stmt = select(User)
        if pagination.is_paginated:
            stmt = stmt.offset(pagination.skip).limit(pagination.limit)

        result = await session.execute(stmt)
        users = list(result.scalars().all())

        return users, total

    @staticmethod
    async def update_user(session: AsyncSession, user: User, **kwargs) -> User:
        """Update user fields (full_name, email only).

        Args:
            session: Database session
            user: User to update
            **kwargs: Fields to update

        Returns:
            Updated User object

        Raises:
            EmailAlreadyExists: If email is being changed to an existing email

        """
        # Check for email duplicate if email is being updated
        if "email" in kwargs and kwargs["email"] is not None:
            new_email = kwargs["email"]
            if new_email != user.email:  # Only check if email is actually changing
                stmt = select(User).where(User.email == new_email)
                result = await session.execute(stmt)
                existing_email = result.scalar_one_or_none()
                if existing_email:
                    raise EmailAlreadyExists()

        for key, value in kwargs.items():
            if value is not None and hasattr(user, key) and key in ("full_name", "email"):
                setattr(user, key, value)

        user.updated_at = datetime.now(UTC)
        logger.info("User updated: %s", user.username)
        return user

    @staticmethod
    async def change_password(user: User, current_password: str, new_password: str) -> bool:
        """Change user password.

        Args:
            user: User object
            current_password: Current password
            new_password: New password

        Returns:
            True if changed successfully

        Raises:
            IncorrectPassword: If current password is incorrect

        """
        # Verify current password
        if not user.verify_password(current_password):
            raise IncorrectPassword()

        # Update password (salt handled automatically by Argon2)
        user.hashed_password = User.hash_password(new_password)
        user.updated_at = datetime.now(UTC)

        logger.info("Password changed for user: %s", user.username)
        return True

    @staticmethod
    async def deactivate_user(session: AsyncSession, user_id: int) -> bool:
        """Deactivate user by ID."""
        stmt = select(User).where(User.id == user_id)
        result = await session.execute(stmt)
        user = result.scalar_one_or_none()

        if not user:
            return False

        revoked_tokens = await AuthService.revoke_all_user_tokens(session, user.id)

        user.status = UserStatus.INACTIVE.value
        user.is_logged_in = False
        user.updated_at = datetime.now(UTC)

        logger.info("User deactivated: %s (revoked_refresh_tokens=%s)", user.username, revoked_tokens)
        return True

    @staticmethod
    async def reactivate_user(session: AsyncSession, user_id: int) -> bool:
        """Reactivate a previously deactivated user by ID."""
        stmt = select(User).where(User.id == user_id)
        result = await session.execute(stmt)
        user = result.scalar_one_or_none()

        if not user:
            return False

        user.status = UserStatus.ACTIVE.value
        user.updated_at = datetime.now(UTC)

        logger.info("User reactivated: %s", user.username)
        return True

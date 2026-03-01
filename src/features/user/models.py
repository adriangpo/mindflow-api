"""User domain models."""

from datetime import UTC, datetime
from enum import StrEnum

from pwdlib import PasswordHash
from sqlalchemy import Boolean, DateTime, Enum, Integer, String
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import Mapped, mapped_column

from src.database.base import Base, TimestampMixin


class UserRole(StrEnum):
    """User roles for RBAC.

    ADMIN: Platform-level administrator (cross-tenant).
           Can manage accounts, plans, and support operations.
           Does NOT participate in clinical operations.

    TENANT_OWNER: The autonomous professional (doctor/psychologist).
                  Owner of the tenant.
                  Full access to: patients, medical records, agenda, scheduling,
                  financial management, notifications, and assistants.
                  ONLY role allowed to access medical records.

    ASSISTANT: Secretary role.
               Can: schedule appointments, update status, manage financial entries,
                    send notifications.
               Cannot: access medical records, export records, modify configuration,
                      delete patients.
    """

    ADMIN = "admin"
    TENANT_OWNER = "tenant_owner"
    ASSISTANT = "assistant"


class UserStatus(StrEnum):
    """User account status."""

    ACTIVE = "active"
    INACTIVE = "inactive"
    LOCKED = "locked"


pwd_hasher = PasswordHash.recommended()


class User(Base, TimestampMixin):
    """User model for authentication and authorization.

    Globally-scoped model: users are independent of tenants.
    Users can have access to multiple tenants via tenant-user assignments.
    """

    __tablename__ = "users"

    # Primary key
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # Identity (globally unique)
    email: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    username: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)
    full_name: Mapped[str] = mapped_column(String(255), nullable=False)

    # Authentication
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)

    # Authorization
    roles: Mapped[list[str]] = mapped_column(
        ARRAY(String),
        nullable=False,
        default=[UserRole.TENANT_OWNER.value],
        server_default=f"{{{UserRole.TENANT_OWNER.value}}}",
    )
    permissions: Mapped[list[str]] = mapped_column(
        ARRAY(String),
        nullable=False,
        default=[],
        server_default="{}",
    )

    # Status
    status: Mapped[str] = mapped_column(
        Enum(UserStatus, native_enum=False, length=50),
        nullable=False,
        default=UserStatus.ACTIVE.value,
        server_default=UserStatus.ACTIVE.value,
        index=True,
    )
    is_logged_in: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="false")

    # Audit
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    failed_login_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    @property
    def is_active(self) -> bool:
        """Computed property: user is active if status is ACTIVE."""
        return self.status == UserStatus.ACTIVE.value

    def verify_password(self, plain_password: str) -> bool:
        """Verify a password against the hash using Argon2.

        Salt is automatically extracted from the hash by pwdlib.
        """
        return pwd_hasher.verify(plain_password, self.hashed_password)

    @staticmethod
    def hash_password(password: str) -> str:
        """Hash a password using Argon2.

        Salt is automatically generated and embedded in the returned hash.
        """
        return pwd_hasher.hash(password)

    def has_role(self, role: UserRole) -> bool:
        """Check if user has a specific role."""
        return role.value in self.roles

    def has_permission(self, permission: str) -> bool:
        """Check if user has a specific permission or is an admin."""
        # Admin role grants all permissions
        if self.roles and UserRole.ADMIN.value in self.roles:
            return True
        # Check if user has the specific permission
        return self.permissions is not None and permission in self.permissions

    def is_locked(self) -> bool:
        """Check if account is locked."""
        locked_until = self.locked_until
        if locked_until:
            if locked_until > datetime.now(UTC):
                return True
        return False

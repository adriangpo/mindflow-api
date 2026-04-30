"""User schemas (DTOs)."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field, field_validator

from src.shared.validators.password import validate_password_strength

from .models import UserRole, UserStatus


# Request schemas
class UserRegisterRequest(BaseModel):
    """User registration request."""

    email: EmailStr
    username: str = Field(..., min_length=3, max_length=50)
    full_name: str = Field(..., min_length=1, max_length=200)
    password: str = Field(..., min_length=8, description="Password must be at least 8 characters")
    confirm_password: str = Field(..., min_length=8)

    @field_validator("password")
    @classmethod
    def _password_strength(cls, value: str) -> str:
        return validate_password_strength(value)

    @field_validator("confirm_password")
    @classmethod
    def _passwords_match(cls, value: str, info) -> str:
        if "password" in info.data and value != info.data["password"]:
            raise ValueError("Passwords do not match")
        return value


class UserUpdateRequest(BaseModel):
    """User update request."""

    full_name: str | None = Field(None, min_length=1, max_length=200)
    email: EmailStr | None = None


class PasswordChangeRequest(BaseModel):
    """Password change request."""

    current_password: str = Field(..., min_length=8)
    new_password: str = Field(..., min_length=8, description="Password must be at least 8 characters")
    confirm_new_password: str = Field(..., min_length=8)

    @field_validator("new_password")
    @classmethod
    def _password_strength(cls, value: str) -> str:
        return validate_password_strength(value)

    @field_validator("confirm_new_password")
    @classmethod
    def _passwords_match(cls, value: str, info) -> str:
        if "new_password" in info.data and value != info.data["new_password"]:
            raise ValueError("New passwords do not match")
        return value


class AssignRolesRequest(BaseModel):
    """Assign roles to a user (admin only).

    Valid roles:
    - ADMIN: Platform-level administrator (manages accounts, plans, support)
    - TENANT_OWNER: Autonomous professional (doctor/psychologist) with full access to tenant
    - ASSISTANT: Secretary with access to scheduling, financial, and notifications only
    """

    roles: list[UserRole] = Field(..., min_length=1)


class AssignPermissionsRequest(BaseModel):
    """Assign permissions to a user (admin only)."""

    permissions: list[str] = Field(..., min_length=1)


class AssignTenantsRequest(BaseModel):
    """Assign tenant access to a user (admin only)."""

    tenant_ids: list[UUID]


# Response schemas
class UserResponse(BaseModel):
    """User response."""

    id: int
    email: EmailStr
    username: str
    full_name: str
    roles: list[UserRole]
    permissions: list[str]
    tenant_ids: list[UUID]
    status: UserStatus
    created_at: datetime
    last_login_at: datetime | None = None

    model_config = {"from_attributes": True}


class UserListResponse(BaseModel):
    """User list response."""

    users: list[UserResponse]
    total: int
    page: int
    page_size: int

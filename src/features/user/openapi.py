"""OpenAPI helpers for the user feature."""

from typing import Any

from pydantic import BaseModel, ConfigDict

from .models import UserRole, UserStatus

OpenAPIResponse = dict[str, Any]
OpenAPIResponses = dict[int | str, OpenAPIResponse]


class UserActionMessageResponse(BaseModel):
    """Generic message payload used by user-mutating endpoints."""

    message: str

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {"message": "Password changed successfully"},
                {"message": "User deactivated successfully"},
            ]
        }
    )


CURRENT_USER_EXAMPLE: dict[str, Any] = {
    "id": 12,
    "email": "doctor@example.com",
    "username": "doctor",
    "full_name": "Dr. Ana Silva",
    "roles": [UserRole.TENANT_OWNER.value],
    "permissions": ["read:reports"],
    "tenant_ids": ["2b0f8a08-6baf-4e74-9c3e-6d1d3f8a8b5a"],
    "status": UserStatus.ACTIVE.value,
    "created_at": "2026-03-21T12:00:00Z",
    "last_login_at": "2026-03-21T12:30:00Z",
}


USER_LIST_EXAMPLE: dict[str, Any] = {
    "users": [CURRENT_USER_EXAMPLE],
    "total": 1,
    "page": 1,
    "page_size": 50,
}


USER_REGISTER_EXAMPLE: dict[str, Any] = {
    "id": 13,
    "email": "new.user@example.com",
    "username": "new.user",
    "full_name": "New User",
    "roles": [UserRole.TENANT_OWNER.value],
    "permissions": [],
    "tenant_ids": [],
    "status": UserStatus.ACTIVE.value,
    "created_at": "2026-03-21T12:00:00Z",
    "last_login_at": None,
}


UPDATED_USER_EXAMPLE: dict[str, Any] = {
    **CURRENT_USER_EXAMPLE,
    "full_name": "Updated Name",
    "email": "updated@example.com",
}


ASSIGN_ROLES_EXAMPLE: dict[str, Any] = {
    "roles": [UserRole.ADMIN.value, UserRole.ASSISTANT.value],
}


ASSIGN_PERMISSIONS_EXAMPLE: dict[str, Any] = {
    "permissions": ["read:reports", "write:reports"],
}


ASSIGN_TENANTS_EXAMPLE: dict[str, Any] = {
    "tenant_ids": ["2b0f8a08-6baf-4e74-9c3e-6d1d3f8a8b5a", "8e4cd1a8-2f4d-4f55-8c62-7f6f93d6e69f"],
}


COMMON_AUTH_RESPONSES: OpenAPIResponses = {
    401: {"description": "Missing, invalid, or expired bearer token."},
    403: {"description": "Authenticated user is inactive, locked, or not permitted to use this endpoint."},
}


COMMON_ADMIN_RESPONSES: OpenAPIResponses = {
    401: {"description": "Missing, invalid, or expired bearer token."},
    403: {"description": "Authenticated user is inactive, locked, or does not have the admin role required here."},
}


def json_response(description: str, example: Any) -> dict[str, Any]:
    """Return a JSON response block with a concrete example."""
    return {
        "description": description,
        "content": {
            "application/json": {
                "example": example,
            }
        },
    }

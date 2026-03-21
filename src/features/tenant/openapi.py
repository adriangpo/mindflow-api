"""OpenAPI helpers for the tenant feature."""

from pydantic import BaseModel, Field


class TenantErrorResponse(BaseModel):
    """Standard error response used by tenant routes."""

    detail: str = Field(..., examples=["Tenant not found"])


class TenantMessageResponse(BaseModel):
    """Standard success message response used by tenant routes."""

    message: str = Field(..., examples=["Tenant deactivated successfully"])


TENANT_RESPONSE_EXAMPLE = {
    "id": "0196e19d-7f7b-7f0b-8e8d-4d7ad75f8c31",
    "name": "Blue Clinic",
    "slug": "blue-clinic",
    "is_active": True,
    "created_at": "2026-03-21T12:00:00Z",
    "updated_at": "2026-03-21T12:00:00Z",
}

TENANT_LIST_RESPONSE_EXAMPLE = {
    "tenants": [TENANT_RESPONSE_EXAMPLE],
    "total": 1,
    "page": 1,
    "page_size": 50,
}

TENANT_MESSAGE_RESPONSE_EXAMPLE = {
    "message": "Tenant deactivated successfully",
}

TENANT_UNAUTHORIZED_RESPONSE = {
    "model": TenantErrorResponse,
    "description": "The request is missing a valid bearer token.",
    "content": {
        "application/json": {
            "examples": {
                "missing_token": {
                    "summary": "Missing token",
                    "value": {"detail": "Not authenticated"},
                },
                "invalid_token": {
                    "summary": "Invalid token",
                    "value": {"detail": "Invalid or expired token"},
                },
            }
        }
    },
}

TENANT_FORBIDDEN_RESPONSE = {
    "model": TenantErrorResponse,
    "description": "The authenticated user is not allowed to perform the operation.",
    "content": {
        "application/json": {
            "examples": {
                "forbidden": {
                    "summary": "Forbidden",
                    "value": {"detail": "User does not have required role(s): admin"},
                },
                "inactive": {
                    "summary": "Inactive account",
                    "value": {"detail": "User account is inactive"},
                },
                "locked": {
                    "summary": "Locked account",
                    "value": {"detail": "User account is locked"},
                },
            }
        }
    },
}

TENANT_NOT_FOUND_RESPONSE = {
    "model": TenantErrorResponse,
    "description": "The requested tenant UUID does not exist.",
    "content": {
        "application/json": {
            "examples": {
                "not_found": {
                    "summary": "Missing tenant",
                    "value": {"detail": "Tenant not found"},
                }
            }
        }
    },
}

TENANT_CONFLICT_RESPONSE = {
    "model": TenantErrorResponse,
    "description": "The tenant payload violates a unique or format constraint.",
    "content": {
        "application/json": {
            "examples": {
                "name_conflict": {
                    "summary": "Duplicate name",
                    "value": {"detail": "Tenant name already exists"},
                },
                "slug_conflict": {
                    "summary": "Duplicate slug",
                    "value": {"detail": "Tenant slug already exists"},
                },
                "slug_invalid": {
                    "summary": "Invalid slug",
                    "value": {"detail": "Tenant slug is invalid"},
                },
            }
        }
    },
}

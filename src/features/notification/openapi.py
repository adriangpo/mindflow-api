"""OpenAPI helpers and docs-only schemas for the notification feature."""

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

OpenAPIResponse = dict[str, Any]
OpenAPIResponses = dict[int | str, OpenAPIResponse]


class NotificationSyncResponse(BaseModel):
    """Response returned by the QStash reminder backfill callback."""

    tenant_count: int = Field(description="Number of active tenants scanned for pending reminders.")
    scheduled_count: int = Field(description="Number of reminder messages published to QStash.")
    failed_count: int = Field(description="Number of reminder schedules that failed to publish.")

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "tenant_count": 12,
                    "scheduled_count": 48,
                    "failed_count": 0,
                }
            ]
        }
    )


def _json_response(description: str, example: dict[str, object]) -> OpenAPIResponse:
    return {
        "description": description,
        "content": {
            "application/json": {
                "example": example,
            }
        },
    }


def tenant_access_responses(*, not_found_detail: str | None = None) -> OpenAPIResponses:
    """Return the common tenant-auth response docs used by tenant-scoped routes."""
    responses: OpenAPIResponses = {
        400: _json_response(
            "Tenant header is missing or not a valid UUID.",
            {"detail": "X-Tenant-ID header is required"},
        ),
        401: _json_response(
            "Bearer access token is missing or invalid.",
            {"detail": "Not authenticated"},
        ),
        403: _json_response(
            "Authenticated user is not allowed to access the requested tenant.",
            {"detail": "User is not assigned to requested tenant"},
        ),
        422: _json_response(
            "Request body or query parameters failed validation.",
            {
                "detail": [
                    {
                        "loc": ["body", "default_reminder_minutes_before"],
                        "msg": "Input should be greater than or equal to 1",
                        "type": "greater_than_equal",
                    }
                ]
            },
        ),
    }

    if not_found_detail is not None:
        responses[404] = _json_response(
            "Requested resource was not found in the current tenant.",
            {"detail": not_found_detail},
        )

    return responses


def qstash_signature_responses() -> OpenAPIResponses:
    """Return the common callback response docs for signed QStash routes."""
    return {
        401: _json_response(
            "QStash signature is missing or invalid.",
            {"detail": "Missing QStash signature"},
        ),
    }


def internal_delivery_request_schema() -> dict[str, object]:
    """Return the docs-only schema for the signed delivery callback payload."""
    return {
        "type": "object",
        "required": ["message_id", "tenant_id"],
        "properties": {
            "message_id": {
                "type": "integer",
                "minimum": 1,
                "description": "Notification message id to deliver.",
            },
            "tenant_id": {
                "type": "string",
                "format": "uuid",
                "description": "Tenant that owns the pending message.",
            },
        },
        "example": {
            "message_id": 123,
            "tenant_id": "9c2c4e31-2d9c-4a0e-9e5f-06b0d59318f0",
        },
    }


def internal_sync_request_schema() -> dict[str, object]:
    """Return the docs-only schema for the signed daily sync callback payload."""
    return {
        "type": "object",
        "properties": {
            "kind": {
                "anyOf": [{"type": "string"}, {"type": "null"}],
                "description": "Optional marker used by the daily backfill callback.",
                "example": "notification_sync",
            }
        },
        "example": {
            "kind": "notification_sync",
        },
    }

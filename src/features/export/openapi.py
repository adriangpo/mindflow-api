"""OpenAPI helpers and documentation schemas for export routes."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from .schemas import ExportJobStatus, ExportProcessCallbackRequest

OpenAPIResponse = dict[str, Any]
OpenAPIResponses = dict[int | str, OpenAPIResponse]

EXPORT_JOB_RESPONSE_EXAMPLE: dict[str, Any] = {
    "id": "0196f8a1-3d7d-7d0b-9a3c-2ad74a1f4c7a",
    "kind": "medical_record_all_pdf",
    "status": "queued",
    "progress_current": 0,
    "progress_total": 3,
    "progress_message": "Queued",
    "download_url": None,
    "error_detail": None,
    "created_at": "2026-03-21T13:00:00Z",
    "updated_at": "2026-03-21T13:00:00Z",
}

EXPORT_EVENT_STREAM_EXAMPLE = (
    ": connected\n\n"
    "event: export.updated\n"
    'data: {"id":"0196f8a1-3d7d-7d0b-9a3c-2ad74a1f4c7a","kind":"medical_record_all_pdf",'
    '"status":"completed","progress_current":3,"progress_total":3,'
    '"progress_message":"Export completed","download_url":"/api/exports/'
    '0196f8a1-3d7d-7d0b-9a3c-2ad74a1f4c7a/download","error_detail":null,'
    '"created_at":"2026-03-21T13:00:00Z","updated_at":"2026-03-21T13:01:10Z"}\n\n'
    ": keepalive\n\n"
)


class ExportProcessCallbackResponse(BaseModel):
    """Response returned after an internal QStash export callback is processed."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "job_id": "0196f8a1-3d7d-7d0b-9a3c-2ad74a1f4c7a",
                "status": "completed",
            }
        }
    )

    job_id: str = Field(description="Export job identifier processed by the callback.")
    status: ExportJobStatus = Field(description="Final job status after processing.")


EXPORT_EVENTS_RESPONSES: OpenAPIResponses = {
    200: {
        "description": (
            "Server-sent events stream for export updates owned by the authenticated user in the current tenant."
        ),
        "content": {
            "text/event-stream": {
                "schema": {"type": "string"},
                "example": EXPORT_EVENT_STREAM_EXAMPLE,
            }
        },
    },
    401: {
        "description": "Missing or invalid bearer token.",
    },
    403: {
        "description": "Authenticated user is not assigned to the requested tenant.",
    },
}

EXPORT_JOB_NOT_FOUND_RESPONSE: dict[str, Any] = {
    "description": "Export job not found or not visible to the current tenant/user.",
}

EXPORT_DOWNLOAD_RESPONSES: OpenAPIResponses = {
    200: {
        "description": (
            "Completed export file. Local storage returns the file directly; S3-compatible storage may redirect "
            "to a presigned object URL instead."
        ),
        "content": {
            "application/pdf": {
                "schema": {"type": "string", "format": "binary"},
            }
        },
    },
    307: {
        "description": "Temporary redirect to a presigned URL when the storage backend is S3-compatible.",
        "headers": {
            "Location": {
                "description": "Presigned download URL.",
                "schema": {"type": "string", "format": "uri"},
            }
        },
    },
    404: EXPORT_JOB_NOT_FOUND_RESPONSE,
    409: {
        "description": (
            "Export job is not complete yet or the stored file metadata is incomplete for download resolution."
        ),
    },
}

EXPORT_PROCESS_CALLBACK_OPENAPI_EXTRA: dict[str, Any] = {
    "parameters": [
        {
            "name": "Upstash-Signature",
            "in": "header",
            "required": True,
            "description": "Required signature used to verify the signed QStash callback.",
            "schema": {"type": "string"},
        }
    ],
    "requestBody": {
        "required": True,
        "content": {
            "application/json": {
                "schema": ExportProcessCallbackRequest.model_json_schema(),
                "example": {"job_id": "0196f8a1-3d7d-7d0b-9a3c-2ad74a1f4c7a"},
            }
        },
    },
}

EXPORT_PROCESS_CALLBACK_RESPONSES: OpenAPIResponses = {
    401: {
        "description": "Missing or invalid QStash signature.",
    },
    404: {
        "description": "QStash callbacks are disabled for the current environment.",
    },
}

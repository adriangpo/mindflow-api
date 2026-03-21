"""OpenAPI metadata for medical record routes."""

from typing import Any

from pydantic import BaseModel, Field

from src.features.export.schemas import ExportJobResponse

from .schemas import MedicalRecordListResponse, MedicalRecordPatientHistoryResponse, MedicalRecordResponse

OpenAPIResponse = dict[str, Any]
OpenAPIResponses = dict[int | str, OpenAPIResponse]


class MedicalRecordErrorResponse(BaseModel):
    """Standard error payload returned by medical record routes."""

    detail: str = Field(..., description="Human-readable error message returned by the API.")


MEDICAL_RECORD_CREATE_DESCRIPTION = (
    "Create one tenant-scoped consultation note. The authenticated user is stored as "
    "`recorded_by_user_id`, the patient must exist in the current tenant, and an optional appointment must "
    "also exist in the current tenant and belong to the same patient. `recorded_at` defaults to the current "
    "UTC time when omitted. Attachments are stored as URL strings and the API rejects duplicate URLs."
)

MEDICAL_RECORD_LIST_DESCRIPTION = (
    "List consultation notes for the current tenant. Filtering supports patient, appointment, free-text search "
    "across title/content/assessment/treatment plan, and date windows evaluated against `recorded_at`'s date "
    "portion. Results are ordered by `recorded_at DESC, id DESC`. The shared pagination contract allows "
    "`page=None` and `page_size=None` to disable paging."
)

MEDICAL_RECORD_HISTORY_DESCRIPTION = (
    "Return the consultation history for one tenant patient. The patient must exist in the current tenant and "
    "the history list uses the same ordering and pagination rules as the main list endpoint."
)

MEDICAL_RECORD_DETAIL_DESCRIPTION = (
    "Return one consultation note by id from the current tenant. The lookup is tenant-scoped, so the same "
    "numeric id in another tenant is not visible here."
)

MEDICAL_RECORD_UPDATE_DESCRIPTION = (
    "Update one consultation note in place. The service re-checks patient and appointment tenancy, and it "
    "rejects any patient/appointment mismatch. Optional fields are patch-like: omitted fields remain unchanged, "
    "`attachments=None` clears the attachment list, and sending `patient_id` or `content` as null is rejected."
)

MEDICAL_RECORD_EXPORT_ALL_DESCRIPTION = (
    "Queue a PDF export for every consultation note in the current tenant. The service refuses to enqueue the "
    "job when the tenant has no medical records. The response is the shared export job envelope; the file is "
    "retrieved later through the `/api/exports` endpoints."
)

MEDICAL_RECORD_EXPORT_PATIENT_DESCRIPTION = (
    "Queue a PDF export for one patient's consultation history. The patient must exist in the current tenant "
    "and the tenant must already contain at least one record for that patient. The response is the shared export "
    "job envelope; the file is retrieved later through the `/api/exports` endpoints."
)

MEDICAL_RECORD_EXPORT_SINGLE_DESCRIPTION = (
    "Queue a PDF export for one consultation note. The record must exist in the current tenant. The response is "
    "the shared export job envelope; the file is retrieved later through the `/api/exports` endpoints."
)

MEDICAL_RECORD_EXAMPLE: dict[str, Any] = {
    "id": 101,
    "patient_id": 42,
    "appointment_id": 9001,
    "recorded_by_user_id": 7,
    "recorded_at": "2026-03-21T13:00:00Z",
    "title": "Follow-up consultation",
    "content": "Patient reports improved sleep and reduced anxiety.",
    "clinical_assessment": "Stable, with gradual improvement.",
    "treatment_plan": "Continue current medication and reassess in 30 days.",
    "attachments": [
        "https://files.example.com/medical-records/101/lab-result.pdf",
    ],
    "created_at": "2026-03-21T13:05:00Z",
    "updated_at": "2026-03-21T13:05:00Z",
}

MEDICAL_RECORD_LIST_EXAMPLE: dict[str, Any] = {
    "records": [MEDICAL_RECORD_EXAMPLE],
    "total": 1,
    "page": 1,
    "page_size": 50,
}

MEDICAL_RECORD_HISTORY_EXAMPLE: dict[str, Any] = {
    "patient_id": 42,
    "records": [MEDICAL_RECORD_EXAMPLE],
    "total": 1,
    "page": 1,
    "page_size": 50,
}

MEDICAL_RECORD_EXPORT_EXAMPLE: dict[str, Any] = {
    "id": "5f8f3b9c-8c8f-4d7e-a6c1-0a4f4d7c7001",
    "kind": "medical_record_all_pdf",
    "status": "queued",
    "progress_current": 0,
    "progress_total": 1,
    "progress_message": "Queued for processing",
    "download_url": None,
    "error_detail": None,
    "created_at": "2026-03-21T13:05:00Z",
    "updated_at": "2026-03-21T13:05:00Z",
}

MEDICAL_RECORD_EXPORT_PATIENT_EXAMPLE: dict[str, Any] = {
    **MEDICAL_RECORD_EXPORT_EXAMPLE,
    "kind": "medical_record_patient_history_pdf",
}

MEDICAL_RECORD_EXPORT_SINGLE_EXAMPLE: dict[str, Any] = {
    **MEDICAL_RECORD_EXPORT_EXAMPLE,
    "kind": "medical_record_single_pdf",
}

MEDICAL_RECORD_ERROR_EXAMPLES: dict[str, dict[str, Any]] = {
    "record_not_found": {
        "summary": "Medical record missing",
        "value": {"detail": "Medical record not found"},
    },
    "patient_not_found": {
        "summary": "Patient missing",
        "value": {"detail": "Patient not found for medical record"},
    },
    "appointment_not_found": {
        "summary": "Appointment missing",
        "value": {"detail": "Appointment not found for medical record"},
    },
    "appointment_mismatch": {
        "summary": "Appointment belongs to another patient",
        "value": {"detail": "Appointment does not belong to the informed patient"},
    },
    "export_empty": {
        "summary": "No records to export",
        "value": {"detail": "No medical records available for export"},
    },
}

CREATE_MEDICAL_RECORD_RESPONSES: OpenAPIResponses = {
    200: {
        "model": MedicalRecordResponse,
        "description": "The consultation note was created in the current tenant.",
        "content": {"application/json": {"examples": {"default": MEDICAL_RECORD_EXAMPLE}}},
    },
    401: {
        "model": MedicalRecordErrorResponse,
        "description": "A valid bearer token is required.",
    },
    403: {
        "model": MedicalRecordErrorResponse,
        "description": "The authenticated user is not assigned to the requested tenant or lacks the required role.",
    },
    404: {
        "model": MedicalRecordErrorResponse,
        "description": "The referenced patient or appointment does not exist in the current tenant.",
        "content": {
            "application/json": {
                "examples": {
                    "patient_not_found": MEDICAL_RECORD_ERROR_EXAMPLES["patient_not_found"],
                    "appointment_not_found": MEDICAL_RECORD_ERROR_EXAMPLES["appointment_not_found"],
                }
            }
        },
    },
    409: {
        "model": MedicalRecordErrorResponse,
        "description": "The supplied appointment does not belong to the supplied patient.",
        "content": {
            "application/json": {
                "examples": {
                    "appointment_mismatch": MEDICAL_RECORD_ERROR_EXAMPLES["appointment_mismatch"],
                }
            }
        },
    },
}

LIST_MEDICAL_RECORDS_RESPONSES: OpenAPIResponses = {
    200: {
        "model": MedicalRecordListResponse,
        "description": "The current tenant's consultation notes were returned with the active filter set.",
        "content": {"application/json": {"examples": {"default": MEDICAL_RECORD_LIST_EXAMPLE}}},
    },
    401: {
        "model": MedicalRecordErrorResponse,
        "description": "A valid bearer token is required.",
    },
    403: {
        "model": MedicalRecordErrorResponse,
        "description": "The authenticated user is not assigned to the requested tenant or lacks the required role.",
    },
}

HISTORY_MEDICAL_RECORDS_RESPONSES: OpenAPIResponses = {
    200: {
        "model": MedicalRecordPatientHistoryResponse,
        "description": "The requested patient's consultation history was returned.",
        "content": {"application/json": {"examples": {"default": MEDICAL_RECORD_HISTORY_EXAMPLE}}},
    },
    401: {
        "model": MedicalRecordErrorResponse,
        "description": "A valid bearer token is required.",
    },
    403: {
        "model": MedicalRecordErrorResponse,
        "description": "The authenticated user is not assigned to the requested tenant or lacks the required role.",
    },
    404: {
        "model": MedicalRecordErrorResponse,
        "description": "The patient does not exist in the current tenant.",
        "content": {
            "application/json": {
                "examples": {"patient_not_found": MEDICAL_RECORD_ERROR_EXAMPLES["patient_not_found"]},
            }
        },
    },
}

DETAIL_MEDICAL_RECORD_RESPONSES: OpenAPIResponses = {
    200: {
        "model": MedicalRecordResponse,
        "description": "The requested consultation note was returned.",
        "content": {"application/json": {"examples": {"default": MEDICAL_RECORD_EXAMPLE}}},
    },
    401: {
        "model": MedicalRecordErrorResponse,
        "description": "A valid bearer token is required.",
    },
    403: {
        "model": MedicalRecordErrorResponse,
        "description": "The authenticated user is not assigned to the requested tenant or lacks the required role.",
    },
    404: {
        "model": MedicalRecordErrorResponse,
        "description": "The consultation note does not exist in the current tenant.",
        "content": {
            "application/json": {
                "examples": {"record_not_found": MEDICAL_RECORD_ERROR_EXAMPLES["record_not_found"]},
            }
        },
    },
}

UPDATE_MEDICAL_RECORD_RESPONSES: OpenAPIResponses = {
    200: {
        "model": MedicalRecordResponse,
        "description": "The consultation note was updated in place.",
        "content": {"application/json": {"examples": {"default": MEDICAL_RECORD_EXAMPLE}}},
    },
    401: {
        "model": MedicalRecordErrorResponse,
        "description": "A valid bearer token is required.",
    },
    403: {
        "model": MedicalRecordErrorResponse,
        "description": "The authenticated user is not assigned to the requested tenant or lacks the required role.",
    },
    404: {
        "model": MedicalRecordErrorResponse,
        "description": "The consultation note, patient, or appointment does not exist in the current tenant.",
        "content": {
            "application/json": {
                "examples": {
                    "record_not_found": MEDICAL_RECORD_ERROR_EXAMPLES["record_not_found"],
                    "patient_not_found": MEDICAL_RECORD_ERROR_EXAMPLES["patient_not_found"],
                    "appointment_not_found": MEDICAL_RECORD_ERROR_EXAMPLES["appointment_not_found"],
                }
            }
        },
    },
    409: {
        "model": MedicalRecordErrorResponse,
        "description": "The supplied patient and appointment do not belong to the same consultation.",
        "content": {
            "application/json": {
                "examples": {
                    "appointment_mismatch": MEDICAL_RECORD_ERROR_EXAMPLES["appointment_mismatch"],
                }
            }
        },
    },
}

EXPORT_ALL_MEDICAL_RECORD_RESPONSES: OpenAPIResponses = {
    202: {
        "model": ExportJobResponse,
        "description": "The all-records export job was accepted for asynchronous processing.",
        "content": {"application/json": {"examples": {"default": MEDICAL_RECORD_EXPORT_EXAMPLE}}},
    },
    401: {
        "model": MedicalRecordErrorResponse,
        "description": "A valid bearer token is required.",
    },
    403: {
        "model": MedicalRecordErrorResponse,
        "description": "The authenticated user is not assigned to the requested tenant or lacks the required role.",
    },
    404: {
        "model": MedicalRecordErrorResponse,
        "description": "The current tenant has no medical records to export.",
        "content": {
            "application/json": {
                "examples": {"export_empty": MEDICAL_RECORD_ERROR_EXAMPLES["export_empty"]},
            }
        },
    },
}

EXPORT_PATIENT_HISTORY_RESPONSES: OpenAPIResponses = {
    202: {
        "model": ExportJobResponse,
        "description": "The patient-history export job was accepted for asynchronous processing.",
        "content": {"application/json": {"examples": {"default": MEDICAL_RECORD_EXPORT_PATIENT_EXAMPLE}}},
    },
    401: {
        "model": MedicalRecordErrorResponse,
        "description": "A valid bearer token is required.",
    },
    403: {
        "model": MedicalRecordErrorResponse,
        "description": "The authenticated user is not assigned to the requested tenant or lacks the required role.",
    },
    404: {
        "model": MedicalRecordErrorResponse,
        "description": "The patient does not exist in the current tenant or has no medical records to export.",
        "content": {
            "application/json": {
                "examples": {
                    "patient_not_found": MEDICAL_RECORD_ERROR_EXAMPLES["patient_not_found"],
                    "export_empty": MEDICAL_RECORD_ERROR_EXAMPLES["export_empty"],
                }
            }
        },
    },
}

EXPORT_SINGLE_RESPONSES: OpenAPIResponses = {
    202: {
        "model": ExportJobResponse,
        "description": "The single-record export job was accepted for asynchronous processing.",
        "content": {"application/json": {"examples": {"default": MEDICAL_RECORD_EXPORT_SINGLE_EXAMPLE}}},
    },
    401: {
        "model": MedicalRecordErrorResponse,
        "description": "A valid bearer token is required.",
    },
    403: {
        "model": MedicalRecordErrorResponse,
        "description": "The authenticated user is not assigned to the requested tenant or lacks the required role.",
    },
    404: {
        "model": MedicalRecordErrorResponse,
        "description": "The consultation note does not exist in the current tenant.",
        "content": {
            "application/json": {
                "examples": {"record_not_found": MEDICAL_RECORD_ERROR_EXAMPLES["record_not_found"]},
            }
        },
    },
}

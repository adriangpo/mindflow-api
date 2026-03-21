"""OpenAPI metadata for patient routes."""

from typing import Any

from pydantic import BaseModel, Field

from src.features.export.schemas import ExportJobResponse

from .schemas import PatientListResponse, PatientResponse

OpenAPIResponse = dict[str, Any]
OpenAPIResponses = dict[int | str, OpenAPIResponse]


class PatientErrorResponse(BaseModel):
    """Standard error payload returned by patient routes."""

    detail: str = Field(..., description="Human-readable error message returned by the API.")


class PatientMessageResponse(BaseModel):
    """Standard message payload returned by patient routes."""

    message: str = Field(..., description="Human-readable status message returned by the API.")


def _json_example(value: dict[str, Any], summary: str) -> dict[str, Any]:
    return {"summary": summary, "value": value}


def _response(model: type[BaseModel], description: str, example: dict[str, Any]) -> OpenAPIResponse:
    return {
        "model": model,
        "description": description,
        "content": {
            "application/json": {
                "examples": {"default": example},
            }
        },
    }


PATIENT_TENANT_HEADER_RESPONSE: OpenAPIResponses = {
    400: _response(
        PatientErrorResponse,
        "The tenant header is missing or invalid.",
        _json_example({"detail": "X-Tenant-ID header is required"}, "Missing tenant header"),
    ),
}

PATIENT_AUTH_RESPONSE: OpenAPIResponses = {
    401: _response(
        PatientErrorResponse,
        "The bearer token is missing, expired, or invalid.",
        _json_example({"detail": "Invalid or expired token"}, "Invalid bearer token"),
    ),
}

PATIENT_FORBIDDEN_RESPONSE: OpenAPIResponses = {
    403: _response(
        PatientErrorResponse,
        "The authenticated user is inactive, locked, missing the tenant_owner role, or not assigned to the tenant.",
        _json_example({"detail": "User is not assigned to requested tenant"}, "Tenant membership failure"),
    ),
}

PATIENT_NOT_FOUND_RESPONSE: OpenAPIResponses = {
    404: _response(
        PatientErrorResponse,
        "The requested patient does not exist in the current tenant.",
        _json_example({"detail": "Patient not found"}, "Patient not found"),
    ),
}

PATIENT_CPF_CONFLICT_RESPONSE: OpenAPIResponses = {
    409: _response(
        PatientErrorResponse,
        "The CPF already exists inside the current tenant.",
        _json_example(
            {"detail": "Patient CPF already registered in this tenant"},
            "Duplicate tenant CPF",
        ),
    ),
}

PATIENT_ALREADY_ACTIVE_CONFLICT_RESPONSE: OpenAPIResponses = {
    409: _response(
        PatientErrorResponse,
        "The patient is already active or cannot be reactivated again.",
        _json_example({"detail": "Patient is already active"}, "Already active"),
    ),
}

PATIENT_ALREADY_INACTIVE_CONFLICT_RESPONSE: OpenAPIResponses = {
    409: _response(
        PatientErrorResponse,
        "The patient is already inactive.",
        _json_example({"detail": "Patient is already inactive"}, "Already inactive"),
    ),
}

PATIENT_ALREADY_REGISTERED_CONFLICT_RESPONSE: OpenAPIResponses = {
    409: _response(
        PatientErrorResponse,
        "The patient already has full registration data.",
        _json_example({"detail": "Patient is already fully registered"}, "Already registered"),
    ),
}

PATIENT_RESPONSE_EXAMPLE = _json_example(
    {
        "id": 123,
        "full_name": "Maria Oliveira",
        "birth_date": "1995-05-22",
        "cpf": "52998224725",
        "cep": "19900000",
        "phone_number": "14999999999",
        "session_price": "180.00",
        "session_frequency": "weekly",
        "first_session_date": "2026-03-20",
        "guardian_name": None,
        "guardian_phone": None,
        "profile_photo_url": "https://example.com/patient-photo.jpg",
        "initial_record": "Initial history notes.",
        "is_registered": True,
        "is_active": True,
        "inactivated_at": None,
        "retention_expires_at": None,
        "created_at": "2026-03-21T12:00:00Z",
        "updated_at": "2026-03-21T12:00:00Z",
    },
    "Patient resource",
)

PATIENT_LIST_RESPONSE_EXAMPLE = _json_example(
    {
        "patients": [PATIENT_RESPONSE_EXAMPLE["value"]],
        "total": 1,
        "page": 1,
        "page_size": 50,
    },
    "Paginated patient list",
)

PATIENT_MESSAGE_EXAMPLE = _json_example(
    {"message": "Patient inactivated successfully"},
    "Patient lifecycle message",
)

EXPORT_JOB_EXAMPLE = _json_example(
    {
        "id": "job_123",
        "kind": "patient_complete_pdf",
        "status": "queued",
        "progress_current": 0,
        "progress_total": 100,
        "progress_message": "Queued for processing",
        "download_url": None,
        "error_detail": None,
        "created_at": "2026-03-21T12:00:00Z",
        "updated_at": "2026-03-21T12:00:00Z",
    },
    "Queued export job",
)

PATIENT_RESPONSE_DOC: OpenAPIResponses = {
    200: _response(
        PatientResponse,
        "The patient was created, updated, fetched, completed, reactivated, or had the profile photo updated.",
        PATIENT_RESPONSE_EXAMPLE,
    ),
}

PATIENT_LIST_RESPONSE_DOC: OpenAPIResponses = {
    200: _response(
        PatientListResponse,
        "The tenant patient collection was returned with pagination metadata.",
        PATIENT_LIST_RESPONSE_EXAMPLE,
    ),
}

PATIENT_EXPORT_RESPONSE_DOC: OpenAPIResponses = {
    202: _response(
        ExportJobResponse,
        "The export job was queued for asynchronous processing.",
        EXPORT_JOB_EXAMPLE,
    ),
}

PATIENT_DELETE_RESPONSE_DOC: OpenAPIResponses = {
    200: _response(
        PatientMessageResponse,
        "The patient was inactivated successfully.",
        PATIENT_MESSAGE_EXAMPLE,
    ),
}

CREATE_PATIENT_DESCRIPTION = (
    "Create a fully registered patient in the current tenant. The request enforces the same full-registration "
    "validation rules as the service layer, including CPF checksum validation, age checks, and guardian "
    "requirements for minors. When the tenant already has the same CPF, the router maps the unique-constraint "
    "failure to `409 Conflict`."
)

QUICK_REGISTER_DESCRIPTION = (
    "Create a lightweight patient record containing only the name. This path is intended for intake or first "
    "consultation workflows where the patient is not fully registered yet. The created record starts as "
    "`is_registered=false` and `is_active=true`."
)

LIST_PATIENTS_DESCRIPTION = (
    "List tenant patients with optional text search and status filters. Results are always tenant-scoped, ordered "
    "by newest `created_at` first, and paginated with the shared pagination contract."
)

GET_PATIENT_DESCRIPTION = (
    "Return one patient from the current tenant. The lookup is tenant-scoped, so the same numeric `patient_id` "
    "cannot resolve to a record in another tenant."
)

EXPORT_PATIENT_DESCRIPTION = (
    "Queue an asynchronous PDF export for the full patient dossier. The worker-generated file includes the patient "
    "profile, appointment history, medical-record history, and billing summary. The API returns `202 Accepted` and "
    "the job must be tracked through the shared export routes."
)

UPDATE_PATIENT_DESCRIPTION = (
    "Update patient fields partially. When the patient is already fully registered, the router merges persisted and "
    "incoming values and revalidates the merged payload against the full registration contract so that cross-field "
    "rules remain enforced."
)

COMPLETE_REGISTRATION_DESCRIPTION = (
    "Convert a quick-registered patient into a fully registered patient. The request uses the full-registration "
    "schema, rejects already registered patients with `409 Conflict`, and clears any inactivation metadata when "
    "registration is completed."
)

PROFILE_PHOTO_DESCRIPTION = (
    "Update only the patient profile photo URL. The request accepts a valid URL or `null` to clear the stored "
    "photo reference."
)

INACTIVATE_PATIENT_DESCRIPTION = (
    "Soft-delete the patient by marking the record inactive. The router does not remove the row; instead it stores "
    "the inactivation timestamp and a five-year retention deadline so the record can still be audited or reactivated "
    "later."
)

REACTIVATE_PATIENT_DESCRIPTION = (
    "Re-enable a patient that was previously inactivated. The router clears the retention metadata and returns the "
    "updated patient representation."
)

PATIENT_COMMON_ACCESS_RESPONSES: OpenAPIResponses = {
    **PATIENT_TENANT_HEADER_RESPONSE,
    **PATIENT_AUTH_RESPONSE,
    **PATIENT_FORBIDDEN_RESPONSE,
}

PATIENT_CREATE_RESPONSES: OpenAPIResponses = {
    **PATIENT_COMMON_ACCESS_RESPONSES,
    **PATIENT_CPF_CONFLICT_RESPONSE,
}

PATIENT_QUICK_REGISTER_RESPONSES = PATIENT_COMMON_ACCESS_RESPONSES

PATIENT_LIST_RESPONSES = PATIENT_COMMON_ACCESS_RESPONSES

PATIENT_GET_RESPONSES: OpenAPIResponses = {
    **PATIENT_COMMON_ACCESS_RESPONSES,
    **PATIENT_NOT_FOUND_RESPONSE,
}

PATIENT_EXPORT_RESPONSES: OpenAPIResponses = {
    **PATIENT_COMMON_ACCESS_RESPONSES,
    **PATIENT_NOT_FOUND_RESPONSE,
}

PATIENT_UPDATE_RESPONSES: OpenAPIResponses = {
    **PATIENT_COMMON_ACCESS_RESPONSES,
    **PATIENT_NOT_FOUND_RESPONSE,
    **PATIENT_CPF_CONFLICT_RESPONSE,
}

PATIENT_COMPLETE_REGISTRATION_RESPONSES: OpenAPIResponses = {
    **PATIENT_COMMON_ACCESS_RESPONSES,
    **PATIENT_NOT_FOUND_RESPONSE,
    **PATIENT_CPF_CONFLICT_RESPONSE,
    **PATIENT_ALREADY_REGISTERED_CONFLICT_RESPONSE,
}

PATIENT_PROFILE_PHOTO_RESPONSES: OpenAPIResponses = {
    **PATIENT_COMMON_ACCESS_RESPONSES,
    **PATIENT_NOT_FOUND_RESPONSE,
}

PATIENT_DELETE_RESPONSES: OpenAPIResponses = {
    **PATIENT_COMMON_ACCESS_RESPONSES,
    **PATIENT_NOT_FOUND_RESPONSE,
    **PATIENT_ALREADY_INACTIVE_CONFLICT_RESPONSE,
}

PATIENT_REACTIVATE_RESPONSES: OpenAPIResponses = {
    **PATIENT_COMMON_ACCESS_RESPONSES,
    **PATIENT_NOT_FOUND_RESPONSE,
    **PATIENT_ALREADY_ACTIVE_CONFLICT_RESPONSE,
}

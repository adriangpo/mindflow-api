"""OpenAPI metadata for finance routes."""

from typing import Any

from pydantic import BaseModel, Field

from src.features.export.schemas import ExportJobResponse

from .schemas import FinanceReportResponse, FinancialEntryListResponse, FinancialEntryResponse

OpenAPIResponse = dict[str, Any]
OpenAPIResponses = dict[int | str, OpenAPIResponse]


class FinanceErrorResponse(BaseModel):
    """Standard error response returned by finance routes."""

    detail: str = Field(..., description="Human-readable error message returned by the API.")


FINANCIAL_ENTRY_CREATE_DESCRIPTION = (
    "Create one manual financial entry for the current tenant. The authenticated user is stored as "
    "`created_by_user_id`, and the entry is persisted as an auditable tenant-scoped record. "
    "The API does not expose an edit-in-place flow for values that should be corrected later; the supported "
    "correction path is to reverse the entry and create a replacement entry."
)

FINANCIAL_ENTRY_LIST_DESCRIPTION = (
    "List tenant manual entries with optional filters. Results are ordered by `occurred_on DESC, id DESC`. "
    "Pagination follows the shared `page` / `page_size` contract, and sending both as `None` disables paging. "
    "When `include_reversed` is `false` the response hides reversed rows. If both `start_date` and `end_date` "
    "are provided, the service requires `end_date >= start_date`."
)

FINANCIAL_ENTRY_DETAIL_DESCRIPTION = (
    "Return one manual entry from the current tenant. The lookup is tenant-scoped, so the same numeric id in "
    "another tenant is not visible here. Missing entries return `404`."
)

FINANCIAL_ENTRY_REVERSE_DESCRIPTION = (
    "Reverse one manual financial entry. The service marks the row as reversed, stores the reversal timestamp, "
    "stores the authenticated user as the reverser, and persists the supplied reason. Already reversed rows are "
    "rejected with `409 Conflict`."
)

FINANCE_REPORT_DESCRIPTION = (
    "Build a tenant finance summary for the selected time window. Automatic income comes from paid "
    "`schedule_appointments`, while manual totals come from non-reversed `financial_entries`. "
    "For `view=custom`, both `start_date` and `end_date` are required and `end_date` must be greater than or "
    "equal to `start_date`. For `view=total`, the service ignores the date filters and returns an unbounded "
    "report with `range_start` and `range_end` set to `null`."
)

FINANCE_EXPORT_DESCRIPTION = (
    "Queue a PDF export for the same finance report window used by `GET /api/finance/report`. "
    "The request is validated by the report builder before the export job is created, so invalid date windows "
    "fail before any async work is enqueued. The response is the generic export job envelope; the actual file is "
    "retrieved later through the shared `/api/exports` endpoints."
)

FINANCIAL_ENTRY_EXAMPLE = {
    "summary": "Created manual entry",
    "value": {
        "id": 123,
        "created_by_user_id": 42,
        "entry_type": "income",
        "classification": "fixed",
        "description": "Monthly package",
        "amount": "50.00",
        "occurred_on": "2026-03-17",
        "notes": "Recurring service fee",
        "is_reversed": False,
        "reversed_at": None,
        "reversed_by_user_id": None,
        "reversal_reason": None,
        "created_at": "2026-03-17T12:00:00Z",
        "updated_at": "2026-03-17T12:00:00Z",
    },
}

FINANCIAL_ENTRY_LIST_EXAMPLE = {
    "summary": "Paginated manual entries",
    "value": {
        "entries": [FINANCIAL_ENTRY_EXAMPLE["value"]],
        "total": 1,
        "page": 1,
        "page_size": 50,
    },
}

FINANCE_REPORT_EXAMPLE = {
    "summary": "Daily report",
    "value": {
        "view": "day",
        "range_start": "2026-03-17",
        "range_end": "2026-03-17",
        "automatic_income_total": "200.00",
        "manual_income_total": "50.00",
        "manual_expense_total": "30.00",
        "total_income": "250.00",
        "total_expense": "30.00",
        "net_total": "220.00",
        "paid_appointments_count": 1,
        "manual_income_count": 1,
        "manual_expense_count": 1,
    },
}

FINANCE_EXPORT_EXAMPLE = {
    "summary": "Queued finance export job",
    "value": {
        "id": "5f8f3b9c-8c8f-4d7e-a6c1-0a4f4d7c7001",
        "kind": "finance_report_pdf",
        "status": "queued",
        "progress_current": 0,
        "progress_total": 1,
        "progress_message": "Queued for processing",
        "download_url": None,
        "error_detail": None,
        "created_at": "2026-03-17T12:00:00Z",
        "updated_at": "2026-03-17T12:00:00Z",
    },
}

CREATE_FINANCIAL_ENTRY_RESPONSES: OpenAPIResponses = {
    200: {
        "model": FinancialEntryResponse,
        "description": "The manual financial entry was created for the current tenant.",
        "content": {"application/json": {"examples": {"default": FINANCIAL_ENTRY_EXAMPLE}}},
    },
    401: {
        "model": FinanceErrorResponse,
        "description": "A valid bearer token is required.",
    },
    403: {
        "model": FinanceErrorResponse,
        "description": "The authenticated user is not assigned to the requested tenant.",
    },
}

LIST_FINANCIAL_ENTRIES_RESPONSES: OpenAPIResponses = {
    200: {
        "model": FinancialEntryListResponse,
        "description": "The current tenant's manual entries were returned with the active filter set.",
        "content": {"application/json": {"examples": {"default": FINANCIAL_ENTRY_LIST_EXAMPLE}}},
    },
    400: {
        "model": FinanceErrorResponse,
        "description": "The supplied date window is invalid.",
        "content": {
            "application/json": {
                "examples": {
                    "missing_range": {
                        "summary": "Incomplete custom range",
                        "value": {"detail": "custom view requires both start_date and end_date"},
                    },
                    "invalid_range": {
                        "summary": "Invalid date order",
                        "value": {"detail": "end_date must be greater than or equal to start_date"},
                    },
                }
            }
        },
    },
    401: {
        "model": FinanceErrorResponse,
        "description": "A valid bearer token is required.",
    },
    403: {
        "model": FinanceErrorResponse,
        "description": "The authenticated user is not assigned to the requested tenant.",
    },
}

GET_FINANCIAL_ENTRY_RESPONSES: OpenAPIResponses = {
    200: {
        "model": FinancialEntryResponse,
        "description": "The requested manual entry was found in the current tenant.",
        "content": {"application/json": {"examples": {"default": FINANCIAL_ENTRY_EXAMPLE}}},
    },
    401: {
        "model": FinanceErrorResponse,
        "description": "A valid bearer token is required.",
    },
    403: {
        "model": FinanceErrorResponse,
        "description": "The authenticated user is not assigned to the requested tenant.",
    },
    404: {
        "model": FinanceErrorResponse,
        "description": "The entry id does not exist in the current tenant.",
    },
}

REVERSE_FINANCIAL_ENTRY_RESPONSES: OpenAPIResponses = {
    200: {
        "model": FinancialEntryResponse,
        "description": "The manual entry was reversed and returned with the new reversal metadata.",
        "content": {"application/json": {"examples": {"default": FINANCIAL_ENTRY_EXAMPLE}}},
    },
    401: {
        "model": FinanceErrorResponse,
        "description": "A valid bearer token is required.",
    },
    403: {
        "model": FinanceErrorResponse,
        "description": "The authenticated user is not assigned to the requested tenant.",
    },
    404: {
        "model": FinanceErrorResponse,
        "description": "The entry id does not exist in the current tenant.",
    },
    409: {
        "model": FinanceErrorResponse,
        "description": "The entry was already reversed.",
    },
}

FINANCE_REPORT_RESPONSES: OpenAPIResponses = {
    200: {
        "model": FinanceReportResponse,
        "description": "The aggregated finance summary for the selected time window.",
        "content": {"application/json": {"examples": {"default": FINANCE_REPORT_EXAMPLE}}},
    },
    400: {
        "model": FinanceErrorResponse,
        "description": "The requested report window is invalid or incomplete.",
        "content": {
            "application/json": {
                "examples": {
                    "missing_range": {
                        "summary": "Incomplete custom range",
                        "value": {"detail": "custom view requires both start_date and end_date"},
                    },
                    "invalid_range": {
                        "summary": "Invalid date order",
                        "value": {"detail": "end_date must be greater than or equal to start_date"},
                    },
                }
            }
        },
    },
    401: {
        "model": FinanceErrorResponse,
        "description": "A valid bearer token is required.",
    },
    403: {
        "model": FinanceErrorResponse,
        "description": "The authenticated user is not assigned to the requested tenant.",
    },
}

EXPORT_FINANCE_REPORT_RESPONSES: OpenAPIResponses = {
    202: {
        "model": ExportJobResponse,
        "description": "The finance report export job was accepted for asynchronous processing.",
        "content": {"application/json": {"examples": {"default": FINANCE_EXPORT_EXAMPLE}}},
    },
    400: {
        "model": FinanceErrorResponse,
        "description": "The requested export window is invalid or incomplete.",
        "content": {
            "application/json": {
                "examples": {
                    "missing_range": {
                        "summary": "Incomplete custom range",
                        "value": {"detail": "custom view requires both start_date and end_date"},
                    },
                    "invalid_range": {
                        "summary": "Invalid date order",
                        "value": {"detail": "end_date must be greater than or equal to start_date"},
                    },
                }
            }
        },
    },
    401: {
        "model": FinanceErrorResponse,
        "description": "A valid bearer token is required.",
    },
    403: {
        "model": FinanceErrorResponse,
        "description": "The authenticated user is not assigned to the requested tenant.",
    },
}

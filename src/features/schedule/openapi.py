"""OpenAPI metadata for schedule routes."""

from typing import Any

from pydantic import BaseModel, Field

from .schemas import (
    AppointmentModality,
    AppointmentStatus,
    PaymentStatus,
    ScheduleAppointmentDetailResponse,
    ScheduleAppointmentListResponse,
    ScheduleAppointmentResponse,
    ScheduleAvailabilityResponse,
    ScheduleDefaultsResponse,
)

OpenAPIResponse = dict[str, Any]
OpenAPIResponses = dict[int | str, OpenAPIResponse]


class ScheduleErrorResponse(BaseModel):
    """Error payload returned by schedule routes."""

    detail: str = Field(..., description="Human-readable error message returned by the API.")


class ScheduleMessageResponse(BaseModel):
    """Simple message payload returned by destructive schedule routes."""

    message: str = Field(..., description="Human-readable status message returned by the API.")


SCHEDULE_COMMON_RESPONSES: OpenAPIResponses = {
    400: {
        "model": ScheduleErrorResponse,
        "description": "The request is malformed or violates a schedule-specific validation rule.",
    },
    401: {
        "model": ScheduleErrorResponse,
        "description": "The bearer token is missing, expired, or otherwise invalid.",
    },
    403: {
        "model": ScheduleErrorResponse,
        "description": "The authenticated user is not active, locked, or not assigned to the requested tenant.",
    },
    422: {
        "description": "FastAPI could not validate the request body, query string, or path parameters.",
    },
}

CREATE_APPOINTMENT_DESCRIPTION = (
    "Creates a tenant-scoped consultation appointment after validating the tenant schedule configuration, "
    "the target patient, and the requested time window. The service rejects past start times, overlapping "
    "appointments, and invalid end times. When `ends_at` is omitted, the configured appointment duration is "
    "used. The response includes the persisted finance snapshot and out-of-schedule warning fields."
)

LIST_APPOINTMENTS_DESCRIPTION = (
    "Lists appointments for the current tenant using overlap-based date filtering. The `view` parameter "
    "controls the date range semantics: `day`, `week`, `month`, or `custom`. Custom views require both "
    "`start_date` and `end_date`, and the service returns only appointments that intersect the selected window."
)

DETAIL_APPOINTMENT_DESCRIPTION = (
    "Returns one appointment with its timeline history. Deleted appointments stay hidden unless "
    "`include_deleted=true` is supplied, and the history payload is returned newest-first so the frontend "
    "can render the latest lifecycle change immediately."
)

UPDATE_APPOINTMENT_DESCRIPTION = (
    "Updates mutable appointment fields and handles rescheduling automatically when the start or end datetime "
    "changes. The service preserves the previous duration when only `starts_at` is sent, rejects time travel, "
    "blocks terminal-status reschedules, and refreshes the finance snapshot when it is still mutable."
)

UPDATE_STATUS_DESCRIPTION = (
    "Moves an appointment through the allowed consultation status transitions. `scheduled` and `rescheduled` "
    "cannot be set manually, and terminal statuses such as `canceled` and `completed` cannot be reopened. "
    "When cancellation is paired with `mark_as_not_charged=true`, the payment status is also rewritten."
)

UPDATE_PAYMENT_DESCRIPTION = (
    "Changes only the payment status while keeping the consultation status untouched. The service is a no-op "
    "when the target status matches the current status, otherwise it updates `paid_at` and writes a history event."
)

DELETE_APPOINTMENT_DESCRIPTION = (
    "Soft-deletes an appointment after explicit confirmation. The record is retained for history and audit "
    "purposes, but it is hidden from normal list/detail flows unless `include_deleted=true` is used."
)

DEFAULTS_DESCRIPTION = (
    "Returns the tenant's scheduling defaults as configured in `schedule_configurations`. The payload combines "
    "the tenant's working hours with the fixed defaults used by new appointments, including scheduled status, "
    "pending payment status, and in-person modality."
)

AVAILABILITY_DESCRIPTION = (
    "Calculates the free appointment slots for one date using the tenant schedule configuration and the current "
    "appointment occupancy. Non-working days return `working_day=false` with an empty slot list. The optional "
    "slot and break values override tenant defaults for the calculation only."
)

APPOINTMENT_VALUE: dict[str, Any] = {
    "id": 101,
    "patient_id": 22,
    "schedule_configuration_id": 7,
    "created_by_user_id": 5,
    "starts_at": "2026-03-22T14:00:00Z",
    "ends_at": "2026-03-22T14:50:00Z",
    "modality": AppointmentModality.IN_PERSON.value,
    "status": AppointmentStatus.SCHEDULED.value,
    "payment_status": PaymentStatus.PENDING.value,
    "notes": "Initial consultation",
    "price_override": None,
    "charge_amount": "200.00",
    "paid_at": None,
    "allow_canceled_report": False,
    "out_of_schedule_warning": False,
    "out_of_schedule_warning_reason": None,
    "is_deleted": False,
    "deleted_at": None,
    "deleted_reason": None,
    "deleted_by_user_id": None,
    "created_at": "2026-03-21T12:00:00Z",
    "updated_at": "2026-03-21T12:00:00Z",
}

APPOINTMENT_EXAMPLE = {
    "summary": "Scheduled appointment",
    "value": APPOINTMENT_VALUE,
}

APPOINTMENT_DETAIL_EXAMPLE = {
    "summary": "Appointment detail with timeline",
    "value": {
        **APPOINTMENT_VALUE,
        "history": [
            {
                "id": 901,
                "appointment_id": 101,
                "changed_by_user_id": 5,
                "event_type": "created",
                "reason": None,
                "from_status": None,
                "to_status": "scheduled",
                "from_payment_status": None,
                "to_payment_status": "pending",
                "from_starts_at": None,
                "to_starts_at": "2026-03-22T14:00:00Z",
                "change_summary": {
                    "starts_at": {"from": None, "to": "2026-03-22T14:00:00Z"},
                    "ends_at": {"from": None, "to": "2026-03-22T14:50:00Z"},
                    "modality": {"from": None, "to": "in_person"},
                },
                "is_reschedule": False,
                "created_at": "2026-03-21T12:00:00Z",
            }
        ],
    },
}

APPOINTMENT_LIST_EXAMPLE = {
    "summary": "Paginated appointment list",
    "value": {
        "appointments": [APPOINTMENT_EXAMPLE["value"]],
        "total": 1,
        "page": 1,
        "page_size": 50,
    },
}

DEFAULTS_EXAMPLE = {
    "summary": "Tenant schedule defaults",
    "value": {
        "configuration_id": 7,
        "working_days": ["monday", "tuesday", "wednesday", "thursday", "friday"],
        "start_time": "08:00:00",
        "end_time": "18:00:00",
        "appointment_duration_minutes": 50,
        "break_between_appointments_minutes": 10,
        "default_status": AppointmentStatus.SCHEDULED.value,
        "default_payment_status": PaymentStatus.PENDING.value,
        "default_modality": AppointmentModality.IN_PERSON.value,
    },
}

AVAILABILITY_EXAMPLE = {
    "summary": "Daily availability",
    "value": {
        "date": "2026-03-22",
        "working_day": True,
        "slot_duration_minutes": 50,
        "break_between_appointments_minutes": 10,
        "available_slots": [
            {"starts_at": "2026-03-22T08:00:00Z", "ends_at": "2026-03-22T08:50:00Z"},
            {"starts_at": "2026-03-22T09:00:00Z", "ends_at": "2026-03-22T09:50:00Z"},
        ],
    },
}

MESSAGE_EXAMPLE = {
    "summary": "Operation completed",
    "value": {"message": "Appointment deleted successfully"},
}

CREATE_APPOINTMENT_RESPONSES: OpenAPIResponses = {
    **SCHEDULE_COMMON_RESPONSES,
    200: {
        "model": ScheduleAppointmentResponse,
        "description": "The appointment was created and persisted for the current tenant.",
        "content": {"application/json": {"examples": {"created": APPOINTMENT_EXAMPLE}}},
    },
    404: {
        "model": ScheduleErrorResponse,
        "description": "The requested patient does not exist in the current tenant.",
    },
    409: {
        "model": ScheduleErrorResponse,
        "description": (
            "The tenant is missing a schedule configuration, the patient is inactive, or the time slot is already "
            "occupied."
        ),
    },
}

LIST_APPOINTMENTS_RESPONSES: OpenAPIResponses = {
    **SCHEDULE_COMMON_RESPONSES,
    200: {
        "model": ScheduleAppointmentListResponse,
        "description": "The appointment window was resolved and the matching appointments were returned.",
        "content": {"application/json": {"examples": {"default": APPOINTMENT_LIST_EXAMPLE}}},
    },
    400: {
        "model": ScheduleErrorResponse,
        "description": "The custom range is incomplete or inconsistent for the selected calendar view.",
    },
}

DETAIL_APPOINTMENT_RESPONSES: OpenAPIResponses = {
    **SCHEDULE_COMMON_RESPONSES,
    200: {
        "model": ScheduleAppointmentDetailResponse,
        "description": "The appointment and its history timeline were loaded from the current tenant.",
        "content": {"application/json": {"examples": {"default": APPOINTMENT_DETAIL_EXAMPLE}}},
    },
    404: {
        "model": ScheduleErrorResponse,
        "description": "The appointment does not exist in the current tenant scope.",
    },
}

UPDATE_APPOINTMENT_RESPONSES: OpenAPIResponses = {
    **SCHEDULE_COMMON_RESPONSES,
    200: {
        "model": ScheduleAppointmentResponse,
        "description": "The appointment was updated, and reschedule semantics were applied when needed.",
        "content": {"application/json": {"examples": {"updated": APPOINTMENT_EXAMPLE}}},
    },
    404: {
        "model": ScheduleErrorResponse,
        "description": "The appointment or replacement patient does not exist in the current tenant.",
    },
    409: {
        "model": ScheduleErrorResponse,
        "description": (
            "The tenant is missing a schedule configuration, the replacement patient is inactive, the new window "
            "conflicts with another appointment, or the update attempts to reschedule a terminal appointment."
        ),
    },
}

UPDATE_STATUS_RESPONSES: OpenAPIResponses = {
    **SCHEDULE_COMMON_RESPONSES,
    200: {
        "model": ScheduleAppointmentResponse,
        "description": "The appointment status transition was accepted and recorded in the timeline.",
        "content": {"application/json": {"examples": {"status_changed": APPOINTMENT_EXAMPLE}}},
    },
    404: {
        "model": ScheduleErrorResponse,
        "description": "The appointment does not exist in the current tenant scope.",
    },
    409: {
        "model": ScheduleErrorResponse,
        "description": "The requested status transition is not allowed from the appointment's current state.",
    },
}

UPDATE_PAYMENT_RESPONSES: OpenAPIResponses = {
    **SCHEDULE_COMMON_RESPONSES,
    200: {
        "model": ScheduleAppointmentResponse,
        "description": "The appointment payment status was updated and the timeline was recorded.",
        "content": {"application/json": {"examples": {"payment_changed": APPOINTMENT_EXAMPLE}}},
    },
    404: {
        "model": ScheduleErrorResponse,
        "description": "The appointment does not exist in the current tenant scope.",
    },
}

DELETE_APPOINTMENT_RESPONSES: OpenAPIResponses = {
    **SCHEDULE_COMMON_RESPONSES,
    200: {
        "model": ScheduleMessageResponse,
        "description": "The appointment was soft-deleted and the caller received a confirmation message.",
        "content": {"application/json": {"examples": {"deleted": MESSAGE_EXAMPLE}}},
    },
    404: {
        "model": ScheduleErrorResponse,
        "description": "The appointment does not exist in the current tenant scope.",
    },
    409: {
        "model": ScheduleErrorResponse,
        "description": "The appointment was already deleted or the delete request is otherwise rejected.",
    },
}

DEFAULTS_RESPONSES: OpenAPIResponses = {
    **SCHEDULE_COMMON_RESPONSES,
    200: {
        "model": ScheduleDefaultsResponse,
        "description": "The tenant's scheduling defaults were loaded from the active schedule configuration.",
        "content": {"application/json": {"examples": {"default": DEFAULTS_EXAMPLE}}},
    },
    409: {
        "model": ScheduleErrorResponse,
        "description": "The tenant does not yet have a schedule configuration.",
    },
}

AVAILABILITY_RESPONSES: OpenAPIResponses = {
    **SCHEDULE_COMMON_RESPONSES,
    200: {
        "model": ScheduleAvailabilityResponse,
        "description": "Available slots for the requested date were calculated from the tenant schedule.",
        "content": {"application/json": {"examples": {"default": AVAILABILITY_EXAMPLE}}},
    },
    409: {
        "model": ScheduleErrorResponse,
        "description": "The tenant does not yet have a schedule configuration.",
    },
}

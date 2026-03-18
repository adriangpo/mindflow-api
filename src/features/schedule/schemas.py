"""Schedule schemas (DTOs)."""

from datetime import UTC, date, datetime, time
from decimal import Decimal
from enum import StrEnum

from pydantic import BaseModel, Field, field_validator, model_validator

from src.features.schedule_config.schemas import WeekDay


class AppointmentStatus(StrEnum):
    """Supported appointment lifecycle states."""

    SCHEDULED = "scheduled"
    CANCELED = "canceled"
    NO_SHOW = "no_show"
    COMPLETED = "completed"
    RESCHEDULED = "rescheduled"


class PaymentStatus(StrEnum):
    """Supported payment states for an appointment."""

    PAID = "paid"
    PENDING = "pending"
    NOT_CHARGED = "not_charged"


class AppointmentModality(StrEnum):
    """Consultation modality options."""

    IN_PERSON = "in_person"
    ONLINE = "online"
    HOME_VISIT = "home_visit"
    HYBRID = "hybrid"
    OTHER = "other"


class ScheduleCalendarView(StrEnum):
    """Date-range views for appointment listing."""

    DAY = "day"
    WEEK = "week"
    MONTH = "month"
    CUSTOM = "custom"


class AppointmentHistoryEvent(StrEnum):
    """Appointment history event types."""

    CREATED = "created"
    UPDATED = "updated"
    STATUS_CHANGED = "status_changed"
    RESCHEDULED = "rescheduled"
    PAYMENT_STATUS_CHANGED = "payment_status_changed"
    DELETED = "deleted"


def _ensure_timezone_aware(value: datetime, *, field_name: str) -> datetime:
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    return value


class ScheduleAppointmentCreateRequest(BaseModel):
    """Create appointment request."""

    patient_id: int = Field(..., gt=0)
    starts_at: datetime
    ends_at: datetime | None = None
    modality: AppointmentModality
    notes: str | None = Field(default=None, max_length=5000)
    price_override: Decimal | None = Field(default=None, gt=0, max_digits=10, decimal_places=2)
    payment_status: PaymentStatus = PaymentStatus.PENDING
    allow_canceled_report: bool = False

    @field_validator("starts_at")
    @classmethod
    def _validate_starts_at(cls, value: datetime) -> datetime:
        return _ensure_timezone_aware(value, field_name="starts_at")

    @field_validator("ends_at")
    @classmethod
    def _validate_ends_at(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return value
        return _ensure_timezone_aware(value, field_name="ends_at")

    @model_validator(mode="after")
    def _validate_time_window(self):
        if self.ends_at is not None and self.starts_at >= self.ends_at:
            raise ValueError("starts_at must be earlier than ends_at")
        return self


class ScheduleAppointmentUpdateRequest(BaseModel):
    """Update appointment request."""

    patient_id: int | None = Field(default=None, gt=0)
    starts_at: datetime | None = None
    ends_at: datetime | None = None
    modality: AppointmentModality | None = None
    notes: str | None = Field(default=None, max_length=5000)
    price_override: Decimal | None = Field(default=None, gt=0, max_digits=10, decimal_places=2)
    payment_status: PaymentStatus | None = None
    allow_canceled_report: bool | None = None

    @field_validator("starts_at")
    @classmethod
    def _validate_starts_at(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return value
        return _ensure_timezone_aware(value, field_name="starts_at")

    @field_validator("ends_at")
    @classmethod
    def _validate_ends_at(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return value
        return _ensure_timezone_aware(value, field_name="ends_at")

    @model_validator(mode="after")
    def _validate_time_window(self):
        if self.starts_at is not None and self.ends_at is not None and self.starts_at >= self.ends_at:
            raise ValueError("starts_at must be earlier than ends_at")
        return self


class ScheduleAppointmentStatusUpdateRequest(BaseModel):
    """Appointment status update request."""

    status: AppointmentStatus
    reason: str | None = Field(default=None, max_length=500)
    mark_as_not_charged: bool = False

    @model_validator(mode="after")
    def _validate_status_change(self):
        if self.status == AppointmentStatus.SCHEDULED:
            raise ValueError("status 'scheduled' is only assigned automatically on creation")
        if self.status == AppointmentStatus.RESCHEDULED:
            raise ValueError("use appointment update endpoint to reschedule")
        return self


class ScheduleAppointmentPaymentStatusUpdateRequest(BaseModel):
    """Appointment payment status update request."""

    payment_status: PaymentStatus
    reason: str | None = Field(default=None, max_length=500)


class ScheduleAppointmentDeleteRequest(BaseModel):
    """Exceptional deletion request for appointments."""

    confirm: bool
    reason: str = Field(..., min_length=3, max_length=500)


class ScheduleAppointmentHistoryResponse(BaseModel):
    """Appointment history event response."""

    id: int
    appointment_id: int
    changed_by_user_id: int | None
    event_type: AppointmentHistoryEvent
    reason: str | None
    from_status: AppointmentStatus | None
    to_status: AppointmentStatus | None
    from_payment_status: PaymentStatus | None
    to_payment_status: PaymentStatus | None
    from_starts_at: datetime | None
    to_starts_at: datetime | None
    change_summary: dict[str, object] | None
    is_reschedule: bool
    created_at: datetime


class ScheduleAppointmentResponse(BaseModel):
    """Appointment response."""

    id: int
    patient_id: int
    schedule_configuration_id: int | None
    created_by_user_id: int
    starts_at: datetime
    ends_at: datetime
    modality: AppointmentModality
    status: AppointmentStatus
    payment_status: PaymentStatus
    notes: str | None
    price_override: Decimal | None
    charge_amount: Decimal
    paid_at: datetime | None
    allow_canceled_report: bool
    out_of_schedule_warning: bool
    out_of_schedule_warning_reason: str | None
    is_deleted: bool
    deleted_at: datetime | None
    deleted_reason: str | None
    deleted_by_user_id: int | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class ScheduleAppointmentDetailResponse(ScheduleAppointmentResponse):
    """Detailed appointment response with timeline."""

    history: list[ScheduleAppointmentHistoryResponse]


class ScheduleAppointmentListResponse(BaseModel):
    """Appointment list response."""

    appointments: list[ScheduleAppointmentResponse]
    total: int
    page: int
    page_size: int


class ScheduleDefaultsResponse(BaseModel):
    """Default scheduling values from tenant configuration."""

    configuration_id: int
    working_days: list[WeekDay]
    start_time: time
    end_time: time
    appointment_duration_minutes: int
    break_between_appointments_minutes: int
    default_status: AppointmentStatus = AppointmentStatus.SCHEDULED
    default_payment_status: PaymentStatus = PaymentStatus.PENDING
    default_modality: AppointmentModality = AppointmentModality.IN_PERSON


class ScheduleAvailabilitySlotResponse(BaseModel):
    """Available slot representation."""

    starts_at: datetime
    ends_at: datetime


class ScheduleAvailabilityResponse(BaseModel):
    """Available slots for a selected date."""

    date: date
    working_day: bool
    slot_duration_minutes: int
    break_between_appointments_minutes: int
    available_slots: list[ScheduleAvailabilitySlotResponse]


def default_reference_date() -> date:
    """Return current UTC date for default schedule listing."""
    return datetime.now(UTC).date()

"""Notification schemas (DTOs)."""

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field, field_validator, model_validator

PHONE_LENGTHS = {10, 11}
MAX_FAILURE_REASON_LENGTH = 500


def _validate_phone_number(value: str | None, *, field_name: str) -> str | None:
    if value is None:
        return value
    if not value.isdigit():
        raise ValueError(f"{field_name} must contain only digits")
    if len(value) not in PHONE_LENGTHS:
        lengths = ", ".join(str(item) for item in sorted(PHONE_LENGTHS))
        raise ValueError(f"{field_name} must have length {lengths}")
    return value


class NotificationChannel(StrEnum):
    """Supported delivery channels."""

    WHATSAPP = "whatsapp"


class NotificationRecipientType(StrEnum):
    """Supported notification recipient groups."""

    PATIENT = "patient"
    USER = "user"


class NotificationEventType(StrEnum):
    """Notification events emitted by the schedule feature."""

    APPOINTMENT_CREATED = "appointment_created"
    APPOINTMENT_UPDATED = "appointment_updated"
    APPOINTMENT_CANCELED = "appointment_canceled"
    APPOINTMENT_REMINDER = "appointment_reminder"


class NotificationMessageStatus(StrEnum):
    """Notification delivery states."""

    PENDING = "pending"
    SENT = "sent"
    FAILED = "failed"
    CANCELED = "canceled"


class NotificationSettingsUpdateRequest(BaseModel):
    """Notification settings upsert request."""

    patient_notifications_enabled: bool = True
    user_notifications_enabled: bool = True
    reminders_enabled: bool = True
    notify_on_create: bool = True
    notify_on_update: bool = True
    notify_on_cancel: bool = True
    default_reminder_minutes_before: int = Field(default=30, ge=1, le=10080)


class NotificationSettingsResponse(BaseModel):
    """Notification settings response."""

    id: int | None = None
    patient_notifications_enabled: bool
    user_notifications_enabled: bool
    reminders_enabled: bool
    notify_on_create: bool
    notify_on_update: bool
    notify_on_cancel: bool
    default_reminder_minutes_before: int
    created_at: datetime | None = None
    updated_at: datetime | None = None

    model_config = {"from_attributes": True}


class NotificationPatientPreferenceUpsertRequest(BaseModel):
    """Per-patient notification preference upsert request."""

    is_enabled: bool = True
    contact_phone: str | None = Field(default=None, min_length=min(PHONE_LENGTHS), max_length=max(PHONE_LENGTHS))
    reminder_minutes_before: int | None = Field(default=None, ge=1, le=10080)

    @field_validator("contact_phone")
    @classmethod
    def _validate_contact_phone(cls, value: str | None) -> str | None:
        return _validate_phone_number(value, field_name="contact_phone")


class NotificationPatientPreferenceResponse(BaseModel):
    """Per-patient notification preference response."""

    patient_id: int
    is_enabled: bool
    contact_phone: str | None
    reminder_minutes_before: int | None
    resolved_reminder_minutes_before: int
    has_preference: bool
    created_at: datetime | None = None
    updated_at: datetime | None = None


class NotificationUserProfileUpsertRequest(BaseModel):
    """Per-user notification profile upsert request."""

    is_enabled: bool = True
    contact_phone: str | None = Field(default=None, min_length=min(PHONE_LENGTHS), max_length=max(PHONE_LENGTHS))
    receive_appointment_notifications: bool = True
    receive_reminders: bool = True

    @field_validator("contact_phone")
    @classmethod
    def _validate_contact_phone(cls, value: str | None) -> str | None:
        return _validate_phone_number(value, field_name="contact_phone")

    @model_validator(mode="after")
    def _validate_contact_requirement(self):
        if (
            self.is_enabled
            and (self.receive_appointment_notifications or self.receive_reminders)
            and self.contact_phone is None
        ):
            raise ValueError("contact_phone is required when notification delivery is enabled")
        return self


class NotificationUserProfileResponse(BaseModel):
    """Per-user notification profile response."""

    user_id: int
    is_enabled: bool
    contact_phone: str | None
    receive_appointment_notifications: bool
    receive_reminders: bool
    has_profile: bool
    created_at: datetime | None = None
    updated_at: datetime | None = None


class NotificationMessageResponse(BaseModel):
    """Notification message response."""

    id: int
    appointment_id: int | None
    patient_id: int | None
    recipient_user_id: int | None
    recipient_type: NotificationRecipientType
    event_type: NotificationEventType
    channel: NotificationChannel
    status: NotificationMessageStatus
    destination: str
    content: str
    scheduled_for: datetime
    sent_at: datetime | None
    failed_at: datetime | None
    canceled_at: datetime | None
    attempt_count: int
    failure_reason: str | None
    provider_message_id: str | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class NotificationMessageListResponse(BaseModel):
    """Notification message list response."""

    messages: list[NotificationMessageResponse]
    total: int
    page: int
    page_size: int


class NotificationDispatchRequest(BaseModel):
    """Manual dispatch request for due notifications."""

    limit: int = Field(default=100, ge=1, le=1000)


class NotificationDispatchResponse(BaseModel):
    """Manual dispatch result summary."""

    processed_count: int
    sent_count: int
    failed_count: int

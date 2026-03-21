"""Notification domain models."""

from datetime import datetime

from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from src.database.base import Base, TenantMixin, TimestampMixin
from src.shared.audit.audit import AuditableMixin


class NotificationSettings(Base, TenantMixin, TimestampMixin, AuditableMixin):
    """Tenant-scoped notification settings."""

    __tablename__ = "notification_settings"
    __table_args__ = (
        UniqueConstraint("tenant_id", name="uq_notification_settings_tenant"),
        CheckConstraint(
            "default_reminder_minutes_before > 0",
            name="ck_notification_settings_default_reminder_positive",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    patient_notifications_enabled: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default="true",
    )
    user_notifications_enabled: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default="true",
    )
    reminders_enabled: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default="true",
    )
    notify_on_create: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default="true",
    )
    notify_on_update: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default="true",
    )
    notify_on_cancel: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default="true",
    )
    default_reminder_minutes_before: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=30,
        server_default="30",
    )


class NotificationPatientPreference(Base, TenantMixin, TimestampMixin, AuditableMixin):
    """Per-patient notification override."""

    __tablename__ = "notification_patient_preferences"
    __table_args__ = (
        UniqueConstraint("tenant_id", "patient_id", name="uq_notification_patient_preferences_tenant_patient"),
        CheckConstraint(
            "reminder_minutes_before IS NULL OR reminder_minutes_before > 0",
            name="ck_notification_patient_preferences_reminder_positive",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    patient_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("patients.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    is_enabled: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default="true",
    )
    contact_phone: Mapped[str | None] = mapped_column(String(11), nullable=True)
    reminder_minutes_before: Mapped[int | None] = mapped_column(Integer, nullable=True)


class NotificationUserProfile(Base, TenantMixin, TimestampMixin, AuditableMixin):
    """Per-user notification contact configuration within a tenant."""

    __tablename__ = "notification_user_profiles"
    __table_args__ = (UniqueConstraint("tenant_id", "user_id", name="uq_notification_user_profiles_tenant_user"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    user_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    is_enabled: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default="true",
    )
    contact_phone: Mapped[str | None] = mapped_column(String(11), nullable=True)
    receive_appointment_notifications: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default="true",
    )
    receive_reminders: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default="true",
    )


class NotificationMessage(Base, TenantMixin, TimestampMixin):
    """Tenant-scoped notification outbox and delivery log."""

    __tablename__ = "notification_messages"
    __table_args__ = (
        CheckConstraint("attempt_count >= 0", name="ck_notification_messages_attempt_count_non_negative"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    appointment_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("schedule_appointments.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    patient_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("patients.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    recipient_user_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    recipient_type: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    channel: Mapped[str] = mapped_column(String(20), nullable=False, default="whatsapp", server_default="whatsapp")
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="pending",
        server_default="pending",
        index=True,
    )

    destination: Mapped[str] = mapped_column(String(11), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    scheduled_for: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)

    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    failed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    canceled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    failure_reason: Mapped[str | None] = mapped_column(String(500), nullable=True)
    provider_message_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    qstash_message_id: Mapped[str | None] = mapped_column(String(100), nullable=True)

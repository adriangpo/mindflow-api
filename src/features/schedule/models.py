"""Schedule domain models."""

from datetime import datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, Integer, Numeric, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from src.database.base import Base, TenantMixin, TimestampMixin
from src.shared.audit.audit import AuditableMixin


class ScheduleAppointment(Base, TenantMixin, TimestampMixin, AuditableMixin):
    """Tenant-scoped consultation appointment model."""

    __tablename__ = "schedule_appointments"
    __table_args__ = (CheckConstraint("starts_at < ends_at", name="ck_schedule_appointments_time_window"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    patient_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("patients.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    schedule_configuration_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("schedule_configurations.id", ondelete="SET NULL"),
        nullable=True,
    )
    created_by_user_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )

    starts_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    ends_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    modality: Mapped[str] = mapped_column(String(30), nullable=False)
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="scheduled", server_default="scheduled")
    payment_status: Mapped[str] = mapped_column(String(30), nullable=False, default="pending", server_default="pending")

    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    price_override: Mapped[Decimal | None] = mapped_column(Numeric(10, 2), nullable=True)
    charge_amount: Mapped[Decimal] = mapped_column(
        Numeric(10, 2),
        nullable=False,
        default=Decimal("0.00"),
        server_default="0.00",
    )
    paid_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)

    allow_canceled_report: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default="false",
    )

    out_of_schedule_warning: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default="false",
    )
    out_of_schedule_warning_reason: Mapped[str | None] = mapped_column(String(500), nullable=True)

    is_deleted: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default="false",
        index=True,
    )
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    deleted_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    deleted_by_user_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )


class ScheduleAppointmentHistory(Base, TenantMixin, TimestampMixin):
    """Immutable timeline events for appointment lifecycle."""

    __tablename__ = "schedule_appointment_history"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    appointment_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("schedule_appointments.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    changed_by_user_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    event_type: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    from_status: Mapped[str | None] = mapped_column(String(30), nullable=True)
    to_status: Mapped[str | None] = mapped_column(String(30), nullable=True)

    from_payment_status: Mapped[str | None] = mapped_column(String(30), nullable=True)
    to_payment_status: Mapped[str | None] = mapped_column(String(30), nullable=True)

    from_starts_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    to_starts_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    change_summary: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)

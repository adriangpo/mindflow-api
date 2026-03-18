"""Schedule service layer."""

from datetime import UTC, date, datetime, time, timedelta
from decimal import Decimal
from enum import Enum
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.features.patient.models import Patient
from src.features.schedule_config.models import ScheduleConfiguration
from src.shared.pagination.pagination import PaginationParams

from .exceptions import (
    ScheduleAppointmentAlreadyDeleted,
    ScheduleAppointmentInPast,
    ScheduleAppointmentNotFound,
    ScheduleConfigurationRequired,
    ScheduleCustomRangeRequired,
    ScheduleDeleteConfirmationRequired,
    ScheduleInvalidCustomRange,
    ScheduleInvalidStatusTransition,
    ScheduleInvalidTimeWindow,
    SchedulePatientInactive,
    SchedulePatientNotFound,
    ScheduleSlotUnavailable,
)
from .models import ScheduleAppointment, ScheduleAppointmentHistory
from .schemas import (
    AppointmentHistoryEvent,
    AppointmentStatus,
    PaymentStatus,
    ScheduleAppointmentCreateRequest,
    ScheduleAppointmentDeleteRequest,
    ScheduleAppointmentStatusUpdateRequest,
    ScheduleAppointmentUpdateRequest,
    ScheduleAvailabilitySlotResponse,
    ScheduleCalendarView,
)

ZERO_AMOUNT = Decimal("0.00")

_STATUS_TRANSITIONS: dict[AppointmentStatus, set[AppointmentStatus]] = {
    AppointmentStatus.SCHEDULED: {
        AppointmentStatus.CANCELED,
        AppointmentStatus.NO_SHOW,
        AppointmentStatus.COMPLETED,
    },
    AppointmentStatus.RESCHEDULED: {
        AppointmentStatus.CANCELED,
        AppointmentStatus.NO_SHOW,
        AppointmentStatus.COMPLETED,
    },
    AppointmentStatus.CANCELED: set(),
    AppointmentStatus.NO_SHOW: {
        AppointmentStatus.CANCELED,
        AppointmentStatus.COMPLETED,
    },
    AppointmentStatus.COMPLETED: set(),
}

_TERMINAL_APPOINTMENT_STATUSES: set[AppointmentStatus] = {
    AppointmentStatus.CANCELED,
    AppointmentStatus.COMPLETED,
}


def _jsonable(value: Any) -> Any:
    """Serialize values for history JSON payloads."""
    if isinstance(value, datetime | date | time):
        return value.isoformat()
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, Enum):
        return value.value
    return value


class ScheduleService:
    """Service for schedule and appointment operations."""

    @staticmethod
    def _require_tenant_id(session: AsyncSession):
        tenant_id = session.info.get("tenant_id")
        if tenant_id is None:
            raise RuntimeError("Tenant context is required for schedule operations")
        return tenant_id

    @staticmethod
    async def _require_schedule_configuration(session: AsyncSession) -> ScheduleConfiguration:
        tenant_id = ScheduleService._require_tenant_id(session)
        stmt = select(ScheduleConfiguration).where(ScheduleConfiguration.tenant_id == tenant_id)
        result = await session.execute(stmt)
        configuration = result.scalar_one_or_none()
        if configuration is None:
            raise ScheduleConfigurationRequired()
        return configuration

    @staticmethod
    async def _require_patient(session: AsyncSession, patient_id: int) -> Patient:
        tenant_id = ScheduleService._require_tenant_id(session)
        stmt = select(Patient).where(
            Patient.id == patient_id,
            Patient.tenant_id == tenant_id,
        )
        result = await session.execute(stmt)
        patient = result.scalar_one_or_none()
        if patient is None:
            raise SchedulePatientNotFound()
        if not patient.is_active:
            raise SchedulePatientInactive()
        return patient

    @staticmethod
    def _resolve_charge_amount(
        patient: Patient,
        *,
        price_override: Decimal | None,
    ) -> Decimal:
        """Resolve the financial amount snapshot for an appointment."""
        if price_override is not None:
            return price_override
        if patient.session_price is not None:
            return patient.session_price
        return ZERO_AMOUNT

    @staticmethod
    def _sync_paid_at(appointment: ScheduleAppointment, *, previous_payment_status: str) -> None:
        """Keep paid_at aligned with payment status transitions."""
        if (
            appointment.payment_status == PaymentStatus.PAID.value
            and previous_payment_status != PaymentStatus.PAID.value
        ):
            appointment.paid_at = datetime.now(UTC)
        elif (
            appointment.payment_status != PaymentStatus.PAID.value
            and previous_payment_status == PaymentStatus.PAID.value
        ):
            appointment.paid_at = None

    @staticmethod
    def _resolve_range(
        view: ScheduleCalendarView,
        reference_date: date | None,
        start_date: date | None,
        end_date: date | None,
    ) -> tuple[datetime, datetime]:
        if view == ScheduleCalendarView.CUSTOM:
            if start_date is None or end_date is None:
                raise ScheduleCustomRangeRequired()
            if end_date < start_date:
                raise ScheduleInvalidCustomRange()
            start_dt = datetime.combine(start_date, time.min, tzinfo=UTC)
            end_dt = datetime.combine(end_date + timedelta(days=1), time.min, tzinfo=UTC)
            return start_dt, end_dt

        current = reference_date or datetime.now(UTC).date()
        if view == ScheduleCalendarView.DAY:
            start_dt = datetime.combine(current, time.min, tzinfo=UTC)
            end_dt = start_dt + timedelta(days=1)
            return start_dt, end_dt

        if view == ScheduleCalendarView.WEEK:
            week_start = current - timedelta(days=current.weekday())
            start_dt = datetime.combine(week_start, time.min, tzinfo=UTC)
            end_dt = start_dt + timedelta(days=7)
            return start_dt, end_dt

        month_start = current.replace(day=1)
        if month_start.month == 12:
            month_end = month_start.replace(year=month_start.year + 1, month=1, day=1)
        else:
            month_end = month_start.replace(month=month_start.month + 1, day=1)

        return (
            datetime.combine(month_start, time.min, tzinfo=UTC),
            datetime.combine(month_end, time.min, tzinfo=UTC),
        )

    @staticmethod
    def _out_of_schedule_reason(
        configuration: ScheduleConfiguration,
        starts_at: datetime,
        ends_at: datetime,
    ) -> str | None:
        reasons: list[str] = []

        weekday = starts_at.strftime("%A").lower()
        if weekday not in configuration.working_days:
            reasons.append("appointment day is outside configured working days")

        if starts_at.date() != ends_at.date():
            reasons.append("appointment crosses multiple dates")

        start_time = starts_at.timetz().replace(tzinfo=None)
        end_time = ends_at.timetz().replace(tzinfo=None)

        if start_time < configuration.start_time or end_time > configuration.end_time:
            reasons.append("appointment time is outside configured working hours")

        return "; ".join(reasons) if reasons else None

    @staticmethod
    async def _has_slot_conflict(
        session: AsyncSession,
        starts_at: datetime,
        ends_at: datetime,
        *,
        exclude_appointment_id: int | None = None,
    ) -> bool:
        tenant_id = ScheduleService._require_tenant_id(session)

        stmt = select(ScheduleAppointment.id).where(
            ScheduleAppointment.tenant_id == tenant_id,
            ScheduleAppointment.is_deleted.is_(False),
            ScheduleAppointment.status != AppointmentStatus.CANCELED.value,
            ScheduleAppointment.starts_at < ends_at,
            ScheduleAppointment.ends_at > starts_at,
        )

        if exclude_appointment_id is not None:
            stmt = stmt.where(ScheduleAppointment.id != exclude_appointment_id)

        result = await session.execute(stmt.limit(1))
        return result.scalar_one_or_none() is not None

    @staticmethod
    async def _add_history_event(
        session: AsyncSession,
        appointment: ScheduleAppointment,
        *,
        changed_by_user_id: int,
        event_type: AppointmentHistoryEvent,
        reason: str | None = None,
        from_status: str | None = None,
        to_status: str | None = None,
        from_payment_status: str | None = None,
        to_payment_status: str | None = None,
        from_starts_at: datetime | None = None,
        to_starts_at: datetime | None = None,
        change_summary: dict[str, Any] | None = None,
    ) -> ScheduleAppointmentHistory:
        tenant_id = ScheduleService._require_tenant_id(session)
        history = ScheduleAppointmentHistory(
            tenant_id=tenant_id,
            appointment_id=appointment.id,
            changed_by_user_id=changed_by_user_id,
            event_type=event_type.value,
            reason=reason,
            from_status=from_status,
            to_status=to_status,
            from_payment_status=from_payment_status,
            to_payment_status=to_payment_status,
            from_starts_at=from_starts_at,
            to_starts_at=to_starts_at,
            change_summary=change_summary,
        )
        session.add(history)
        await session.flush()
        return history

    @staticmethod
    def _build_change_summary(previous: dict[str, Any], current: dict[str, Any]) -> dict[str, dict[str, Any]]:
        """Build a change diff dictionary between previous and current values."""
        summary: dict[str, dict[str, Any]] = {}
        for key, old_value in previous.items():
            new_value = current.get(key)
            if old_value == new_value:
                continue
            summary[key] = {
                "from": _jsonable(old_value),
                "to": _jsonable(new_value),
            }
        return summary

    @staticmethod
    def _snapshot_appointment(appointment: ScheduleAppointment) -> dict[str, Any]:
        """Capture mutable appointment fields for history diffing."""
        return {
            "patient_id": appointment.patient_id,
            "starts_at": appointment.starts_at,
            "ends_at": appointment.ends_at,
            "modality": appointment.modality,
            "status": appointment.status,
            "payment_status": appointment.payment_status,
            "notes": appointment.notes,
            "price_override": appointment.price_override,
            "charge_amount": appointment.charge_amount,
            "paid_at": appointment.paid_at,
            "allow_canceled_report": appointment.allow_canceled_report,
            "out_of_schedule_warning": appointment.out_of_schedule_warning,
            "out_of_schedule_warning_reason": appointment.out_of_schedule_warning_reason,
        }

    @staticmethod
    def _resolve_updated_window(
        appointment: ScheduleAppointment,
        data: ScheduleAppointmentUpdateRequest,
    ) -> tuple[datetime, datetime, bool]:
        """Resolve appointment time window after partial update payload merge."""
        previous_duration = appointment.ends_at - appointment.starts_at

        starts_at = data.starts_at if data.starts_at is not None else appointment.starts_at
        if data.ends_at is not None:
            ends_at = data.ends_at
        elif data.starts_at is not None:
            ends_at = data.starts_at + previous_duration
        else:
            ends_at = appointment.ends_at

        time_changed = starts_at != appointment.starts_at or ends_at != appointment.ends_at
        return starts_at, ends_at, time_changed

    @staticmethod
    def _should_refresh_charge_amount(*, previous_payment_status: str, next_payment_status: str) -> bool:
        """Return whether the appointment finance snapshot is still mutable."""
        return previous_payment_status != PaymentStatus.PAID.value or next_payment_status != PaymentStatus.PAID.value

    @staticmethod
    def _refresh_charge_amount_from_updates(
        appointment: ScheduleAppointment,
        data: ScheduleAppointmentUpdateRequest,
        *,
        target_patient: Patient | None,
        previous_payment_status: str,
        next_payment_status: str,
    ) -> None:
        """Refresh charge_amount when mutable finance inputs change."""
        if not ScheduleService._should_refresh_charge_amount(
            previous_payment_status=previous_payment_status,
            next_payment_status=next_payment_status,
        ):
            return

        if data.price_override is not None:
            appointment.charge_amount = data.price_override
            return

        if data.patient_id is not None and appointment.price_override is None and target_patient is not None:
            appointment.charge_amount = target_patient.session_price or ZERO_AMOUNT

    @staticmethod
    def _apply_appointment_updates(
        appointment: ScheduleAppointment,
        data: ScheduleAppointmentUpdateRequest,
        *,
        starts_at: datetime,
        ends_at: datetime,
        time_changed: bool,
        configuration: ScheduleConfiguration,
        target_patient: Patient | None,
    ) -> None:
        """Apply mutable update fields to an appointment instance."""
        previous_payment_status = appointment.payment_status
        next_payment_status = (
            data.payment_status.value if data.payment_status is not None else appointment.payment_status
        )

        if data.patient_id is not None:
            appointment.patient_id = data.patient_id

        appointment.starts_at = starts_at
        appointment.ends_at = ends_at

        if data.modality is not None:
            appointment.modality = data.modality.value
        if data.notes is not None:
            appointment.notes = data.notes
        if data.price_override is not None:
            appointment.price_override = data.price_override
        if data.payment_status is not None:
            appointment.payment_status = next_payment_status
        if data.allow_canceled_report is not None:
            appointment.allow_canceled_report = data.allow_canceled_report

        ScheduleService._refresh_charge_amount_from_updates(
            appointment,
            data,
            target_patient=target_patient,
            previous_payment_status=previous_payment_status,
            next_payment_status=next_payment_status,
        )
        ScheduleService._sync_paid_at(appointment, previous_payment_status=previous_payment_status)

        if not time_changed:
            return

        appointment.status = AppointmentStatus.RESCHEDULED.value
        warning_reason = ScheduleService._out_of_schedule_reason(configuration, starts_at, ends_at)
        appointment.out_of_schedule_warning = warning_reason is not None
        appointment.out_of_schedule_warning_reason = warning_reason

    @staticmethod
    def _resolve_update_event_type(
        change_summary: dict[str, dict[str, Any]],
        *,
        time_changed: bool,
        previous_payment_status: str,
        current_payment_status: str,
    ) -> AppointmentHistoryEvent:
        """Resolve history event type for appointment update operations."""
        if time_changed:
            return AppointmentHistoryEvent.RESCHEDULED
        if set(change_summary.keys()).issubset({"payment_status", "paid_at"}) and (
            previous_payment_status != current_payment_status
        ):
            return AppointmentHistoryEvent.PAYMENT_STATUS_CHANGED
        return AppointmentHistoryEvent.UPDATED

    @staticmethod
    async def create_appointment(
        session: AsyncSession,
        user_id: int,
        data: ScheduleAppointmentCreateRequest,
    ) -> ScheduleAppointment:
        """Create an appointment with slot validation and history tracking."""
        configuration = await ScheduleService._require_schedule_configuration(session)
        patient = await ScheduleService._require_patient(session, data.patient_id)

        starts_at = data.starts_at
        ends_at = data.ends_at or starts_at + timedelta(minutes=configuration.appointment_duration_minutes)

        if ends_at <= starts_at:
            raise ScheduleInvalidTimeWindow()

        if starts_at <= datetime.now(UTC):
            raise ScheduleAppointmentInPast()

        if await ScheduleService._has_slot_conflict(session, starts_at, ends_at):
            raise ScheduleSlotUnavailable()

        warning_reason = ScheduleService._out_of_schedule_reason(configuration, starts_at, ends_at)

        appointment = ScheduleAppointment(
            tenant_id=ScheduleService._require_tenant_id(session),
            patient_id=data.patient_id,
            schedule_configuration_id=configuration.id,
            created_by_user_id=user_id,
            starts_at=starts_at,
            ends_at=ends_at,
            modality=data.modality.value,
            status=AppointmentStatus.SCHEDULED.value,
            payment_status=data.payment_status.value,
            notes=data.notes,
            price_override=data.price_override,
            charge_amount=ScheduleService._resolve_charge_amount(patient, price_override=data.price_override),
            paid_at=datetime.now(UTC) if data.payment_status == PaymentStatus.PAID else None,
            allow_canceled_report=data.allow_canceled_report,
            out_of_schedule_warning=warning_reason is not None,
            out_of_schedule_warning_reason=warning_reason,
        )
        session.add(appointment)
        await session.flush()

        await ScheduleService._add_history_event(
            session,
            appointment,
            changed_by_user_id=user_id,
            event_type=AppointmentHistoryEvent.CREATED,
            to_status=appointment.status,
            to_payment_status=appointment.payment_status,
            to_starts_at=appointment.starts_at,
            change_summary={
                "starts_at": {"from": None, "to": appointment.starts_at.isoformat()},
                "ends_at": {"from": None, "to": appointment.ends_at.isoformat()},
                "modality": {"from": None, "to": appointment.modality},
            },
        )

        return appointment

    @staticmethod
    async def list_appointments(
        session: AsyncSession,
        pagination: PaginationParams,
        *,
        view: ScheduleCalendarView,
        reference_date: date | None,
        start_date: date | None,
        end_date: date | None,
        patient_id: int | None,
        statuses: list[AppointmentStatus] | None,
        payment_statuses: list[PaymentStatus] | None,
        include_deleted: bool,
    ) -> tuple[list[ScheduleAppointment], int]:
        """List appointments by date range view and optional filters."""
        tenant_id = ScheduleService._require_tenant_id(session)
        range_start, range_end = ScheduleService._resolve_range(view, reference_date, start_date, end_date)

        count_stmt = (
            select(func.count())
            .select_from(ScheduleAppointment)
            .where(
                ScheduleAppointment.tenant_id == tenant_id,
                ScheduleAppointment.starts_at < range_end,
                ScheduleAppointment.ends_at > range_start,
            )
        )

        stmt = select(ScheduleAppointment).where(
            ScheduleAppointment.tenant_id == tenant_id,
            ScheduleAppointment.starts_at < range_end,
            ScheduleAppointment.ends_at > range_start,
        )

        if not include_deleted:
            count_stmt = count_stmt.where(ScheduleAppointment.is_deleted.is_(False))
            stmt = stmt.where(ScheduleAppointment.is_deleted.is_(False))

        if patient_id is not None:
            count_stmt = count_stmt.where(ScheduleAppointment.patient_id == patient_id)
            stmt = stmt.where(ScheduleAppointment.patient_id == patient_id)

        if statuses:
            status_values = [status.value for status in statuses]
            count_stmt = count_stmt.where(ScheduleAppointment.status.in_(status_values))
            stmt = stmt.where(ScheduleAppointment.status.in_(status_values))

        if payment_statuses:
            payment_values = [payment.value for payment in payment_statuses]
            count_stmt = count_stmt.where(ScheduleAppointment.payment_status.in_(payment_values))
            stmt = stmt.where(ScheduleAppointment.payment_status.in_(payment_values))

        stmt = stmt.order_by(ScheduleAppointment.starts_at.asc(), ScheduleAppointment.id.asc())

        total_result = await session.execute(count_stmt)
        total = total_result.scalar_one()

        if pagination.is_paginated:
            stmt = stmt.offset(pagination.skip).limit(pagination.limit)

        result = await session.execute(stmt)
        return list(result.scalars().all()), total

    @staticmethod
    async def get_appointment(
        session: AsyncSession,
        appointment_id: int,
        *,
        include_deleted: bool = False,
    ) -> ScheduleAppointment | None:
        """Get an appointment from current tenant context."""
        tenant_id = ScheduleService._require_tenant_id(session)
        stmt = select(ScheduleAppointment).where(
            ScheduleAppointment.id == appointment_id,
            ScheduleAppointment.tenant_id == tenant_id,
        )
        if not include_deleted:
            stmt = stmt.where(ScheduleAppointment.is_deleted.is_(False))

        result = await session.execute(stmt)
        return result.scalar_one_or_none()

    @staticmethod
    async def require_appointment(
        session: AsyncSession,
        appointment_id: int,
        *,
        include_deleted: bool = False,
    ) -> ScheduleAppointment:
        """Get an appointment or raise not-found error."""
        appointment = await ScheduleService.get_appointment(
            session,
            appointment_id,
            include_deleted=include_deleted,
        )
        if appointment is None:
            raise ScheduleAppointmentNotFound()
        return appointment

    @staticmethod
    async def get_appointment_history(
        session: AsyncSession,
        appointment_id: int,
    ) -> list[ScheduleAppointmentHistory]:
        """Return appointment lifecycle timeline ordered by latest event first."""
        tenant_id = ScheduleService._require_tenant_id(session)
        stmt = (
            select(ScheduleAppointmentHistory)
            .where(
                ScheduleAppointmentHistory.tenant_id == tenant_id,
                ScheduleAppointmentHistory.appointment_id == appointment_id,
            )
            .order_by(
                ScheduleAppointmentHistory.created_at.desc(),
                ScheduleAppointmentHistory.id.desc(),
            )
        )
        result = await session.execute(stmt)
        return list(result.scalars().all())

    @staticmethod
    async def update_appointment(
        session: AsyncSession,
        user_id: int,
        appointment: ScheduleAppointment,
        data: ScheduleAppointmentUpdateRequest,
    ) -> ScheduleAppointment:
        """Update appointment data and auto-handle reschedule semantics."""
        configuration = await ScheduleService._require_schedule_configuration(session)
        target_patient: Patient | None = None

        if data.patient_id is not None and data.patient_id != appointment.patient_id:
            target_patient = await ScheduleService._require_patient(session, data.patient_id)

        starts_at, ends_at, time_changed = ScheduleService._resolve_updated_window(appointment, data)

        if ends_at <= starts_at:
            raise ScheduleInvalidTimeWindow()

        if time_changed and starts_at <= datetime.now(UTC):
            raise ScheduleAppointmentInPast()

        current_status = AppointmentStatus(appointment.status)
        if time_changed and current_status in _TERMINAL_APPOINTMENT_STATUSES:
            raise ScheduleInvalidStatusTransition(
                current_status.value,
                AppointmentStatus.RESCHEDULED.value,
            )

        if time_changed and await ScheduleService._has_slot_conflict(
            session,
            starts_at,
            ends_at,
            exclude_appointment_id=appointment.id,
        ):
            raise ScheduleSlotUnavailable()

        previous_values = ScheduleService._snapshot_appointment(appointment)
        ScheduleService._apply_appointment_updates(
            appointment,
            data,
            starts_at=starts_at,
            ends_at=ends_at,
            time_changed=time_changed,
            configuration=configuration,
            target_patient=target_patient,
        )
        current_values = ScheduleService._snapshot_appointment(appointment)

        change_summary = ScheduleService._build_change_summary(previous_values, current_values)
        if not change_summary:
            return appointment

        await session.flush()

        event_type = ScheduleService._resolve_update_event_type(
            change_summary,
            time_changed=time_changed,
            previous_payment_status=previous_values["payment_status"],
            current_payment_status=current_values["payment_status"],
        )

        await ScheduleService._add_history_event(
            session,
            appointment,
            changed_by_user_id=user_id,
            event_type=event_type,
            from_status=previous_values["status"],
            to_status=current_values["status"],
            from_payment_status=previous_values["payment_status"],
            to_payment_status=current_values["payment_status"],
            from_starts_at=previous_values["starts_at"],
            to_starts_at=current_values["starts_at"],
            change_summary=change_summary,
        )

        return appointment

    @staticmethod
    async def update_appointment_status(
        session: AsyncSession,
        user_id: int,
        appointment: ScheduleAppointment,
        data: ScheduleAppointmentStatusUpdateRequest,
    ) -> ScheduleAppointment:
        """Change appointment consultation status with transition validation."""
        current_status = AppointmentStatus(appointment.status)
        target_status = data.status

        if target_status == current_status:
            raise ScheduleInvalidStatusTransition(current_status.value, target_status.value)

        allowed_targets = _STATUS_TRANSITIONS[current_status]
        if target_status not in allowed_targets:
            raise ScheduleInvalidStatusTransition(current_status.value, target_status.value)

        previous_status = appointment.status
        previous_payment_status = appointment.payment_status
        previous_paid_at = appointment.paid_at

        appointment.status = target_status.value

        if target_status == AppointmentStatus.CANCELED and data.mark_as_not_charged:
            appointment.payment_status = PaymentStatus.NOT_CHARGED.value

        ScheduleService._sync_paid_at(appointment, previous_payment_status=previous_payment_status)

        await session.flush()

        change_summary = {
            "status": {
                "from": previous_status,
                "to": appointment.status,
            }
        }

        if previous_payment_status != appointment.payment_status:
            change_summary["payment_status"] = {
                "from": previous_payment_status,
                "to": appointment.payment_status,
            }
        if previous_paid_at != appointment.paid_at:
            change_summary["paid_at"] = {
                "from": _jsonable(previous_paid_at),
                "to": _jsonable(appointment.paid_at),
            }

        await ScheduleService._add_history_event(
            session,
            appointment,
            changed_by_user_id=user_id,
            event_type=AppointmentHistoryEvent.STATUS_CHANGED,
            reason=data.reason,
            from_status=previous_status,
            to_status=appointment.status,
            from_payment_status=previous_payment_status,
            to_payment_status=appointment.payment_status,
            from_starts_at=appointment.starts_at,
            to_starts_at=appointment.starts_at,
            change_summary=change_summary,
        )

        return appointment

    @staticmethod
    async def update_payment_status(
        session: AsyncSession,
        user_id: int,
        appointment: ScheduleAppointment,
        payment_status: PaymentStatus,
        reason: str | None,
    ) -> ScheduleAppointment:
        """Change appointment payment status and append timeline event."""
        if appointment.payment_status == payment_status.value:
            return appointment

        previous_payment_status = appointment.payment_status
        previous_paid_at = appointment.paid_at
        appointment.payment_status = payment_status.value
        ScheduleService._sync_paid_at(appointment, previous_payment_status=previous_payment_status)

        await session.flush()

        change_summary: dict[str, dict[str, Any]] = {
            "payment_status": {
                "from": previous_payment_status,
                "to": appointment.payment_status,
            }
        }
        if previous_paid_at != appointment.paid_at:
            change_summary["paid_at"] = {
                "from": _jsonable(previous_paid_at),
                "to": _jsonable(appointment.paid_at),
            }

        await ScheduleService._add_history_event(
            session,
            appointment,
            changed_by_user_id=user_id,
            event_type=AppointmentHistoryEvent.PAYMENT_STATUS_CHANGED,
            reason=reason,
            from_status=appointment.status,
            to_status=appointment.status,
            from_payment_status=previous_payment_status,
            to_payment_status=appointment.payment_status,
            from_starts_at=appointment.starts_at,
            to_starts_at=appointment.starts_at,
            change_summary=change_summary,
        )

        return appointment

    @staticmethod
    async def delete_appointment(
        session: AsyncSession,
        user_id: int,
        appointment: ScheduleAppointment,
        data: ScheduleAppointmentDeleteRequest,
    ) -> ScheduleAppointment:
        """Soft-delete appointment after explicit confirmation payload."""
        if not data.confirm:
            raise ScheduleDeleteConfirmationRequired()

        if appointment.is_deleted:
            raise ScheduleAppointmentAlreadyDeleted()

        appointment.is_deleted = True
        appointment.deleted_at = datetime.now(UTC)
        appointment.deleted_reason = data.reason
        appointment.deleted_by_user_id = user_id

        await session.flush()

        await ScheduleService._add_history_event(
            session,
            appointment,
            changed_by_user_id=user_id,
            event_type=AppointmentHistoryEvent.DELETED,
            reason=data.reason,
            from_status=appointment.status,
            to_status=appointment.status,
            from_payment_status=appointment.payment_status,
            to_payment_status=appointment.payment_status,
            from_starts_at=appointment.starts_at,
            to_starts_at=appointment.starts_at,
            change_summary={
                "is_deleted": {
                    "from": False,
                    "to": True,
                },
                "deleted_reason": {
                    "from": None,
                    "to": data.reason,
                },
            },
        )

        return appointment

    @staticmethod
    async def get_defaults(session: AsyncSession) -> ScheduleConfiguration:
        """Return tenant schedule configuration used as scheduling defaults."""
        return await ScheduleService._require_schedule_configuration(session)

    @staticmethod
    async def get_available_slots(
        session: AsyncSession,
        target_date: date,
        *,
        slot_duration_minutes: int | None = None,
        break_between_appointments_minutes: int | None = None,
    ) -> tuple[bool, int, int, list[ScheduleAvailabilitySlotResponse]]:
        """Calculate available slots for a target date in tenant schedule."""
        configuration = await ScheduleService._require_schedule_configuration(session)

        duration = slot_duration_minutes or configuration.appointment_duration_minutes
        interval = break_between_appointments_minutes
        if interval is None:
            interval = configuration.break_between_appointments_minutes

        if duration <= 0:
            raise ScheduleInvalidTimeWindow()
        if interval < 0:
            raise ScheduleInvalidTimeWindow()

        weekday = target_date.strftime("%A").lower()
        if weekday not in configuration.working_days:
            return False, duration, interval, []

        day_start = datetime.combine(target_date, configuration.start_time, tzinfo=UTC)
        day_end = datetime.combine(target_date, configuration.end_time, tzinfo=UTC)

        tenant_id = ScheduleService._require_tenant_id(session)
        busy_stmt = (
            select(ScheduleAppointment.starts_at, ScheduleAppointment.ends_at)
            .where(
                ScheduleAppointment.tenant_id == tenant_id,
                ScheduleAppointment.is_deleted.is_(False),
                ScheduleAppointment.status != AppointmentStatus.CANCELED.value,
                ScheduleAppointment.starts_at < day_end,
                ScheduleAppointment.ends_at > day_start,
            )
            .order_by(ScheduleAppointment.starts_at.asc())
        )
        busy_result = await session.execute(busy_stmt)
        busy_slots = list(busy_result.all())

        available_slots: list[ScheduleAvailabilitySlotResponse] = []

        cursor = day_start
        slot_delta = timedelta(minutes=duration)
        break_delta = timedelta(minutes=interval)

        while cursor + slot_delta <= day_end:
            slot_end = cursor + slot_delta

            has_conflict = any(start < slot_end and end > cursor for start, end in busy_slots)
            if not has_conflict:
                available_slots.append(
                    ScheduleAvailabilitySlotResponse(
                        starts_at=cursor,
                        ends_at=slot_end,
                    )
                )

            cursor = slot_end + break_delta

        return True, duration, interval, available_slots

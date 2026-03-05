"""Schedule router (API endpoints)."""

from datetime import date

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from src.database.dependencies import get_tenant_db_session
from src.features.auth.dependencies import require_role, require_tenant_membership
from src.features.schedule_config.schemas import WeekDay
from src.features.user.models import User, UserRole
from src.shared.pagination.pagination import PaginationParams

from .schemas import (
    AppointmentHistoryEvent,
    AppointmentModality,
    AppointmentStatus,
    PaymentStatus,
    ScheduleAppointmentCreateRequest,
    ScheduleAppointmentDeleteRequest,
    ScheduleAppointmentDetailResponse,
    ScheduleAppointmentHistoryResponse,
    ScheduleAppointmentListResponse,
    ScheduleAppointmentPaymentStatusUpdateRequest,
    ScheduleAppointmentResponse,
    ScheduleAppointmentStatusUpdateRequest,
    ScheduleAppointmentUpdateRequest,
    ScheduleAvailabilityResponse,
    ScheduleCalendarView,
    ScheduleDefaultsResponse,
)
from .service import ScheduleService

router = APIRouter(
    prefix="/schedule",
    tags=["Schedule Management"],
    dependencies=[Depends(require_role(UserRole.TENANT_OWNER, UserRole.ASSISTANT))],
)


def _to_history_response(history_entry) -> ScheduleAppointmentHistoryResponse:
    """Convert history model to API response."""
    return ScheduleAppointmentHistoryResponse.model_validate(
        {
            "id": history_entry.id,
            "appointment_id": history_entry.appointment_id,
            "changed_by_user_id": history_entry.changed_by_user_id,
            "event_type": history_entry.event_type,
            "reason": history_entry.reason,
            "from_status": history_entry.from_status,
            "to_status": history_entry.to_status,
            "from_payment_status": history_entry.from_payment_status,
            "to_payment_status": history_entry.to_payment_status,
            "from_starts_at": history_entry.from_starts_at,
            "to_starts_at": history_entry.to_starts_at,
            "change_summary": history_entry.change_summary,
            "is_reschedule": history_entry.event_type == AppointmentHistoryEvent.RESCHEDULED.value,
            "created_at": history_entry.created_at,
        }
    )


@router.post("/appointments", response_model=ScheduleAppointmentResponse)
async def create_appointment(
    data: ScheduleAppointmentCreateRequest,
    current_user: User = Depends(require_tenant_membership),
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Create a new consultation appointment."""
    appointment = await ScheduleService.create_appointment(session, current_user.id, data)
    await session.commit()
    await session.refresh(appointment)
    return ScheduleAppointmentResponse.model_validate(appointment)


@router.get("/appointments", response_model=ScheduleAppointmentListResponse)
async def list_appointments(
    pagination: PaginationParams = Depends(),
    view: ScheduleCalendarView = Query(default=ScheduleCalendarView.DAY),
    reference_date: date | None = Query(default=None),
    start_date: date | None = Query(default=None),
    end_date: date | None = Query(default=None),
    patient_id: int | None = Query(default=None, gt=0),
    statuses: list[AppointmentStatus] | None = Query(default=None),
    payment_statuses: list[PaymentStatus] | None = Query(default=None),
    include_deleted: bool = Query(default=False),
    _: User = Depends(require_tenant_membership),
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """List appointments by calendar view and filters."""
    appointments, total = await ScheduleService.list_appointments(
        session=session,
        pagination=pagination,
        view=view,
        reference_date=reference_date,
        start_date=start_date,
        end_date=end_date,
        patient_id=patient_id,
        statuses=statuses,
        payment_statuses=payment_statuses,
        include_deleted=include_deleted,
    )
    return ScheduleAppointmentListResponse(
        appointments=[ScheduleAppointmentResponse.model_validate(item) for item in appointments],
        total=total,
        page=pagination.page or 1,
        page_size=pagination.page_size or 50,
    )


@router.get("/appointments/{appointment_id}", response_model=ScheduleAppointmentDetailResponse)
async def get_appointment_detail(
    appointment_id: int,
    include_deleted: bool = Query(default=False),
    _: User = Depends(require_tenant_membership),
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Get appointment detail including timeline history."""
    appointment = await ScheduleService.require_appointment(session, appointment_id, include_deleted=include_deleted)
    history = await ScheduleService.get_appointment_history(session, appointment_id)

    base_response = ScheduleAppointmentResponse.model_validate(appointment)
    return ScheduleAppointmentDetailResponse(
        **base_response.model_dump(),
        history=[_to_history_response(entry) for entry in history],
    )


@router.put("/appointments/{appointment_id}", response_model=ScheduleAppointmentResponse)
async def update_appointment(
    appointment_id: int,
    data: ScheduleAppointmentUpdateRequest,
    current_user: User = Depends(require_tenant_membership),
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Update appointment details and reschedule when datetime changes."""
    appointment = await ScheduleService.require_appointment(session, appointment_id)
    updated = await ScheduleService.update_appointment(session, current_user.id, appointment, data)
    await session.commit()
    await session.refresh(updated)
    return ScheduleAppointmentResponse.model_validate(updated)


@router.patch("/appointments/{appointment_id}/status", response_model=ScheduleAppointmentResponse)
async def update_appointment_status(
    appointment_id: int,
    data: ScheduleAppointmentStatusUpdateRequest,
    current_user: User = Depends(require_tenant_membership),
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Update appointment consultation status."""
    appointment = await ScheduleService.require_appointment(session, appointment_id)
    updated = await ScheduleService.update_appointment_status(session, current_user.id, appointment, data)
    await session.commit()
    await session.refresh(updated)
    return ScheduleAppointmentResponse.model_validate(updated)


@router.patch("/appointments/{appointment_id}/payment-status", response_model=ScheduleAppointmentResponse)
async def update_appointment_payment_status(
    appointment_id: int,
    data: ScheduleAppointmentPaymentStatusUpdateRequest,
    current_user: User = Depends(require_tenant_membership),
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Update appointment payment status."""
    appointment = await ScheduleService.require_appointment(session, appointment_id)
    updated = await ScheduleService.update_payment_status(
        session,
        current_user.id,
        appointment,
        payment_status=data.payment_status,
        reason=data.reason,
    )
    await session.commit()
    await session.refresh(updated)
    return ScheduleAppointmentResponse.model_validate(updated)


@router.delete("/appointments/{appointment_id}")
async def delete_appointment(
    appointment_id: int,
    data: ScheduleAppointmentDeleteRequest,
    current_user: User = Depends(require_tenant_membership),
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Soft-delete an appointment in exceptional error scenarios."""
    appointment = await ScheduleService.require_appointment(session, appointment_id, include_deleted=True)
    await ScheduleService.delete_appointment(session, current_user.id, appointment, data)
    await session.commit()
    return {"message": "Appointment deleted successfully"}


@router.get("/defaults", response_model=ScheduleDefaultsResponse)
async def get_schedule_defaults(
    _: User = Depends(require_tenant_membership),
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Get tenant default scheduling values from schedule configuration."""
    configuration = await ScheduleService.get_defaults(session)
    return ScheduleDefaultsResponse(
        configuration_id=configuration.id,
        working_days=[WeekDay(day) for day in configuration.working_days],
        start_time=configuration.start_time,
        end_time=configuration.end_time,
        appointment_duration_minutes=configuration.appointment_duration_minutes,
        break_between_appointments_minutes=configuration.break_between_appointments_minutes,
        default_status=AppointmentStatus.SCHEDULED,
        default_payment_status=PaymentStatus.PENDING,
        default_modality=AppointmentModality.IN_PERSON,
    )


@router.get("/availability", response_model=ScheduleAvailabilityResponse)
async def get_schedule_availability(
    target_date: date = Query(...),
    slot_duration_minutes: int | None = Query(default=None, gt=0),
    break_between_appointments_minutes: int | None = Query(default=None, ge=0),
    _: User = Depends(require_tenant_membership),
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """List available slots for the selected date."""
    working_day, duration, interval, slots = await ScheduleService.get_available_slots(
        session,
        target_date,
        slot_duration_minutes=slot_duration_minutes,
        break_between_appointments_minutes=break_between_appointments_minutes,
    )
    return ScheduleAvailabilityResponse(
        date=target_date,
        working_day=working_day,
        slot_duration_minutes=duration,
        break_between_appointments_minutes=interval,
        available_slots=slots,
    )

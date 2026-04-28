"""Schedule router (API endpoints)."""

from datetime import date

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from src.database.dependencies import get_tenant_db_session
from src.features.auth.dependencies import require_tenant_membership
from src.features.schedule_config.schemas import WeekDay
from src.features.user.models import User
from src.shared.pagination.pagination import PaginationParams
from src.shared.redis import commit_with_staged_redis

from .openapi import (
    AVAILABILITY_DESCRIPTION,
    AVAILABILITY_RESPONSES,
    CREATE_APPOINTMENT_DESCRIPTION,
    CREATE_APPOINTMENT_RESPONSES,
    DEFAULTS_DESCRIPTION,
    DEFAULTS_RESPONSES,
    DELETE_APPOINTMENT_DESCRIPTION,
    DELETE_APPOINTMENT_RESPONSES,
    DETAIL_APPOINTMENT_DESCRIPTION,
    DETAIL_APPOINTMENT_RESPONSES,
    LIST_APPOINTMENTS_DESCRIPTION,
    LIST_APPOINTMENTS_RESPONSES,
    UPDATE_APPOINTMENT_DESCRIPTION,
    UPDATE_APPOINTMENT_RESPONSES,
    UPDATE_PAYMENT_DESCRIPTION,
    UPDATE_PAYMENT_RESPONSES,
    UPDATE_STATUS_DESCRIPTION,
    UPDATE_STATUS_RESPONSES,
    ScheduleMessageResponse,
)
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
    dependencies=[Depends(require_tenant_membership)],
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


@router.post(
    "/appointments",
    response_model=ScheduleAppointmentResponse,
    summary="Create an appointment",
    description=CREATE_APPOINTMENT_DESCRIPTION,
    response_description="The created appointment, including finance and warning fields.",
    responses=CREATE_APPOINTMENT_RESPONSES,
)
async def create_appointment(
    data: ScheduleAppointmentCreateRequest,
    current_user: User = Depends(require_tenant_membership),
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Create a tenant-scoped consultation appointment."""
    appointment = await ScheduleService.create_appointment(session, current_user.id, data)
    await commit_with_staged_redis(session)
    await session.refresh(appointment)
    return ScheduleAppointmentResponse.model_validate(appointment)


@router.get(
    "/appointments",
    response_model=ScheduleAppointmentListResponse,
    summary="List appointments",
    description=LIST_APPOINTMENTS_DESCRIPTION,
    response_description="A paginated list of appointments that overlap the requested date window.",
    responses=LIST_APPOINTMENTS_RESPONSES,
)
async def list_appointments(
    pagination: PaginationParams = Depends(),
    view: ScheduleCalendarView = Query(
        default=ScheduleCalendarView.DAY,
        description="Calendar window for the query: `day`, `week`, `month`, `year`, or `total`.",
    ),
    reference_date: date | None = Query(
        default=None,
        description="Reference date for the selected calendar window. Defaults to current UTC date.",
    ),
    start_date: date | None = Query(
        default=None,
        description="Inclusive start date override. Used together with `end_date` for custom range queries.",
    ),
    end_date: date | None = Query(
        default=None,
        description="Inclusive end date override. Used together with `start_date` for custom range queries.",
    ),
    patient_id: int | None = Query(
        default=None,
        gt=0,
        description="Filter appointments for one specific patient.",
    ),
    statuses: list[AppointmentStatus] | None = Query(
        default=None,
        description="Filter by one or more appointment consultation statuses.",
    ),
    payment_statuses: list[PaymentStatus] | None = Query(
        default=None,
        description="Filter by one or more payment statuses.",
    ),
    include_deleted: bool = Query(
        default=False,
        description="When true, includes soft-deleted appointments in the result.",
    ),
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """List tenant appointments using overlap-based calendar filtering."""
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


@router.get(
    "/appointments/{appointment_id}",
    response_model=ScheduleAppointmentDetailResponse,
    summary="Get appointment detail",
    description=DETAIL_APPOINTMENT_DESCRIPTION,
    response_description="The appointment record plus its latest-first history timeline.",
    responses=DETAIL_APPOINTMENT_RESPONSES,
)
async def get_appointment_detail(
    appointment_id: int,
    include_deleted: bool = Query(default=False),
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Get an appointment and its timeline history."""
    appointment = await ScheduleService.require_appointment(session, appointment_id, include_deleted=include_deleted)
    history = await ScheduleService.get_appointment_history(session, appointment_id)

    base_response = ScheduleAppointmentResponse.model_validate(appointment)
    return ScheduleAppointmentDetailResponse(
        **base_response.model_dump(),
        history=[_to_history_response(entry) for entry in history],
    )


@router.put(
    "/appointments/{appointment_id}",
    response_model=ScheduleAppointmentResponse,
    summary="Update an appointment",
    description=UPDATE_APPOINTMENT_DESCRIPTION,
    response_description="The updated appointment after all reschedule and finance rules are applied.",
    responses=UPDATE_APPOINTMENT_RESPONSES,
)
async def update_appointment(
    appointment_id: int,
    data: ScheduleAppointmentUpdateRequest,
    current_user: User = Depends(require_tenant_membership),
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Update appointment fields and reschedule when datetimes change."""
    appointment = await ScheduleService.require_appointment(session, appointment_id)
    updated = await ScheduleService.update_appointment(session, current_user.id, appointment, data)
    await commit_with_staged_redis(session)
    await session.refresh(updated)
    return ScheduleAppointmentResponse.model_validate(updated)


@router.patch(
    "/appointments/{appointment_id}/status",
    response_model=ScheduleAppointmentResponse,
    summary="Change appointment status",
    description=UPDATE_STATUS_DESCRIPTION,
    response_description="The appointment after the status transition and timeline write.",
    responses=UPDATE_STATUS_RESPONSES,
)
async def update_appointment_status(
    appointment_id: int,
    data: ScheduleAppointmentStatusUpdateRequest,
    current_user: User = Depends(require_tenant_membership),
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Update the consultation status for an appointment."""
    appointment = await ScheduleService.require_appointment(session, appointment_id)
    updated = await ScheduleService.update_appointment_status(session, current_user.id, appointment, data)
    await commit_with_staged_redis(session)
    await session.refresh(updated)
    return ScheduleAppointmentResponse.model_validate(updated)


@router.patch(
    "/appointments/{appointment_id}/payment-status",
    response_model=ScheduleAppointmentResponse,
    summary="Change payment status",
    description=UPDATE_PAYMENT_DESCRIPTION,
    response_description="The appointment after the payment state change has been persisted.",
    responses=UPDATE_PAYMENT_RESPONSES,
)
async def update_appointment_payment_status(
    appointment_id: int,
    data: ScheduleAppointmentPaymentStatusUpdateRequest,
    current_user: User = Depends(require_tenant_membership),
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Update the payment status for an appointment."""
    appointment = await ScheduleService.require_appointment(session, appointment_id)
    updated = await ScheduleService.update_payment_status(
        session,
        current_user.id,
        appointment,
        payment_status=data.payment_status,
        reason=data.reason,
    )
    await commit_with_staged_redis(session)
    await session.refresh(updated)
    return ScheduleAppointmentResponse.model_validate(updated)


@router.delete(
    "/appointments/{appointment_id}",
    response_model=ScheduleMessageResponse,
    summary="Delete an appointment",
    description=DELETE_APPOINTMENT_DESCRIPTION,
    response_description="A confirmation message describing whether the appointment was deleted.",
    responses=DELETE_APPOINTMENT_RESPONSES,
)
async def delete_appointment(
    appointment_id: int,
    data: ScheduleAppointmentDeleteRequest,
    current_user: User = Depends(require_tenant_membership),
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Soft-delete an appointment after explicit confirmation."""
    appointment = await ScheduleService.require_appointment(session, appointment_id, include_deleted=True)
    await ScheduleService.delete_appointment(session, current_user.id, appointment, data)
    await commit_with_staged_redis(session)
    return {"message": "Appointment deleted successfully"}


@router.get(
    "/defaults",
    response_model=ScheduleDefaultsResponse,
    summary="Get schedule defaults",
    description=DEFAULTS_DESCRIPTION,
    response_description="The tenant's schedule configuration plus the fixed appointment defaults.",
    responses=DEFAULTS_RESPONSES,
)
async def get_schedule_defaults(
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Get the tenant's default scheduling values."""
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


@router.get(
    "/availability",
    response_model=ScheduleAvailabilityResponse,
    summary="Get schedule availability",
    description=AVAILABILITY_DESCRIPTION,
    response_description="Available slots for the selected date and the parameters used to calculate them.",
    responses=AVAILABILITY_RESPONSES,
)
async def get_schedule_availability(
    target_date: date = Query(
        ...,
        description="Date to compute available slots for.",
    ),
    slot_duration_minutes: int | None = Query(
        default=None,
        gt=0,
        description="Slot duration in minutes. Defaults to the tenant schedule configuration value.",
    ),
    break_between_appointments_minutes: int | None = Query(
        default=None,
        ge=0,
        description="Break between slots in minutes. Defaults to the tenant schedule configuration value.",
    ),
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Calculate the open slots for one date."""
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

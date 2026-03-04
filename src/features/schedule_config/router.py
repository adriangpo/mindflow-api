"""Schedule configuration router (API endpoints)."""

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.encoders import jsonable_encoder
from pydantic import ValidationError
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from src.database.dependencies import get_tenant_db_session
from src.features.auth.dependencies import require_tenant_membership
from src.features.user.models import User
from src.shared.pagination.pagination import PaginationParams

from .exceptions import (
    ScheduleConfigurationAlreadyExists,
    ScheduleConfigurationNotFound,
)
from .schemas import (
    ScheduleConfigurationCreateRequest,
    ScheduleConfigurationListResponse,
    ScheduleConfigurationResponse,
    ScheduleConfigurationUpdateRequest,
)
from .service import ScheduleConfigurationService, is_tenant_unique_violation

router = APIRouter(prefix="/schedule-configurations", tags=["Schedule Configuration"])


@router.post("", response_model=ScheduleConfigurationResponse)
async def create_schedule_configuration(
    data: ScheduleConfigurationCreateRequest,
    current_user: User = Depends(require_tenant_membership),
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Create the tenant schedule configuration."""
    configuration = await ScheduleConfigurationService.create_configuration(session, current_user.id, data)
    try:
        await session.commit()
    except IntegrityError as exc:
        await session.rollback()
        if is_tenant_unique_violation(exc):
            raise ScheduleConfigurationAlreadyExists() from exc
        raise
    await session.refresh(configuration)
    return ScheduleConfigurationResponse.model_validate(configuration)


@router.get("", response_model=ScheduleConfigurationListResponse)
async def list_schedule_configurations(
    pagination: PaginationParams = Depends(),
    _: User = Depends(require_tenant_membership),
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """List schedule configurations in the tenant."""
    items, total = await ScheduleConfigurationService.list_configurations(
        session=session,
        pagination=pagination,
    )
    return ScheduleConfigurationListResponse(
        configurations=[ScheduleConfigurationResponse.model_validate(item) for item in items],
        total=total,
        page=pagination.page or 1,
        page_size=pagination.page_size or 50,
    )


@router.get("/{configuration_id}", response_model=ScheduleConfigurationResponse)
async def get_schedule_configuration(
    configuration_id: int,
    _: User = Depends(require_tenant_membership),
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Get schedule configuration by id."""
    configuration = await ScheduleConfigurationService.get_configuration(session, configuration_id)
    if configuration is None:
        raise ScheduleConfigurationNotFound()

    return ScheduleConfigurationResponse.model_validate(configuration)


@router.put("/{configuration_id}", response_model=ScheduleConfigurationResponse)
async def update_schedule_configuration(
    configuration_id: int,
    data: ScheduleConfigurationUpdateRequest,
    _: User = Depends(require_tenant_membership),
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Update schedule configuration by id."""
    configuration = await ScheduleConfigurationService.get_configuration(session, configuration_id)
    if configuration is None:
        raise ScheduleConfigurationNotFound()

    # Re-validate merged state using creation schema to centralize business validation in schemas.
    try:
        ScheduleConfigurationCreateRequest.model_validate(
            {
                "working_days": data.working_days if data.working_days is not None else configuration.working_days,
                "start_time": data.start_time if data.start_time is not None else configuration.start_time,
                "end_time": data.end_time if data.end_time is not None else configuration.end_time,
                "appointment_duration_minutes": (
                    data.appointment_duration_minutes
                    if data.appointment_duration_minutes is not None
                    else configuration.appointment_duration_minutes
                ),
                "break_between_appointments_minutes": (
                    data.break_between_appointments_minutes
                    if data.break_between_appointments_minutes is not None
                    else configuration.break_between_appointments_minutes
                ),
            }
        )
    except ValidationError as exc:
        # Keep API behavior consistent with request-body schema errors.
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=jsonable_encoder(exc.errors()),
        ) from exc

    updated = await ScheduleConfigurationService.update_configuration(session, configuration, data)
    await session.commit()
    await session.refresh(updated)
    return ScheduleConfigurationResponse.model_validate(updated)


@router.delete("/{configuration_id}")
async def delete_schedule_configuration(
    configuration_id: int,
    _: User = Depends(require_tenant_membership),
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Delete schedule configuration by id."""
    configuration = await ScheduleConfigurationService.get_configuration(session, configuration_id)
    if configuration is None:
        raise ScheduleConfigurationNotFound()

    await ScheduleConfigurationService.delete_configuration(session, configuration_id)
    await session.commit()
    return {"message": "Schedule configuration deleted successfully"}

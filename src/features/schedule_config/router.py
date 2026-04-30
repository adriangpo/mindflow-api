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
from .openapi import (
    SCHEDULE_CONFIGURATION_DELETE_EXAMPLE,
    ScheduleConfigurationDeleteResponse,
    ScheduleConfigurationErrorResponse,
)
from .schemas import (
    ScheduleConfigurationCreateRequest,
    ScheduleConfigurationListResponse,
    ScheduleConfigurationResponse,
    ScheduleConfigurationUpdateRequest,
)
from .service import ScheduleConfigurationService, is_tenant_unique_violation

router = APIRouter(
    prefix="/schedule-configurations",
    tags=["Schedule Configuration"],
    dependencies=[Depends(require_tenant_membership)],
)


@router.post(
    "",
    response_model=ScheduleConfigurationResponse,
    summary="Create tenant schedule configuration",
    description=(
        "Creates the single schedule configuration for the current tenant. "
        "The creator is recorded as `user_id`, but the configuration applies to the entire tenant. "
        "The API rejects a second configuration for the same tenant both before and after the database commit "
        "so concurrent requests still surface a `409` conflict. "
        "The time window must be valid (`start_time` earlier than `end_time`) and at least one working day "
        "must be supplied."
    ),
    response_description="Created tenant schedule configuration.",
    responses={
        409: {
            "model": ScheduleConfigurationErrorResponse,
            "description": "A configuration already exists for the current tenant.",
            "content": {
                "application/json": {"example": {"detail": "Schedule configuration already exists for this tenant"}}
            },
        },
        422: {
            "description": "Request body validation failed.",
            "content": {
                "application/json": {
                    "example": {
                        "detail": [
                            {
                                "type": "value_error",
                                "loc": ["body", "start_time"],
                                "msg": "start_time must be earlier than end_time",
                                "input": "18:00:00",
                            }
                        ]
                    }
                }
            },
        },
    },
)
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


@router.get(
    "",
    response_model=ScheduleConfigurationListResponse,
    summary="List tenant schedule configurations",
    description=(
        "Returns the schedule configuration rows visible to the current tenant. "
        "The service still scopes every query with the tenant context, so the endpoint "
        "never leaks data across tenants. "
        "Pagination is supported through `page` and `page_size`; when either value is omitted, the response still "
        "returns `page=1` and `page_size=50` as defaults."
    ),
    response_description="Paginated schedule configuration list for the current tenant.",
)
async def list_schedule_configurations(
    pagination: PaginationParams = Depends(),
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


@router.get(
    "/{configuration_id}",
    response_model=ScheduleConfigurationResponse,
    summary="Get tenant schedule configuration",
    description=(
        "Loads one schedule configuration by id inside the current tenant scope. "
        "A configuration that exists in another tenant is treated as not found. "
        "The endpoint returns `404` when the configuration id is missing, deleted, or belongs to another tenant."
    ),
    response_description="Schedule configuration details for the current tenant.",
    responses={
        404: {
            "model": ScheduleConfigurationErrorResponse,
            "description": "No schedule configuration exists for the requested id in this tenant.",
            "content": {"application/json": {"example": {"detail": "Schedule configuration not found"}}},
        }
    },
)
async def get_schedule_configuration(
    configuration_id: int,
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Get schedule configuration by id."""
    configuration = await ScheduleConfigurationService.get_configuration(session, configuration_id)
    if configuration is None:
        raise ScheduleConfigurationNotFound()

    return ScheduleConfigurationResponse.model_validate(configuration)


@router.put(
    "/{configuration_id}",
    response_model=ScheduleConfigurationResponse,
    summary="Update tenant schedule configuration",
    description=(
        "Updates one schedule configuration in the current tenant. "
        "Only the provided fields are changed. The router then merges the stored configuration with the incoming "
        "payload and re-validates the final state using the creation schema, which means a partial update can still "
        "fail with `422` if it produces an invalid time window. "
        "A missing configuration returns `404`."
    ),
    response_description="Updated tenant schedule configuration.",
    responses={
        404: {
            "model": ScheduleConfigurationErrorResponse,
            "description": "No schedule configuration exists for the requested id in this tenant.",
            "content": {"application/json": {"example": {"detail": "Schedule configuration not found"}}},
        },
        422: {
            "description": "Request body or merged-state validation failed.",
            "content": {
                "application/json": {
                    "example": {
                        "detail": [
                            {
                                "type": "value_error",
                                "loc": ["body", "__root__"],
                                "msg": "start_time must be earlier than end_time",
                                "input": {
                                    "working_days": ["monday"],
                                    "start_time": "18:00:00",
                                    "end_time": "08:00:00",
                                    "appointment_duration_minutes": 50,
                                    "break_between_appointments_minutes": 10,
                                },
                            }
                        ]
                    }
                }
            },
        },
    },
)
async def update_schedule_configuration(
    configuration_id: int,
    data: ScheduleConfigurationUpdateRequest,
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Update schedule configuration by id."""
    configuration = await ScheduleConfigurationService.get_configuration(session, configuration_id)
    if configuration is None:
        raise ScheduleConfigurationNotFound()

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


@router.delete(
    "/{configuration_id}",
    response_model=ScheduleConfigurationDeleteResponse,
    summary="Delete tenant schedule configuration",
    description=(
        "Deletes the current tenant's configuration by id. "
        "This is a hard delete, not a soft delete, so the row is removed from `schedule_configurations` entirely. "
        "The router first resolves the configuration in tenant scope and returns `404` if it does not exist."
    ),
    response_description="Deletion acknowledgement.",
    responses={
        404: {
            "model": ScheduleConfigurationErrorResponse,
            "description": "No schedule configuration exists for the requested id in this tenant.",
            "content": {"application/json": {"example": {"detail": "Schedule configuration not found"}}},
        },
        200: {
            "description": "Deletion acknowledgement.",
            "content": {"application/json": {"example": SCHEDULE_CONFIGURATION_DELETE_EXAMPLE["value"]}},
        },
    },
)
async def delete_schedule_configuration(
    configuration_id: int,
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Delete schedule configuration by id."""
    configuration = await ScheduleConfigurationService.get_configuration(session, configuration_id)
    if configuration is None:
        raise ScheduleConfigurationNotFound()

    await ScheduleConfigurationService.delete_configuration(session, configuration_id)
    await session.commit()
    return {"message": "Schedule configuration deleted successfully"}

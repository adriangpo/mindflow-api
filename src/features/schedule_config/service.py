"""Schedule configuration service layer."""

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.shared.pagination.pagination import PaginationParams

from .exceptions import (
    ScheduleConfigurationAlreadyExists,
    ScheduleConfigurationNotFound,
)
from .models import ScheduleConfiguration
from .schemas import ScheduleConfigurationCreateRequest, ScheduleConfigurationUpdateRequest


class ScheduleConfigurationService:
    """Service for schedule configuration operations."""

    @staticmethod
    async def create_configuration(
        session: AsyncSession,
        user_id: int,
        data: ScheduleConfigurationCreateRequest,
    ) -> ScheduleConfiguration:
        """Create a new schedule configuration."""
        tenant_id = session.info.get("tenant_id")

        # Business decision: one configuration per user.
        existing = await ScheduleConfigurationService.get_configuration_by_user_id(session, user_id)
        if existing:
            raise ScheduleConfigurationAlreadyExists()

        configuration = ScheduleConfiguration(
            tenant_id=tenant_id,
            user_id=user_id,
            working_days=[day.value for day in data.working_days],
            start_time=data.start_time,
            end_time=data.end_time,
            appointment_duration_minutes=data.appointment_duration_minutes,
            break_between_appointments_minutes=data.break_between_appointments_minutes,
        )
        session.add(configuration)
        return configuration

    @staticmethod
    async def get_configuration(session: AsyncSession, configuration_id: int) -> ScheduleConfiguration | None:
        """Get schedule configuration by id."""
        stmt = select(ScheduleConfiguration).where(ScheduleConfiguration.id == configuration_id)
        result = await session.execute(stmt)
        return result.scalar_one_or_none()

    @staticmethod
    async def get_configuration_by_user_id(session: AsyncSession, user_id: int) -> ScheduleConfiguration | None:
        """Get schedule configuration by user id."""
        stmt = select(ScheduleConfiguration).where(ScheduleConfiguration.user_id == user_id)
        result = await session.execute(stmt)
        return result.scalar_one_or_none()

    @staticmethod
    async def list_configurations(
        session: AsyncSession,
        pagination: PaginationParams,
        user_id: int | None = None,
    ) -> tuple[list[ScheduleConfiguration], int]:
        """List schedule configurations with optional filtering by user_id."""
        count_stmt = select(func.count()).select_from(ScheduleConfiguration)
        stmt = select(ScheduleConfiguration)

        if user_id is not None:
            count_stmt = count_stmt.where(ScheduleConfiguration.user_id == user_id)
            stmt = stmt.where(ScheduleConfiguration.user_id == user_id)

        total_result = await session.execute(count_stmt)
        total = total_result.scalar_one()

        if pagination.is_paginated:
            stmt = stmt.offset(pagination.skip).limit(pagination.limit)

        result = await session.execute(stmt)
        items = list(result.scalars().all())
        return items, total

    @staticmethod
    async def update_configuration(
        session: AsyncSession,
        configuration: ScheduleConfiguration,
        data: ScheduleConfigurationUpdateRequest,
    ) -> ScheduleConfiguration:
        """Update schedule configuration data."""
        if data.working_days is not None:
            configuration.working_days = [day.value for day in data.working_days]
        if data.start_time is not None:
            configuration.start_time = data.start_time
        if data.end_time is not None:
            configuration.end_time = data.end_time
        if data.appointment_duration_minutes is not None:
            configuration.appointment_duration_minutes = data.appointment_duration_minutes
        if data.break_between_appointments_minutes is not None:
            configuration.break_between_appointments_minutes = data.break_between_appointments_minutes

        await session.flush()
        return configuration

    @staticmethod
    async def delete_configuration(session: AsyncSession, configuration_id: int) -> bool:
        """Delete schedule configuration by id."""
        configuration = await ScheduleConfigurationService.get_configuration(session, configuration_id)
        if configuration is None:
            return False

        await session.delete(configuration)
        return True

    @staticmethod
    async def require_configuration(session: AsyncSession, configuration_id: int) -> ScheduleConfiguration:
        """Get schedule configuration or raise not found."""
        configuration = await ScheduleConfigurationService.get_configuration(session, configuration_id)
        if configuration is None:
            raise ScheduleConfigurationNotFound()
        return configuration

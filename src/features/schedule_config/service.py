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
    def _require_tenant_id(session: AsyncSession):
        """Return tenant_id from session context or raise if missing."""
        tenant_id = session.info.get("tenant_id")
        if tenant_id is None:
            raise RuntimeError("Tenant context is required for schedule configuration operations")
        return tenant_id

    @staticmethod
    async def create_configuration(
        session: AsyncSession,
        user_id: int,
        data: ScheduleConfigurationCreateRequest,
    ) -> ScheduleConfiguration:
        """Create a new schedule configuration."""
        tenant_id = ScheduleConfigurationService._require_tenant_id(session)

        # Business decision: one configuration per tenant.
        existing = await ScheduleConfigurationService.get_configuration_by_tenant(session)
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
        tenant_id = ScheduleConfigurationService._require_tenant_id(session)
        stmt = select(ScheduleConfiguration).where(
            ScheduleConfiguration.id == configuration_id,
            ScheduleConfiguration.tenant_id == tenant_id,
        )
        result = await session.execute(stmt)
        return result.scalar_one_or_none()

    @staticmethod
    async def get_configuration_by_tenant(session: AsyncSession) -> ScheduleConfiguration | None:
        """Get schedule configuration for current tenant."""
        tenant_id = ScheduleConfigurationService._require_tenant_id(session)
        stmt = select(ScheduleConfiguration).where(ScheduleConfiguration.tenant_id == tenant_id)
        result = await session.execute(stmt)
        return result.scalar_one_or_none()

    @staticmethod
    async def list_configurations(
        session: AsyncSession,
        pagination: PaginationParams,
    ) -> tuple[list[ScheduleConfiguration], int]:
        """List schedule configurations for the current tenant."""
        tenant_id = ScheduleConfigurationService._require_tenant_id(session)
        count_stmt = (
            select(func.count()).select_from(ScheduleConfiguration).where(ScheduleConfiguration.tenant_id == tenant_id)
        )
        stmt = select(ScheduleConfiguration).where(ScheduleConfiguration.tenant_id == tenant_id)

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

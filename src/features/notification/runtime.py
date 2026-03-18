"""Notification runtime helpers."""

import asyncio
import logging

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from src.config.settings import settings
from src.database.client import get_session, set_tenant_context
from src.features.tenant.models import Tenant

from .service import NotificationService

logger = logging.getLogger(__name__)


async def dispatch_due_notifications_for_all_tenants(*, limit_per_tenant: int = 100) -> None:
    """Dispatch due notifications tenant by tenant using RLS-aware sessions."""
    async with get_session() as session:
        result = await session.execute(select(Tenant.id).where(Tenant.is_active.is_(True)))
        tenant_ids = list(result.scalars().all())

    for tenant_id in tenant_ids:
        try:
            async with get_session() as tenant_session:
                await set_tenant_context(tenant_session, tenant_id)
                await NotificationService.dispatch_due_messages(tenant_session, limit=limit_per_tenant)
        except SQLAlchemyError, RuntimeError:
            logger.exception("Notification dispatch failed for tenant %s", tenant_id)


async def run_notification_dispatch_loop() -> None:
    """Poll and dispatch due notifications until canceled."""
    while True:
        try:
            await dispatch_due_notifications_for_all_tenants()
        except asyncio.CancelledError:
            raise
        except SQLAlchemyError, RuntimeError:
            logger.exception("Notification dispatch loop iteration failed")

        await asyncio.sleep(settings.notification_dispatch_interval_seconds)

"""Database dependencies."""

from collections.abc import AsyncGenerator
from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from src.database.client import get_session, set_tenant_context
from src.shared.tenancy.dependencies import require_tenant


async def get_db_session() -> AsyncGenerator[AsyncSession]:
    """Get a database session without tenant context.

    Use this for global models (e.g., users, refresh tokens) that are not
    protected by tenant Row-Level Security (RLS).
    """
    async with get_session() as session:
        yield session


async def get_tenant_db_session(request: Request) -> AsyncGenerator[AsyncSession]:
    """Get a database session with tenant context set for RLS.

    This dependency:
    1. Validates the tenant header (require_tenant)
    2. Creates a database session
    3. Sets app.current_tenant PostgreSQL variable for RLS policy enforcement

    Args:
        request: FastAPI request object with tenant_id in state

    Yields:
        AsyncSession with tenant context configured

    """
    tenant_id = await require_tenant(request)
    async with get_session() as session:
        await set_tenant_context(session, tenant_id)
        yield session

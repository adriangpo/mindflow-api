"""Database dependencies."""

from collections.abc import AsyncGenerator
from uuid import UUID

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from src.database.client import get_session, set_tenant_context


async def get_db_session(request: Request) -> AsyncGenerator[AsyncSession]:
    """Get database session with tenant context set for RLS.

    This dependency:
    1. Extracts tenant_id from request.state (set by TenantMiddleware)
    2. Creates a database session
    3. Sets app.current_tenant PostgreSQL variable for RLS policy enforcement

    Args:
        request: FastAPI request object with tenant_id in state

    Yields:
        AsyncSession with tenant context configured

    Raises:
        RuntimeError: If tenant_id is not in request.state (middleware not applied)

    """
    # Get tenant_id from request state (set by TenantMiddleware)
    tenant_id: UUID = request.state.tenant_id

    async with get_session() as session:
        # Set the tenant context for RLS policies
        await set_tenant_context(session, tenant_id)
        yield session

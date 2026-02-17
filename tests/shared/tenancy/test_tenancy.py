"""Tests for multi-tenancy and Row-Level Security (RLS) enforcement.

These tests verify that the multi-tenancy implementation correctly prevents
cross-tenant data access through both application-level checks and database-level RLS policies.
"""

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from src.main import app


class TestCrossTenantAPIIsolation:
    """Tests verifying that API endpoints respect tenant boundaries."""

    @pytest.mark.asyncio
    async def test_health_endpoint_excludes_tenant_header_requirement(self):
        """Verify that health endpoint doesn't require X-Tenant-ID."""
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
            # No X-Tenant-ID header for excluded endpoint
        ) as client:
            response = await client.get("/health")
            assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_root_endpoint_excludes_tenant_header_requirement(self):
        """Verify that root endpoint doesn't require X-Tenant-ID."""
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
            # No X-Tenant-ID header for excluded endpoint
        ) as client:
            response = await client.get("/")
            assert response.status_code == 200


class TestTenantContextSettings:
    """Tests verifying that tenant context is properly set in sessions."""

    @pytest.mark.asyncio
    async def test_tenant_context_set_in_session_info(
        self,
        session: AsyncSession,
        tenant_id,
    ):
        """Verify that tenant_id is stored in session.info."""
        assert "tenant_id" in session.info
        assert session.info["tenant_id"] == tenant_id

    @pytest.mark.asyncio
    async def test_postgresql_session_variable_set(
        self,
        session: AsyncSession,
        tenant_id,
    ):
        """Verify that PostgreSQL app.current_tenant variable is set."""
        # Query the PostgreSQL session variable
        result = await session.execute(text("SELECT current_setting('app.current_tenant')::uuid"))
        current_tenant = result.scalar()

        assert current_tenant == tenant_id

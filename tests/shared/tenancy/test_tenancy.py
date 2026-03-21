"""Tests for multi-tenancy and Row-Level Security (RLS) enforcement."""

from datetime import time
from uuid import uuid7

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from src.features.schedule_config.models import ScheduleConfiguration
from src.features.tenant.models import Tenant
from src.main import app

RLS_TEST_ROLE = "mindflow_rls_probe_role"


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


class TestTenantRLSPolicies:
    """Tests verifying migration-applied RLS definitions and runtime behavior."""

    @pytest.mark.asyncio
    async def test_rls_is_enabled_and_policy_exists_for_tenant_tables(self, session: AsyncSession):
        result = await session.execute(text("""
                SELECT
                    c.relname AS table_name,
                    c.relrowsecurity AS rls_enabled,
                    EXISTS (
                        SELECT 1
                        FROM pg_policies p
                        WHERE p.schemaname = 'public'
                          AND p.tablename = c.relname
                    ) AS has_policy
                FROM pg_class c
                JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE n.nspname = 'public'
                  AND c.relname IN (
                      'financial_entries',
                      'notification_settings',
                      'notification_patient_preferences',
                      'notification_user_profiles',
                      'notification_messages',
                      'schedule_configurations',
                      'patients',
                      'schedule_appointments',
                      'schedule_appointment_history',
                      'medical_records'
                  )
                ORDER BY c.relname
                """))
        rows = result.mappings().all()

        assert len(rows) == 10
        assert all(row["rls_enabled"] for row in rows)
        assert all(row["has_policy"] for row in rows)

    @pytest.mark.asyncio
    async def test_schedule_configuration_rls_filters_rows_by_current_tenant(
        self,
        session: AsyncSession,
        tenant_id,
        make_user,
    ):
        other_tenant_id = uuid7()
        session.add(
            Tenant(
                id=other_tenant_id,
                name=f"Tenant {other_tenant_id.hex[:12]}",
                slug=f"tenant-{other_tenant_id.hex[:12]}",
                is_active=True,
            )
        )
        owner = await make_user(tenant_ids=[tenant_id, other_tenant_id])

        session.add_all(
            [
                ScheduleConfiguration(
                    user_id=owner.id,
                    tenant_id=tenant_id,
                    working_days=["monday"],
                    start_time=time(hour=8),
                    end_time=time(hour=12),
                    appointment_duration_minutes=50,
                    break_between_appointments_minutes=10,
                ),
                ScheduleConfiguration(
                    user_id=owner.id,
                    tenant_id=other_tenant_id,
                    working_days=["tuesday"],
                    start_time=time(hour=13),
                    end_time=time(hour=18),
                    appointment_duration_minutes=45,
                    break_between_appointments_minutes=15,
                ),
            ]
        )
        await session.flush()

        try:
            await session.execute(text(f"""
                    DO $$
                    BEGIN
                        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{RLS_TEST_ROLE}') THEN
                            CREATE ROLE {RLS_TEST_ROLE};
                        END IF;
                    END
                    $$;
                    """))
            await session.execute(text(f"GRANT USAGE ON SCHEMA public TO {RLS_TEST_ROLE}"))
            await session.execute(text(f"GRANT SELECT ON TABLE schedule_configurations TO {RLS_TEST_ROLE}"))
            await session.execute(text(f"SET LOCAL ROLE {RLS_TEST_ROLE}"))
        except DBAPIError as exc:
            pytest.skip(f"Could not create/switch role for RLS behavior probe: {exc}")

        own_tenant_rows = await session.execute(text("""
                SELECT tenant_id
                FROM schedule_configurations
                ORDER BY id
                """))
        assert [row[0] for row in own_tenant_rows.fetchall()] == [tenant_id]

        await session.execute(text(f"SET LOCAL app.current_tenant = '{other_tenant_id}'"))
        other_tenant_rows = await session.execute(text("""
                SELECT tenant_id
                FROM schedule_configurations
                ORDER BY id
                """))
        assert [row[0] for row in other_tenant_rows.fetchall()] == [other_tenant_id]

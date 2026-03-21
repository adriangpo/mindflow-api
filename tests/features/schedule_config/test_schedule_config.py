"""Tests for schedule configuration feature."""

from datetime import time
from uuid import UUID

import pytest
from fastapi import status
from sqlalchemy.exc import IntegrityError

from src.features.auth.dependencies import get_current_active_user, get_current_user
from src.features.schedule_config.exceptions import ScheduleConfigurationAlreadyExists
from src.features.schedule_config.schemas import (
    ScheduleConfigurationCreateRequest,
    ScheduleConfigurationUpdateRequest,
    WeekDay,
)
from src.features.schedule_config.service import ScheduleConfigurationService
from src.features.user.models import UserRole
from src.main import app
from src.shared.pagination.pagination import PaginationParams


def _tenant_id_from_client(client) -> UUID:
    """Extract tenant UUID from test client default headers."""
    tenant_id_header = client.headers.get("X-Tenant-ID")
    assert tenant_id_header is not None
    return UUID(tenant_id_header)


class TestScheduleConfigurationService:
    """Service-layer tests for schedule configuration."""

    async def test_create_configuration_success(self, session, make_user):
        user = await make_user()

        request = ScheduleConfigurationCreateRequest(
            working_days=[WeekDay.MONDAY, WeekDay.WEDNESDAY, WeekDay.FRIDAY],
            start_time=time(8, 0),
            end_time=time(18, 0),
            appointment_duration_minutes=50,
            break_between_appointments_minutes=10,
        )

        configuration = await ScheduleConfigurationService.create_configuration(session, user.id, request)
        await session.commit()
        await session.refresh(configuration)

        assert configuration.user_id == user.id
        assert configuration.working_days == ["monday", "wednesday", "friday"]
        assert configuration.appointment_duration_minutes == 50
        assert configuration.break_between_appointments_minutes == 10

    async def test_tenant_can_only_have_one_configuration(self, session, make_user):
        owner = await make_user(email="owner_sc@example.com", username="owner_sc")
        assistant = await make_user(email="assistant_sc@example.com", username="assistant_sc")

        owner_request = ScheduleConfigurationCreateRequest(
            working_days=[WeekDay.MONDAY],
            start_time=time(8, 0),
            end_time=time(17, 0),
            appointment_duration_minutes=50,
            break_between_appointments_minutes=10,
        )
        assistant_request = ScheduleConfigurationCreateRequest(
            working_days=[WeekDay.TUESDAY],
            start_time=time(9, 0),
            end_time=time(18, 0),
            appointment_duration_minutes=45,
            break_between_appointments_minutes=15,
        )
        await ScheduleConfigurationService.create_configuration(session, owner.id, owner_request)
        await session.flush()

        with pytest.raises(ScheduleConfigurationAlreadyExists):
            await ScheduleConfigurationService.create_configuration(session, assistant.id, assistant_request)

    async def test_list_configurations_with_pagination(self, session, make_user):
        user_1 = await make_user(email="sc_user1@example.com", username="sc_user1")

        await ScheduleConfigurationService.create_configuration(
            session,
            user_1.id,
            ScheduleConfigurationCreateRequest(
                working_days=[WeekDay.MONDAY],
                start_time=time(8, 0),
                end_time=time(17, 0),
                appointment_duration_minutes=50,
                break_between_appointments_minutes=10,
            ),
        )
        await session.flush()

        items, total = await ScheduleConfigurationService.list_configurations(
            session=session,
            pagination=PaginationParams(page=1, page_size=1),
        )
        assert total == 1
        assert len(items) == 1

    async def test_update_configuration(self, session, make_user):
        user = await make_user()
        configuration = await ScheduleConfigurationService.create_configuration(
            session,
            user.id,
            ScheduleConfigurationCreateRequest(
                working_days=[WeekDay.MONDAY],
                start_time=time(8, 0),
                end_time=time(17, 0),
                appointment_duration_minutes=50,
                break_between_appointments_minutes=10,
            ),
        )
        await session.flush()

        updated = await ScheduleConfigurationService.update_configuration(
            session,
            configuration,
            ScheduleConfigurationUpdateRequest(appointment_duration_minutes=40),
        )
        await session.commit()

        assert updated.appointment_duration_minutes == 40


class TestScheduleConfigurationAPI:
    """API-layer tests for schedule configuration."""

    async def test_user_can_create_own_configuration(self, auth_client):
        client, user = auth_client
        user.tenant_ids = [_tenant_id_from_client(client)]
        payload = {
            "working_days": ["monday", "wednesday"],
            "start_time": "08:00",
            "end_time": "17:00",
            "appointment_duration_minutes": 50,
            "break_between_appointments_minutes": 10,
        }

        response = await client.post("/api/schedule-configurations", json=payload)

        assert response.status_code == status.HTTP_200_OK
        body = response.json()
        assert body["working_days"] == ["monday", "wednesday"]

    async def test_assistant_can_get_tenant_configuration(self, auth_client, make_user, session):
        client, _ = auth_client
        tenant_id = _tenant_id_from_client(client)
        owner = await make_user(email="owner_sc_get@example.com", username="owner_sc_get")
        assistant = await make_user(
            email="assistant_sc_get@example.com",
            username="assistant_sc_get",
            roles=[UserRole.ASSISTANT],
            tenant_ids=[tenant_id],
        )
        config = await ScheduleConfigurationService.create_configuration(
            session,
            owner.id,
            ScheduleConfigurationCreateRequest(
                working_days=[WeekDay.FRIDAY],
                start_time=time(8, 0),
                end_time=time(17, 0),
                appointment_duration_minutes=50,
                break_between_appointments_minutes=10,
            ),
        )
        await session.commit()
        await session.refresh(config)

        async def override_get_current_user():
            return assistant

        app.dependency_overrides[get_current_user] = override_get_current_user
        app.dependency_overrides[get_current_active_user] = override_get_current_user
        try:
            response = await client.get(f"/api/schedule-configurations/{config.id}")
        finally:
            app.dependency_overrides.pop(get_current_user, None)
            app.dependency_overrides.pop(get_current_active_user, None)

        assert response.status_code == status.HTTP_200_OK

    async def test_list_returns_tenant_configuration(self, auth_client, session):
        client, user = auth_client
        user.tenant_ids = [_tenant_id_from_client(client)]

        await ScheduleConfigurationService.create_configuration(
            session,
            user.id,
            ScheduleConfigurationCreateRequest(
                working_days=[WeekDay.MONDAY],
                start_time=time(8, 0),
                end_time=time(17, 0),
                appointment_duration_minutes=50,
                break_between_appointments_minutes=10,
            ),
        )
        await session.commit()

        response = await client.get("/api/schedule-configurations?page=1&page_size=10")

        assert response.status_code == status.HTTP_200_OK
        body = response.json()
        assert body["total"] == 1
        assert len(body["configurations"]) == 1

    async def test_cannot_create_second_tenant_configuration(self, auth_client):
        client, user = auth_client
        user.tenant_ids = [_tenant_id_from_client(client)]
        payload = {
            "working_days": ["monday", "wednesday"],
            "start_time": "08:00",
            "end_time": "17:00",
            "appointment_duration_minutes": 50,
            "break_between_appointments_minutes": 10,
        }

        first_response = await client.post("/api/schedule-configurations", json=payload)
        assert first_response.status_code == status.HTTP_200_OK

        second_response = await client.post(
            "/api/schedule-configurations",
            json={
                "working_days": ["tuesday"],
                "start_time": "09:00",
                "end_time": "18:00",
                "appointment_duration_minutes": 45,
                "break_between_appointments_minutes": 15,
            },
        )
        assert second_response.status_code == status.HTTP_409_CONFLICT

    async def test_user_not_assigned_to_tenant_gets_403(self, auth_client):
        client, user = auth_client
        user.tenant_ids = []

        response = await client.get("/api/schedule-configurations")

        assert response.status_code == status.HTTP_403_FORBIDDEN

    async def test_create_maps_unique_integrity_error_to_409(self, auth_client, session, monkeypatch):
        client, user = auth_client
        user.tenant_ids = [_tenant_id_from_client(client)]

        async def commit_with_unique_violation():
            raise IntegrityError(
                statement="INSERT INTO schedule_configurations ...",
                params={},
                orig=Exception("duplicate key value violates unique constraint uq_schedule_configuration_tenant"),
            )

        monkeypatch.setattr(session, "commit", commit_with_unique_violation)

        response = await client.post(
            "/api/schedule-configurations",
            json={
                "working_days": ["monday", "wednesday"],
                "start_time": "08:00",
                "end_time": "17:00",
                "appointment_duration_minutes": 50,
                "break_between_appointments_minutes": 10,
            },
        )

        assert response.status_code == status.HTTP_409_CONFLICT

    async def test_invalid_time_window_returns_422(self, auth_client):
        client, user = auth_client
        user.tenant_ids = [_tenant_id_from_client(client)]
        payload = {
            "working_days": ["monday"],
            "start_time": "18:00",
            "end_time": "08:00",
            "appointment_duration_minutes": 50,
            "break_between_appointments_minutes": 10,
        }

        response = await client.post("/api/schedule-configurations", json=payload)

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT

    async def test_update_with_invalid_merged_time_window_returns_422(self, auth_client):
        client, user = auth_client
        user.tenant_ids = [_tenant_id_from_client(client)]

        create_response = await client.post(
            "/api/schedule-configurations",
            json={
                "working_days": ["monday"],
                "start_time": "08:00",
                "end_time": "17:00",
                "appointment_duration_minutes": 50,
                "break_between_appointments_minutes": 10,
            },
        )
        configuration_id = create_response.json()["id"]

        response = await client.put(
            f"/api/schedule-configurations/{configuration_id}",
            json={"start_time": "18:00"},
        )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT

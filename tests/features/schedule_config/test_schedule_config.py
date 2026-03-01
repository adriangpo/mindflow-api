"""Tests for schedule configuration feature."""

from datetime import time
from uuid import uuid7

import pytest
from fastapi import status

from src.features.schedule_config.exceptions import ScheduleConfigurationAlreadyExists
from src.features.schedule_config.schemas import (
    ScheduleConfigurationCreateRequest,
    ScheduleConfigurationUpdateRequest,
    WeekDay,
)
from src.features.schedule_config.service import ScheduleConfigurationService
from src.shared.pagination.pagination import PaginationParams


class TestScheduleConfigurationService:
    """Service-layer tests for schedule configuration."""

    async def test_create_configuration_success(self, session, make_user):
        user = await make_user()
        session.info["tenant_id"] = uuid7()

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

    async def test_user_can_only_have_one_configuration(self, session, make_user):
        user = await make_user()
        session.info["tenant_id"] = uuid7()

        request = ScheduleConfigurationCreateRequest(
            working_days=[WeekDay.MONDAY],
            start_time=time(8, 0),
            end_time=time(17, 0),
            appointment_duration_minutes=50,
            break_between_appointments_minutes=10,
        )
        await ScheduleConfigurationService.create_configuration(session, user.id, request)
        await session.flush()

        with pytest.raises(ScheduleConfigurationAlreadyExists):
            await ScheduleConfigurationService.create_configuration(session, user.id, request)

    async def test_list_configurations_with_pagination(self, session, make_user):
        session.info["tenant_id"] = uuid7()
        user_1 = await make_user(email="sc_user1@example.com", username="sc_user1")
        user_2 = await make_user(email="sc_user2@example.com", username="sc_user2")

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
        await ScheduleConfigurationService.create_configuration(
            session,
            user_2.id,
            ScheduleConfigurationCreateRequest(
                working_days=[WeekDay.TUESDAY],
                start_time=time(9, 0),
                end_time=time(18, 0),
                appointment_duration_minutes=45,
                break_between_appointments_minutes=15,
            ),
        )
        await session.flush()

        items, total = await ScheduleConfigurationService.list_configurations(
            session=session,
            pagination=PaginationParams(page=1, page_size=1),
        )
        assert total == 2
        assert len(items) == 1

    async def test_update_configuration(self, session, make_user):
        user = await make_user()
        session.info["tenant_id"] = uuid7()
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
        client, _ = auth_client
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

    async def test_user_cannot_get_another_users_configuration(self, auth_client, make_user, session):
        client, _ = auth_client
        other_user = await make_user(email="other_sc_get@example.com", username="other_sc_get")
        config = await ScheduleConfigurationService.create_configuration(
            session,
            other_user.id,
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

        response = await client.get(f"/api/schedule-configurations/{config.id}")

        assert response.status_code == status.HTTP_403_FORBIDDEN

    async def test_list_only_returns_current_users_configurations(self, auth_client, make_user, session):
        client, user = auth_client
        other_user = await make_user(email="other_sc_list@example.com", username="other_sc_list")

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
        await ScheduleConfigurationService.create_configuration(
            session,
            other_user.id,
            ScheduleConfigurationCreateRequest(
                working_days=[WeekDay.TUESDAY],
                start_time=time(9, 0),
                end_time=time(18, 0),
                appointment_duration_minutes=45,
                break_between_appointments_minutes=15,
            ),
        )
        await session.commit()

        response = await client.get("/api/schedule-configurations?page=1&page_size=10")

        assert response.status_code == status.HTTP_200_OK
        body = response.json()
        assert body["total"] == 1
        assert len(body["configurations"]) == 1

    async def test_invalid_time_window_returns_422(self, auth_client):
        client, _ = auth_client
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
        client, _ = auth_client

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

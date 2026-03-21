"""Tests for schedule feature."""

from datetime import UTC, date, datetime, time, timedelta
from decimal import Decimal
from uuid import UUID

import pytest
from fastapi import status

from src.features.auth.dependencies import get_current_active_user, get_current_user
from src.features.patient.schemas import PatientCreateRequest, PatientQuickCreateRequest
from src.features.patient.service import PatientService
from src.features.schedule.exceptions import (
    ScheduleInvalidStatusTransition,
    ScheduleSlotUnavailable,
)
from src.features.schedule.schemas import (
    AppointmentModality,
    AppointmentStatus,
    PaymentStatus,
    ScheduleAppointmentCreateRequest,
    ScheduleAppointmentStatusUpdateRequest,
    ScheduleAppointmentUpdateRequest,
    ScheduleCalendarView,
)
from src.features.schedule.service import ScheduleService
from src.features.schedule_config.schemas import ScheduleConfigurationCreateRequest, WeekDay
from src.features.schedule_config.service import ScheduleConfigurationService
from src.features.user.models import UserRole
from src.main import app
from src.shared.pagination.pagination import PaginationParams


def _tenant_id_from_client(client) -> UUID:
    tenant_id_header = client.headers.get("X-Tenant-ID")
    assert tenant_id_header is not None
    return UUID(tenant_id_header)


def _next_weekday(target_weekday: int) -> date:
    today = datetime.now(UTC).date()
    delta = (target_weekday - today.weekday()) % 7
    if delta == 0:
        delta = 7
    return today + timedelta(days=delta)


async def _create_schedule_configuration(session, user_id: int):
    configuration = await ScheduleConfigurationService.create_configuration(
        session,
        user_id,
        ScheduleConfigurationCreateRequest(
            working_days=[
                WeekDay.MONDAY,
                WeekDay.TUESDAY,
                WeekDay.WEDNESDAY,
                WeekDay.THURSDAY,
                WeekDay.FRIDAY,
                WeekDay.SATURDAY,
                WeekDay.SUNDAY,
            ],
            start_time=time(8, 0),
            end_time=time(18, 0),
            appointment_duration_minutes=50,
            break_between_appointments_minutes=10,
        ),
    )
    await session.flush()
    return configuration


async def _create_patient(session, *, cpf: str = "52998224725"):
    patient = await PatientService.create_patient(
        session,
        PatientCreateRequest(
            full_name="Paciente Agenda",
            birth_date=date(1990, 1, 1),
            cpf=cpf,
            cep="19900000",
            phone_number="14999999999",
            session_price=Decimal("200.00"),
            session_frequency="weekly",
        ),
    )
    await session.flush()
    return patient


class TestScheduleService:
    """Service-layer tests for schedule operations."""

    async def test_create_appointment_success(self, session, make_user):
        user = await make_user()
        patient = await _create_patient(session)
        await _create_schedule_configuration(session, user.id)

        starts_at = datetime.now(UTC) + timedelta(days=1)
        appointment = await ScheduleService.create_appointment(
            session,
            user.id,
            ScheduleAppointmentCreateRequest(
                patient_id=patient.id,
                starts_at=starts_at,
                modality=AppointmentModality.IN_PERSON,
            ),
        )
        await session.commit()

        assert appointment.status == AppointmentStatus.SCHEDULED.value
        assert appointment.payment_status == PaymentStatus.PENDING.value
        assert appointment.charge_amount == Decimal("200.00")
        assert appointment.paid_at is None
        assert appointment.ends_at == starts_at + timedelta(minutes=50)

    async def test_create_paid_appointment_sets_paid_at(self, session, make_user):
        user = await make_user()
        patient = await _create_patient(session)
        await _create_schedule_configuration(session, user.id)

        appointment = await ScheduleService.create_appointment(
            session,
            user.id,
            ScheduleAppointmentCreateRequest(
                patient_id=patient.id,
                starts_at=datetime.now(UTC) + timedelta(days=1),
                modality=AppointmentModality.IN_PERSON,
                payment_status=PaymentStatus.PAID,
            ),
        )
        await session.commit()

        assert appointment.charge_amount == Decimal("200.00")
        assert appointment.paid_at is not None

    async def test_create_appointment_blocks_occupied_slot(self, session, make_user):
        user = await make_user()
        patient_1 = await _create_patient(session, cpf="11144477735")
        patient_2 = await _create_patient(session, cpf="39053344705")
        await _create_schedule_configuration(session, user.id)

        starts_at = datetime.now(UTC) + timedelta(days=1)
        payload = ScheduleAppointmentCreateRequest(
            patient_id=patient_1.id,
            starts_at=starts_at,
            modality=AppointmentModality.IN_PERSON,
        )

        await ScheduleService.create_appointment(session, user.id, payload)
        await session.flush()

        with pytest.raises(ScheduleSlotUnavailable):
            await ScheduleService.create_appointment(
                session,
                user.id,
                ScheduleAppointmentCreateRequest(
                    patient_id=patient_2.id,
                    starts_at=starts_at,
                    modality=AppointmentModality.ONLINE,
                ),
            )

    async def test_update_datetime_marks_rescheduled(self, session, make_user):
        user = await make_user()
        patient = await _create_patient(session)
        await _create_schedule_configuration(session, user.id)

        starts_at = datetime.now(UTC) + timedelta(days=1)
        appointment = await ScheduleService.create_appointment(
            session,
            user.id,
            ScheduleAppointmentCreateRequest(
                patient_id=patient.id,
                starts_at=starts_at,
                modality=AppointmentModality.IN_PERSON,
            ),
        )
        await session.flush()

        updated = await ScheduleService.update_appointment(
            session,
            user.id,
            appointment,
            ScheduleAppointmentUpdateRequest(starts_at=starts_at + timedelta(hours=2)),
        )
        await session.commit()

        history = await ScheduleService.get_appointment_history(session, appointment.id)

        assert updated.status == AppointmentStatus.RESCHEDULED.value
        assert any(event.event_type == "rescheduled" for event in history)

    async def test_cancel_status_can_mark_not_charged(self, session, make_user):
        user = await make_user()
        patient = await _create_patient(session)
        await _create_schedule_configuration(session, user.id)

        appointment = await ScheduleService.create_appointment(
            session,
            user.id,
            ScheduleAppointmentCreateRequest(
                patient_id=patient.id,
                starts_at=datetime.now(UTC) + timedelta(days=1),
                modality=AppointmentModality.IN_PERSON,
            ),
        )
        await session.flush()

        updated = await ScheduleService.update_appointment_status(
            session,
            user.id,
            appointment,
            ScheduleAppointmentStatusUpdateRequest(
                status=AppointmentStatus.CANCELED,
                mark_as_not_charged=True,
            ),
        )
        await session.commit()

        assert updated.status == AppointmentStatus.CANCELED.value
        assert updated.payment_status == PaymentStatus.NOT_CHARGED.value
        assert updated.paid_at is None

    async def test_payment_status_updates_manage_paid_at(self, session, make_user):
        user = await make_user()
        patient = await _create_patient(session)
        await _create_schedule_configuration(session, user.id)

        appointment = await ScheduleService.create_appointment(
            session,
            user.id,
            ScheduleAppointmentCreateRequest(
                patient_id=patient.id,
                starts_at=datetime.now(UTC) + timedelta(days=1),
                modality=AppointmentModality.IN_PERSON,
            ),
        )
        await session.flush()

        updated = await ScheduleService.update_payment_status(
            session,
            user.id,
            appointment,
            payment_status=PaymentStatus.PAID,
            reason="received payment",
        )
        paid_at = updated.paid_at
        assert paid_at is not None

        reverted = await ScheduleService.update_payment_status(
            session,
            user.id,
            appointment,
            payment_status=PaymentStatus.PENDING,
            reason="reopened invoice",
        )
        await session.commit()

        assert reverted.paid_at is None

    async def test_patient_session_price_change_does_not_mutate_existing_charge_amount(self, session, make_user):
        user = await make_user()
        patient = await _create_patient(session)
        await _create_schedule_configuration(session, user.id)

        appointment = await ScheduleService.create_appointment(
            session,
            user.id,
            ScheduleAppointmentCreateRequest(
                patient_id=patient.id,
                starts_at=datetime.now(UTC) + timedelta(days=1),
                modality=AppointmentModality.IN_PERSON,
            ),
        )
        await session.flush()

        patient.session_price = Decimal("350.00")
        await session.commit()
        await session.refresh(appointment)

        assert appointment.charge_amount == Decimal("200.00")

    async def test_quick_registered_patient_without_amount_snapshots_zero(self, session, make_user):
        user = await make_user()
        quick_patient = await PatientService.create_quick_patient(
            session,
            PatientQuickCreateRequest(full_name="Paciente Rapido"),
        )
        await _create_schedule_configuration(session, user.id)

        appointment = await ScheduleService.create_appointment(
            session,
            user.id,
            ScheduleAppointmentCreateRequest(
                patient_id=quick_patient.id,
                starts_at=datetime.now(UTC) + timedelta(days=1),
                modality=AppointmentModality.ONLINE,
                payment_status=PaymentStatus.PAID,
            ),
        )
        await session.commit()

        assert appointment.charge_amount == Decimal("0.00")
        assert appointment.paid_at is not None

    async def test_get_available_slots_excludes_occupied_time(self, session, make_user):
        user = await make_user()
        patient = await _create_patient(session)

        await ScheduleConfigurationService.create_configuration(
            session,
            user.id,
            ScheduleConfigurationCreateRequest(
                working_days=[WeekDay.MONDAY],
                start_time=time(8, 0),
                end_time=time(10, 0),
                appointment_duration_minutes=60,
                break_between_appointments_minutes=0,
            ),
        )
        await session.flush()

        monday = _next_weekday(0)
        occupied_start = datetime.combine(monday, time(8, 0), tzinfo=UTC)

        await ScheduleService.create_appointment(
            session,
            user.id,
            ScheduleAppointmentCreateRequest(
                patient_id=patient.id,
                starts_at=occupied_start,
                ends_at=occupied_start + timedelta(hours=1),
                modality=AppointmentModality.ONLINE,
            ),
        )
        await session.commit()

        working_day, duration, interval, slots = await ScheduleService.get_available_slots(session, monday)

        assert working_day is True
        assert duration == 60
        assert interval == 0
        assert len(slots) == 1
        assert slots[0].starts_at == datetime.combine(monday, time(9, 0), tzinfo=UTC)

    async def test_terminal_status_cannot_be_rescheduled(self, session, make_user):
        user = await make_user()
        patient = await _create_patient(session)
        await _create_schedule_configuration(session, user.id)

        starts_at = datetime.now(UTC) + timedelta(days=1)
        appointment = await ScheduleService.create_appointment(
            session,
            user.id,
            ScheduleAppointmentCreateRequest(
                patient_id=patient.id,
                starts_at=starts_at,
                modality=AppointmentModality.IN_PERSON,
            ),
        )
        await ScheduleService.update_appointment_status(
            session,
            user.id,
            appointment,
            ScheduleAppointmentStatusUpdateRequest(status=AppointmentStatus.CANCELED),
        )

        with pytest.raises(ScheduleInvalidStatusTransition):
            await ScheduleService.update_appointment(
                session,
                user.id,
                appointment,
                ScheduleAppointmentUpdateRequest(starts_at=starts_at + timedelta(hours=2)),
            )

    async def test_list_day_includes_appointments_overlapping_view_window(self, session, make_user):
        user = await make_user()
        patient = await _create_patient(session)
        await _create_schedule_configuration(session, user.id)

        reference_date = datetime.now(UTC).date() + timedelta(days=3)
        starts_at = datetime.combine(reference_date - timedelta(days=1), time(23, 30), tzinfo=UTC)
        ends_at = datetime.combine(reference_date, time(0, 30), tzinfo=UTC)

        appointment = await ScheduleService.create_appointment(
            session,
            user.id,
            ScheduleAppointmentCreateRequest(
                patient_id=patient.id,
                starts_at=starts_at,
                ends_at=ends_at,
                modality=AppointmentModality.ONLINE,
            ),
        )
        await session.commit()

        items, total = await ScheduleService.list_appointments(
            session=session,
            pagination=PaginationParams(page=1, page_size=10),
            view=ScheduleCalendarView.DAY,
            reference_date=reference_date,
            start_date=None,
            end_date=None,
            patient_id=None,
            statuses=None,
            payment_statuses=None,
            include_deleted=False,
        )

        assert total == 1
        assert len(items) == 1
        assert items[0].id == appointment.id


class TestScheduleAPI:
    """API-layer tests for schedule operations."""

    async def test_owner_can_create_appointment_and_fetch_detail(self, auth_client, session):
        client, user = auth_client
        user.tenant_ids = [_tenant_id_from_client(client)]

        patient = await _create_patient(session)
        await _create_schedule_configuration(session, user.id)
        await session.commit()

        starts_at = (datetime.now(UTC) + timedelta(days=1)).replace(microsecond=0)
        create_response = await client.post(
            "/api/schedule/appointments",
            json={
                "patient_id": patient.id,
                "starts_at": starts_at.isoformat(),
                "modality": "in_person",
            },
        )

        assert create_response.status_code == status.HTTP_200_OK
        appointment_id = create_response.json()["id"]

        detail_response = await client.get(f"/api/schedule/appointments/{appointment_id}")
        assert detail_response.status_code == status.HTTP_200_OK
        assert len(detail_response.json()["history"]) == 1

    async def test_assistant_can_create_appointment(self, auth_client, make_user, session):
        client, owner = auth_client
        tenant_id = _tenant_id_from_client(client)
        owner.tenant_ids = [tenant_id]

        assistant = await make_user(
            email="assistant_schedule@example.com",
            username="assistant_schedule",
            roles=[UserRole.ASSISTANT],
            tenant_ids=[tenant_id],
        )

        patient = await _create_patient(session)
        await _create_schedule_configuration(session, owner.id)
        await session.commit()

        async def override_get_current_user():
            return assistant

        app.dependency_overrides[get_current_user] = override_get_current_user
        app.dependency_overrides[get_current_active_user] = override_get_current_user
        try:
            response = await client.post(
                "/api/schedule/appointments",
                json={
                    "patient_id": patient.id,
                    "starts_at": (datetime.now(UTC) + timedelta(days=1)).replace(microsecond=0).isoformat(),
                    "modality": "online",
                },
            )
        finally:
            app.dependency_overrides.pop(get_current_user, None)
            app.dependency_overrides.pop(get_current_active_user, None)

        assert response.status_code == status.HTTP_200_OK

    async def test_user_not_assigned_to_tenant_gets_403(self, auth_client):
        client, user = auth_client
        user.tenant_ids = []

        response = await client.get("/api/schedule/appointments")

        assert response.status_code == status.HTTP_403_FORBIDDEN

    async def test_create_outside_configuration_returns_warning(self, auth_client, session):
        client, user = auth_client
        user.tenant_ids = [_tenant_id_from_client(client)]

        patient = await _create_patient(session)
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

        monday = _next_weekday(0)
        response = await client.post(
            "/api/schedule/appointments",
            json={
                "patient_id": patient.id,
                "starts_at": datetime.combine(monday, time(20, 0), tzinfo=UTC).isoformat(),
                "modality": "in_person",
            },
        )

        assert response.status_code == status.HTTP_200_OK
        body = response.json()
        assert body["out_of_schedule_warning"] is True
        assert body["out_of_schedule_warning_reason"] is not None

    async def test_delete_requires_confirmation_and_hides_appointment(self, auth_client, session):
        client, user = auth_client
        user.tenant_ids = [_tenant_id_from_client(client)]

        patient = await _create_patient(session)
        await _create_schedule_configuration(session, user.id)
        await session.commit()

        starts_at = (datetime.now(UTC) + timedelta(days=1)).replace(microsecond=0)
        create_response = await client.post(
            "/api/schedule/appointments",
            json={
                "patient_id": patient.id,
                "starts_at": starts_at.isoformat(),
                "modality": "in_person",
            },
        )
        appointment_id = create_response.json()["id"]

        invalid_delete = await client.request(
            "DELETE",
            f"/api/schedule/appointments/{appointment_id}",
            json={
                "confirm": False,
                "reason": "created by mistake",
            },
        )
        assert invalid_delete.status_code == status.HTTP_400_BAD_REQUEST

        valid_delete = await client.request(
            "DELETE",
            f"/api/schedule/appointments/{appointment_id}",
            json={
                "confirm": True,
                "reason": "created by mistake",
            },
        )
        assert valid_delete.status_code == status.HTTP_200_OK

        day_query = starts_at.date().isoformat()
        list_response = await client.get(f"/api/schedule/appointments?reference_date={day_query}&view=day")

        assert list_response.status_code == status.HTTP_200_OK
        assert list_response.json()["total"] == 0

    async def test_status_scheduled_manual_update_returns_422(self, auth_client, session):
        client, user = auth_client
        user.tenant_ids = [_tenant_id_from_client(client)]

        patient = await _create_patient(session)
        await _create_schedule_configuration(session, user.id)
        await session.commit()

        create_response = await client.post(
            "/api/schedule/appointments",
            json={
                "patient_id": patient.id,
                "starts_at": (datetime.now(UTC) + timedelta(days=1)).replace(microsecond=0).isoformat(),
                "modality": "in_person",
            },
        )
        appointment_id = create_response.json()["id"]

        update_response = await client.patch(
            f"/api/schedule/appointments/{appointment_id}/status",
            json={"status": "scheduled"},
        )

        assert update_response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT

    async def test_availability_endpoint_returns_available_slots(self, auth_client, session):
        client, user = auth_client
        user.tenant_ids = [_tenant_id_from_client(client)]

        await ScheduleConfigurationService.create_configuration(
            session,
            user.id,
            ScheduleConfigurationCreateRequest(
                working_days=[WeekDay.MONDAY],
                start_time=time(8, 0),
                end_time=time(10, 0),
                appointment_duration_minutes=60,
                break_between_appointments_minutes=0,
            ),
        )
        await session.commit()

        monday = _next_weekday(0)
        response = await client.get(f"/api/schedule/availability?target_date={monday.isoformat()}")

        assert response.status_code == status.HTTP_200_OK
        body = response.json()
        assert body["working_day"] is True
        assert len(body["available_slots"]) == 2

    async def test_list_custom_range_requires_both_dates(self, auth_client):
        client, user = auth_client
        user.tenant_ids = [_tenant_id_from_client(client)]

        response = await client.get("/api/schedule/appointments?view=custom&start_date=2026-03-01")

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    async def test_canceled_appointment_cannot_be_reopened_via_update(self, auth_client, session):
        client, user = auth_client
        user.tenant_ids = [_tenant_id_from_client(client)]

        patient = await _create_patient(session)
        await _create_schedule_configuration(session, user.id)
        await session.commit()

        starts_at = (datetime.now(UTC) + timedelta(days=1)).replace(microsecond=0)
        create_response = await client.post(
            "/api/schedule/appointments",
            json={
                "patient_id": patient.id,
                "starts_at": starts_at.isoformat(),
                "modality": "in_person",
            },
        )
        appointment_id = create_response.json()["id"]

        cancel_response = await client.patch(
            f"/api/schedule/appointments/{appointment_id}/status",
            json={"status": "canceled"},
        )
        assert cancel_response.status_code == status.HTTP_200_OK

        update_response = await client.put(
            f"/api/schedule/appointments/{appointment_id}",
            json={"starts_at": (starts_at + timedelta(hours=2)).isoformat()},
        )
        assert update_response.status_code == status.HTTP_409_CONFLICT

    async def test_service_list_custom_view_with_filters(self, session, make_user):
        user = await make_user()
        patient = await _create_patient(session)
        await _create_schedule_configuration(session, user.id)

        starts_at = datetime.now(UTC) + timedelta(days=1)
        appointment = await ScheduleService.create_appointment(
            session,
            user.id,
            ScheduleAppointmentCreateRequest(
                patient_id=patient.id,
                starts_at=starts_at,
                modality=AppointmentModality.IN_PERSON,
            ),
        )
        await ScheduleService.update_appointment_status(
            session,
            user.id,
            appointment,
            ScheduleAppointmentStatusUpdateRequest(status=AppointmentStatus.COMPLETED),
        )
        await session.commit()

        items, total = await ScheduleService.list_appointments(
            session=session,
            pagination=PaginationParams(page=1, page_size=10),
            view=ScheduleCalendarView.CUSTOM,
            reference_date=None,
            start_date=starts_at.date(),
            end_date=starts_at.date(),
            patient_id=patient.id,
            statuses=[AppointmentStatus.COMPLETED],
            payment_statuses=None,
            include_deleted=False,
        )

        assert total == 1
        assert len(items) == 1
        assert items[0].id == appointment.id

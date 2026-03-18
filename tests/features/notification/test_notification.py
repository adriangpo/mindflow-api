"""Tests for notification feature."""

from datetime import UTC, date, datetime, time, timedelta
from decimal import Decimal
from uuid import UUID

from fastapi import status
from sqlalchemy import select

from src.features.auth.dependencies import get_current_active_user, get_current_user
from src.features.notification.models import NotificationMessage
from src.features.notification.schemas import (
    NotificationEventType,
    NotificationMessageStatus,
    NotificationPatientPreferenceUpsertRequest,
    NotificationRecipientType,
    NotificationUserProfileUpsertRequest,
)
from src.features.notification.service import NotificationService
from src.features.patient.schemas import PatientCreateRequest
from src.features.patient.service import PatientService
from src.features.schedule.schemas import (
    AppointmentModality,
    AppointmentStatus,
    ScheduleAppointmentCreateRequest,
    ScheduleAppointmentStatusUpdateRequest,
)
from src.features.schedule.service import ScheduleService
from src.features.schedule_config.schemas import ScheduleConfigurationCreateRequest, WeekDay
from src.features.schedule_config.service import ScheduleConfigurationService
from src.features.user.models import UserRole
from src.main import app


def _tenant_id_from_client(client) -> UUID:
    tenant_id_header = client.headers.get("X-Tenant-ID")
    assert tenant_id_header is not None
    return UUID(tenant_id_header)


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


async def _create_patient(session, *, cpf: str = "52998224725", phone_number: str = "14999999999"):
    patient = await PatientService.create_patient(
        session,
        PatientCreateRequest(
            full_name="Paciente Notificacao",
            birth_date=date(1990, 1, 1),
            cpf=cpf,
            cep="19900000",
            phone_number=phone_number,
            session_price=Decimal("180.00"),
            session_frequency="weekly",
        ),
    )
    await session.flush()
    return patient


class TestNotificationService:
    """Service-layer notification tests."""

    async def test_create_appointment_emits_confirmation_and_reminders(self, session, make_user):
        tenant_id = session.info["tenant_id"]
        user = await make_user(tenant_ids=[tenant_id])
        patient = await _create_patient(session)
        await _create_schedule_configuration(session, user.id)
        await NotificationService.upsert_user_profile(
            session,
            user.id,
            NotificationUserProfileUpsertRequest(contact_phone="14988887777"),
        )

        appointment = await ScheduleService.create_appointment(
            session,
            user.id,
            ScheduleAppointmentCreateRequest(
                patient_id=patient.id,
                starts_at=datetime.now(UTC) + timedelta(days=2),
                modality=AppointmentModality.IN_PERSON,
            ),
        )
        await session.commit()

        result = await session.execute(
            select(NotificationMessage)
            .where(NotificationMessage.appointment_id == appointment.id)
            .order_by(NotificationMessage.id.asc())
        )
        messages = list(result.scalars().all())

        assert len(messages) == 4
        assert sum(message.event_type == NotificationEventType.APPOINTMENT_CREATED.value for message in messages) == 2
        assert sum(message.event_type == NotificationEventType.APPOINTMENT_REMINDER.value for message in messages) == 2
        assert sum(message.status == NotificationMessageStatus.SENT.value for message in messages) == 2
        assert sum(message.status == NotificationMessageStatus.PENDING.value for message in messages) == 2

    async def test_patient_preference_overrides_contact_and_reminder_time(self, session, make_user):
        tenant_id = session.info["tenant_id"]
        user = await make_user(tenant_ids=[tenant_id])
        patient = await _create_patient(session)
        await _create_schedule_configuration(session, user.id)

        await NotificationService.upsert_patient_preference(
            session,
            patient.id,
            NotificationPatientPreferenceUpsertRequest(
                is_enabled=True,
                contact_phone="14911112222",
                reminder_minutes_before=1440,
            ),
        )

        starts_at = datetime.now(UTC) + timedelta(days=3)
        appointment = await ScheduleService.create_appointment(
            session,
            user.id,
            ScheduleAppointmentCreateRequest(
                patient_id=patient.id,
                starts_at=starts_at,
                modality=AppointmentModality.ONLINE,
            ),
        )
        await session.commit()

        reminder = await session.scalar(
            select(NotificationMessage).where(
                NotificationMessage.appointment_id == appointment.id,
                NotificationMessage.event_type == NotificationEventType.APPOINTMENT_REMINDER.value,
                NotificationMessage.recipient_type == NotificationRecipientType.PATIENT.value,
            )
        )

        assert reminder is not None
        assert reminder.destination == "14911112222"
        assert reminder.scheduled_for == starts_at - timedelta(minutes=1440)

    async def test_canceling_appointment_cancels_pending_reminders_and_sends_cancel_message(self, session, make_user):
        tenant_id = session.info["tenant_id"]
        user = await make_user(tenant_ids=[tenant_id])
        patient = await _create_patient(session)
        await _create_schedule_configuration(session, user.id)

        appointment = await ScheduleService.create_appointment(
            session,
            user.id,
            ScheduleAppointmentCreateRequest(
                patient_id=patient.id,
                starts_at=datetime.now(UTC) + timedelta(days=2),
                modality=AppointmentModality.IN_PERSON,
            ),
        )
        await ScheduleService.update_appointment_status(
            session,
            user.id,
            appointment,
            ScheduleAppointmentStatusUpdateRequest(status=AppointmentStatus.CANCELED),
        )
        await session.commit()

        reminder_result = await session.execute(
            select(NotificationMessage).where(
                NotificationMessage.appointment_id == appointment.id,
                NotificationMessage.event_type == NotificationEventType.APPOINTMENT_REMINDER.value,
            )
        )
        reminder_messages = list(reminder_result.scalars().all())
        cancel_message = await session.scalar(
            select(NotificationMessage).where(
                NotificationMessage.appointment_id == appointment.id,
                NotificationMessage.event_type == NotificationEventType.APPOINTMENT_CANCELED.value,
                NotificationMessage.recipient_type == NotificationRecipientType.PATIENT.value,
            )
        )

        assert reminder_messages
        assert all(message.status == NotificationMessageStatus.CANCELED.value for message in reminder_messages)
        assert cancel_message is not None
        assert cancel_message.status == NotificationMessageStatus.SENT.value


class TestNotificationAPI:
    """API-layer notification tests."""

    async def test_settings_and_profile_endpoints(self, auth_client, session):
        client, user = auth_client
        tenant_id = _tenant_id_from_client(client)
        user.tenant_ids = [tenant_id]
        await session.flush()
        patient = await _create_patient(session)

        get_response = await client.get("/api/notifications/settings")
        assert get_response.status_code == status.HTTP_200_OK
        assert get_response.json()["default_reminder_minutes_before"] == 30

        update_response = await client.put(
            "/api/notifications/settings",
            json={
                "patient_notifications_enabled": True,
                "user_notifications_enabled": True,
                "reminders_enabled": True,
                "notify_on_create": True,
                "notify_on_update": True,
                "notify_on_cancel": True,
                "default_reminder_minutes_before": 1440,
            },
        )
        assert update_response.status_code == status.HTTP_200_OK
        assert update_response.json()["default_reminder_minutes_before"] == 1440

        user_profile_response = await client.put(
            f"/api/notifications/users/{user.id}",
            json={
                "is_enabled": True,
                "contact_phone": "14988887777",
                "receive_appointment_notifications": True,
                "receive_reminders": True,
            },
        )
        assert user_profile_response.status_code == status.HTTP_200_OK
        assert user_profile_response.json()["contact_phone"] == "14988887777"

        patient_profile_response = await client.put(
            f"/api/notifications/patients/{patient.id}",
            json={
                "is_enabled": True,
                "contact_phone": "14911112222",
                "reminder_minutes_before": 60,
            },
        )
        assert patient_profile_response.status_code == status.HTTP_200_OK
        assert patient_profile_response.json()["resolved_reminder_minutes_before"] == 60

    async def test_schedule_api_creates_and_lists_notification_messages(self, auth_client, session):
        client, user = auth_client
        tenant_id = _tenant_id_from_client(client)
        user.tenant_ids = [tenant_id]
        await session.flush()
        patient = await _create_patient(session)
        await _create_schedule_configuration(session, user.id)

        await client.put(
            f"/api/notifications/users/{user.id}",
            json={
                "is_enabled": True,
                "contact_phone": "14988887777",
                "receive_appointment_notifications": True,
                "receive_reminders": True,
            },
        )

        create_response = await client.post(
            "/api/schedule/appointments",
            json={
                "patient_id": patient.id,
                "starts_at": (datetime.now(UTC) + timedelta(days=2)).isoformat(),
                "modality": "in_person",
            },
        )
        assert create_response.status_code == status.HTTP_200_OK

        list_response = await client.get("/api/notifications/messages")
        assert list_response.status_code == status.HTTP_200_OK
        assert list_response.json()["total"] == 4

    async def test_dispatch_endpoint_sends_due_pending_notifications(self, auth_client, session):
        client, user = auth_client
        tenant_id = _tenant_id_from_client(client)
        user.tenant_ids = [tenant_id]
        await session.flush()
        patient = await _create_patient(session)
        await _create_schedule_configuration(session, user.id)

        appointment = await ScheduleService.create_appointment(
            session,
            user.id,
            ScheduleAppointmentCreateRequest(
                patient_id=patient.id,
                starts_at=datetime.now(UTC) + timedelta(days=2),
                modality=AppointmentModality.IN_PERSON,
            ),
        )
        await session.flush()

        reminder = await session.scalar(
            select(NotificationMessage).where(
                NotificationMessage.appointment_id == appointment.id,
                NotificationMessage.event_type == NotificationEventType.APPOINTMENT_REMINDER.value,
                NotificationMessage.recipient_type == NotificationRecipientType.PATIENT.value,
            )
        )
        assert reminder is not None

        reminder.scheduled_for = datetime.now(UTC) - timedelta(minutes=1)
        reminder.status = NotificationMessageStatus.PENDING.value
        reminder.sent_at = None
        reminder.failed_at = None
        await session.commit()

        pending_response = await client.get(
            "/api/notifications/messages?event_type=appointment_reminder&message_status=pending"
        )
        assert pending_response.status_code == status.HTTP_200_OK
        assert pending_response.json()["total"] == 1

        dispatch_response = await client.post("/api/notifications/dispatch", json={"limit": 10})
        assert dispatch_response.status_code == status.HTTP_200_OK
        assert dispatch_response.json()["sent_count"] == 1

        await session.refresh(reminder)
        assert reminder.status == NotificationMessageStatus.SENT.value

    async def test_assistant_can_access_notifications_endpoints(self, auth_client, make_user):
        client, owner = auth_client
        tenant_id = _tenant_id_from_client(client)
        owner.tenant_ids = [tenant_id]

        assistant = await make_user(
            email="assistant_notifications@example.com",
            username="assistant_notifications",
            roles=[UserRole.ASSISTANT],
            tenant_ids=[tenant_id],
        )

        async def override_get_current_user():
            return assistant

        app.dependency_overrides[get_current_user] = override_get_current_user
        app.dependency_overrides[get_current_active_user] = override_get_current_user
        try:
            response = await client.get("/api/notifications/settings")
        finally:
            app.dependency_overrides.pop(get_current_user, None)
            app.dependency_overrides.pop(get_current_active_user, None)

        assert response.status_code == status.HTTP_200_OK

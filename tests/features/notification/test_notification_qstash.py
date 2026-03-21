"""Tests for the QStash-backed notification flow."""

import json
from datetime import UTC, date, datetime, time, timedelta
from decimal import Decimal

from fastapi import status
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from src.features.notification.models import NotificationMessage
from src.features.notification.qstash import sync_pending_messages_with_qstash
from src.features.notification.schemas import (
    NotificationEventType,
    NotificationMessageStatus,
    NotificationPatientPreferenceUpsertRequest,
    NotificationRecipientType,
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
from src.main import app
from src.shared.redis import commit_with_staged_redis


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
            full_name="Paciente Notificacao QStash",
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


class TestNotificationQStash:
    """Notification tests covering the QStash production mode."""

    async def test_qstash_mode_schedules_immediate_and_delayed_messages(self, session, make_user, fake_qstash):
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
        await commit_with_staged_redis(session)

        result = await session.execute(
            select(NotificationMessage)
            .where(NotificationMessage.appointment_id == appointment.id)
            .order_by(NotificationMessage.id.asc())
        )
        messages = list(result.scalars().all())

        assert len(messages) == 2
        assert len(fake_qstash.message.published) == 2
        assert all(message.qstash_message_id is not None for message in messages)

        published_by_message_id = {item["body"]["message_id"]: item for item in fake_qstash.message.published}
        created_message = next(
            message for message in messages if message.event_type == NotificationEventType.APPOINTMENT_CREATED.value
        )
        reminder_message = next(
            message for message in messages if message.event_type == NotificationEventType.APPOINTMENT_REMINDER.value
        )

        assert published_by_message_id[created_message.id]["delay"] is None
        assert int(published_by_message_id[reminder_message.id]["delay"] or 0) > 0

    async def test_qstash_delivery_callback_is_idempotent(self, auth_client, session, fake_qstash, sign_qstash_request):
        _ = fake_qstash
        client, _ = auth_client
        tenant_id = session.info["tenant_id"]

        message = NotificationMessage(
            tenant_id=tenant_id,
            appointment_id=None,
            patient_id=None,
            recipient_user_id=None,
            recipient_type=NotificationRecipientType.PATIENT.value,
            event_type=NotificationEventType.APPOINTMENT_REMINDER.value,
            channel="whatsapp",
            status=NotificationMessageStatus.PENDING.value,
            destination="14999999999",
            content="Mensagem de lembrete",
            scheduled_for=datetime.now(UTC) - timedelta(minutes=1),
            qstash_message_id="scheduled-qmsg-1",
        )
        session.add(message)
        await session.commit()

        body = json.dumps(
            {
                "message_id": message.id,
                "tenant_id": str(tenant_id),
            },
            separators=(",", ":"),
        )
        headers = sign_qstash_request(
            body=body,
            path="/api/internal/qstash/notifications/deliver",
        )

        first_response = await client.post(
            "/api/internal/qstash/notifications/deliver",
            content=body,
            headers=headers,
        )
        second_response = await client.post(
            "/api/internal/qstash/notifications/deliver",
            content=body,
            headers=headers,
        )

        assert first_response.status_code == status.HTTP_200_OK
        assert first_response.json()["sent_count"] == 1
        assert second_response.status_code == status.HTTP_200_OK
        assert second_response.json()["processed_count"] == 0

        await session.refresh(message)
        assert message.status == NotificationMessageStatus.SENT.value
        assert message.qstash_message_id is None

    async def test_qstash_cancels_and_reschedules_after_patient_preference_update(
        self,
        session,
        make_user,
        fake_qstash,
    ):
        tenant_id = session.info["tenant_id"]
        user = await make_user(tenant_ids=[tenant_id])
        patient = await _create_patient(session)
        await _create_schedule_configuration(session, user.id)

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
        await commit_with_staged_redis(session)

        initial_reminder = await session.scalar(
            select(NotificationMessage).where(
                NotificationMessage.appointment_id == appointment.id,
                NotificationMessage.event_type == NotificationEventType.APPOINTMENT_REMINDER.value,
                NotificationMessage.recipient_type == NotificationRecipientType.PATIENT.value,
                NotificationMessage.status == NotificationMessageStatus.PENDING.value,
            )
        )
        assert initial_reminder is not None
        assert initial_reminder.qstash_message_id is not None
        initial_qstash_id = initial_reminder.qstash_message_id

        await NotificationService.upsert_patient_preference(
            session,
            patient.id,
            NotificationPatientPreferenceUpsertRequest(
                is_enabled=True,
                contact_phone="14911112222",
                reminder_minutes_before=1440,
            ),
        )
        await commit_with_staged_redis(session)

        result = await session.execute(
            select(NotificationMessage)
            .where(
                NotificationMessage.appointment_id == appointment.id,
                NotificationMessage.event_type == NotificationEventType.APPOINTMENT_REMINDER.value,
                NotificationMessage.recipient_type == NotificationRecipientType.PATIENT.value,
            )
            .order_by(NotificationMessage.id.asc())
        )
        reminders = list(result.scalars().all())

        assert len(reminders) == 2
        assert reminders[0].status == NotificationMessageStatus.CANCELED.value
        assert reminders[1].status == NotificationMessageStatus.PENDING.value
        assert reminders[1].destination == "14911112222"
        assert reminders[1].scheduled_for == starts_at - timedelta(minutes=1440)
        assert reminders[1].qstash_message_id is not None
        assert initial_qstash_id in fake_qstash.message.canceled

    async def test_qstash_cancels_scheduled_reminders_when_appointment_is_canceled(
        self,
        session,
        make_user,
        fake_qstash,
    ):
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
        await commit_with_staged_redis(session)

        reminder_result = await session.execute(
            select(NotificationMessage).where(
                NotificationMessage.appointment_id == appointment.id,
                NotificationMessage.event_type == NotificationEventType.APPOINTMENT_REMINDER.value,
            )
        )
        initial_reminders = list(reminder_result.scalars().all())
        initial_qstash_ids = [message.qstash_message_id for message in initial_reminders if message.qstash_message_id]

        await ScheduleService.update_appointment_status(
            session,
            user.id,
            appointment,
            ScheduleAppointmentStatusUpdateRequest(status=AppointmentStatus.CANCELED),
        )
        await commit_with_staged_redis(session)

        canceled_reminder_result = await session.execute(
            select(NotificationMessage).where(
                NotificationMessage.appointment_id == appointment.id,
                NotificationMessage.event_type == NotificationEventType.APPOINTMENT_REMINDER.value,
            )
        )
        canceled_reminders = list(canceled_reminder_result.scalars().all())

        assert canceled_reminders
        assert all(message.status == NotificationMessageStatus.CANCELED.value for message in canceled_reminders)
        assert set(initial_qstash_ids).issubset(set(fake_qstash.message.canceled))

    async def test_daily_sync_only_schedules_messages_within_next_seven_days(
        self,
        session,
        fake_qstash,
    ):
        tenant_id = session.info["tenant_id"]
        near_message = NotificationMessage(
            tenant_id=tenant_id,
            appointment_id=None,
            patient_id=None,
            recipient_user_id=None,
            recipient_type=NotificationRecipientType.PATIENT.value,
            event_type=NotificationEventType.APPOINTMENT_REMINDER.value,
            channel="whatsapp",
            status=NotificationMessageStatus.PENDING.value,
            destination="14999999999",
            content="Lembrete próximo",
            scheduled_for=datetime.now(UTC) + timedelta(days=3),
        )
        far_message = NotificationMessage(
            tenant_id=tenant_id,
            appointment_id=None,
            patient_id=None,
            recipient_user_id=None,
            recipient_type=NotificationRecipientType.PATIENT.value,
            event_type=NotificationEventType.APPOINTMENT_REMINDER.value,
            channel="whatsapp",
            status=NotificationMessageStatus.PENDING.value,
            destination="14999999999",
            content="Lembrete distante",
            scheduled_for=datetime.now(UTC) + timedelta(days=10),
        )
        session.add_all([near_message, far_message])
        await session.commit()

        result = await sync_pending_messages_with_qstash(limit_per_tenant=1000)

        await session.refresh(near_message)
        await session.refresh(far_message)

        assert result["scheduled_count"] == 1
        assert near_message.qstash_message_id is not None
        assert far_message.qstash_message_id is None
        assert len(fake_qstash.message.published) == 1

    async def test_internal_callbacks_reject_missing_or_invalid_signature(
        self,
        auth_client,
        fake_qstash,
    ):
        _ = fake_qstash
        client, _ = auth_client
        body = json.dumps(
            {
                "message_id": 1,
                "tenant_id": "00000000-0000-0000-0000-000000000000",
            },
            separators=(",", ":"),
        )

        callback_cases = [
            (
                "/api/internal/qstash/notifications/deliver",
                body,
            ),
            (
                "/api/internal/qstash/notifications/sync",
                json.dumps({"kind": "notification_sync"}, separators=(",", ":")),
            ),
        ]

        for path, callback_body in callback_cases:
            missing_signature_response = await client.post(
                path,
                content=callback_body,
                headers={"Content-Type": "application/json"},
            )
            invalid_signature_response = await client.post(
                path,
                content=callback_body,
                headers={
                    "Content-Type": "application/json",
                    "Upstash-Signature": "invalid-signature",
                },
            )

            assert missing_signature_response.status_code == status.HTTP_401_UNAUTHORIZED
            assert invalid_signature_response.status_code == status.HTTP_401_UNAUTHORIZED

    async def test_qstash_delivery_callback_does_not_require_tenant_header(
        self,
        session,
        fake_qstash,
        sign_qstash_request,
    ):
        _ = fake_qstash
        tenant_id = session.info["tenant_id"]

        message = NotificationMessage(
            tenant_id=tenant_id,
            appointment_id=None,
            patient_id=None,
            recipient_user_id=None,
            recipient_type=NotificationRecipientType.PATIENT.value,
            event_type=NotificationEventType.APPOINTMENT_REMINDER.value,
            channel="whatsapp",
            status=NotificationMessageStatus.PENDING.value,
            destination="14999999999",
            content="Mensagem de lembrete",
            scheduled_for=datetime.now(UTC) - timedelta(minutes=1),
            qstash_message_id="scheduled-qmsg-no-tenant",
        )
        session.add(message)
        await session.commit()

        body = json.dumps(
            {
                "message_id": message.id,
                "tenant_id": str(tenant_id),
            },
            separators=(",", ":"),
        )

        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as public_client:
            response = await public_client.post(
                "/api/internal/qstash/notifications/deliver",
                content=body,
                headers=sign_qstash_request(
                    body=body,
                    path="/api/internal/qstash/notifications/deliver",
                ),
            )

        assert response.status_code == status.HTTP_200_OK
        assert response.json()["sent_count"] == 1

    async def test_qstash_sync_callback_does_not_require_tenant_header(
        self,
        session,
        fake_qstash,
        sign_qstash_request,
    ):
        _ = fake_qstash
        tenant_id = session.info["tenant_id"]
        near_message = NotificationMessage(
            tenant_id=tenant_id,
            appointment_id=None,
            patient_id=None,
            recipient_user_id=None,
            recipient_type=NotificationRecipientType.PATIENT.value,
            event_type=NotificationEventType.APPOINTMENT_REMINDER.value,
            channel="whatsapp",
            status=NotificationMessageStatus.PENDING.value,
            destination="14999999999",
            content="Lembrete de callback",
            scheduled_for=datetime.now(UTC) + timedelta(days=3),
        )
        session.add(near_message)
        await session.commit()

        body = json.dumps({"kind": "notification_sync"}, separators=(",", ":"))
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as public_client:
            response = await public_client.post(
                "/api/internal/qstash/notifications/sync",
                content=body,
                headers=sign_qstash_request(
                    body=body,
                    path="/api/internal/qstash/notifications/sync",
                ),
            )

        assert response.status_code == status.HTTP_200_OK
        assert response.json()["tenant_count"] == 1
        assert response.json()["scheduled_count"] == 1
        assert response.json()["failed_count"] == 0

        await session.refresh(near_message)
        assert near_message.qstash_message_id is not None

    async def test_qstash_sync_callback_returns_404_outside_qstash_mode(self):
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as public_client:
            response = await public_client.post(
                "/api/internal/qstash/notifications/sync",
                content=json.dumps({"kind": "notification_sync"}, separators=(",", ":")),
                headers={"Content-Type": "application/json"},
            )

        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert response.json()["detail"] == "QStash callbacks are disabled"

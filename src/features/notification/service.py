"""Notification service layer."""

import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from src.features.patient.models import Patient
from src.features.schedule.models import ScheduleAppointment
from src.features.schedule.schemas import AppointmentStatus
from src.features.user.models import User, UserStatus
from src.shared.pagination.pagination import PaginationParams

from .delivery import NotificationDeliveryError, get_notification_delivery_backend
from .exceptions import (
    NotificationPatientNotFound,
    NotificationUserNotAssignedToTenant,
    NotificationUserNotFound,
)
from .models import (
    NotificationMessage,
    NotificationPatientPreference,
    NotificationSettings,
    NotificationUserProfile,
)
from .schemas import (
    NotificationChannel,
    NotificationEventType,
    NotificationMessageStatus,
    NotificationPatientPreferenceUpsertRequest,
    NotificationRecipientType,
    NotificationSettingsUpdateRequest,
    NotificationUserProfileUpsertRequest,
)

logger = logging.getLogger(__name__)

DEFAULT_REMINDER_MINUTES_BEFORE = 30
ACTIVE_NOTIFICATION_APPOINTMENT_STATUSES = {
    AppointmentStatus.SCHEDULED.value,
    AppointmentStatus.RESCHEDULED.value,
}


@dataclass(slots=True)
class ResolvedNotificationSettings:
    """Resolved tenant notification settings with defaults applied."""

    patient_notifications_enabled: bool = True
    user_notifications_enabled: bool = True
    reminders_enabled: bool = True
    notify_on_create: bool = True
    notify_on_update: bool = True
    notify_on_cancel: bool = True
    default_reminder_minutes_before: int = DEFAULT_REMINDER_MINUTES_BEFORE


@dataclass(slots=True)
class ResolvedPatientTarget:
    """Resolved patient delivery target and reminder timing."""

    destination: str
    reminder_minutes_before: int


class NotificationService:
    """Service for notification settings, outbox management, and dispatch."""

    @staticmethod
    def _require_tenant_id(session: AsyncSession):
        tenant_id = session.info.get("tenant_id")
        if tenant_id is None:
            raise RuntimeError("Tenant context is required for notification operations")
        return tenant_id

    @staticmethod
    async def _get_settings_model(session: AsyncSession) -> NotificationSettings | None:
        tenant_id = NotificationService._require_tenant_id(session)
        stmt = select(NotificationSettings).where(NotificationSettings.tenant_id == tenant_id)
        result = await session.execute(stmt)
        return result.scalar_one_or_none()

    @staticmethod
    def _resolve_settings_model(settings_model: NotificationSettings | None) -> ResolvedNotificationSettings:
        if settings_model is None:
            return ResolvedNotificationSettings()

        return ResolvedNotificationSettings(
            patient_notifications_enabled=settings_model.patient_notifications_enabled,
            user_notifications_enabled=settings_model.user_notifications_enabled,
            reminders_enabled=settings_model.reminders_enabled,
            notify_on_create=settings_model.notify_on_create,
            notify_on_update=settings_model.notify_on_update,
            notify_on_cancel=settings_model.notify_on_cancel,
            default_reminder_minutes_before=settings_model.default_reminder_minutes_before,
        )

    @staticmethod
    async def _resolve_settings(session: AsyncSession) -> ResolvedNotificationSettings:
        settings_model = await NotificationService._get_settings_model(session)
        return NotificationService._resolve_settings_model(settings_model)

    @staticmethod
    async def get_settings(session: AsyncSession) -> dict[str, object]:
        """Return tenant notification settings with defaults applied."""
        settings_model = await NotificationService._get_settings_model(session)
        resolved = NotificationService._resolve_settings_model(settings_model)
        return {
            "id": settings_model.id if settings_model is not None else None,
            "patient_notifications_enabled": resolved.patient_notifications_enabled,
            "user_notifications_enabled": resolved.user_notifications_enabled,
            "reminders_enabled": resolved.reminders_enabled,
            "notify_on_create": resolved.notify_on_create,
            "notify_on_update": resolved.notify_on_update,
            "notify_on_cancel": resolved.notify_on_cancel,
            "default_reminder_minutes_before": resolved.default_reminder_minutes_before,
            "created_at": settings_model.created_at if settings_model is not None else None,
            "updated_at": settings_model.updated_at if settings_model is not None else None,
        }

    @staticmethod
    async def upsert_settings(
        session: AsyncSession,
        data: NotificationSettingsUpdateRequest,
    ) -> NotificationSettings:
        """Create or update tenant notification settings."""
        settings_model = await NotificationService._get_settings_model(session)
        if settings_model is None:
            settings_model = NotificationSettings(tenant_id=NotificationService._require_tenant_id(session))
            session.add(settings_model)

        settings_model.patient_notifications_enabled = data.patient_notifications_enabled
        settings_model.user_notifications_enabled = data.user_notifications_enabled
        settings_model.reminders_enabled = data.reminders_enabled
        settings_model.notify_on_create = data.notify_on_create
        settings_model.notify_on_update = data.notify_on_update
        settings_model.notify_on_cancel = data.notify_on_cancel
        settings_model.default_reminder_minutes_before = data.default_reminder_minutes_before

        await session.flush()
        await NotificationService.sync_future_reminders_for_tenant(session)
        await NotificationService.dispatch_due_messages(session, limit=100)
        return settings_model

    @staticmethod
    async def _get_patient(session: AsyncSession, patient_id: int) -> Patient | None:
        tenant_id = NotificationService._require_tenant_id(session)
        stmt = select(Patient).where(
            Patient.id == patient_id,
            Patient.tenant_id == tenant_id,
        )
        result = await session.execute(stmt)
        return result.scalar_one_or_none()

    @staticmethod
    async def _require_patient(session: AsyncSession, patient_id: int) -> Patient:
        patient = await NotificationService._get_patient(session, patient_id)
        if patient is None:
            raise NotificationPatientNotFound()
        return patient

    @staticmethod
    async def _get_patient_preference(
        session: AsyncSession,
        patient_id: int,
    ) -> NotificationPatientPreference | None:
        tenant_id = NotificationService._require_tenant_id(session)
        stmt = select(NotificationPatientPreference).where(
            NotificationPatientPreference.tenant_id == tenant_id,
            NotificationPatientPreference.patient_id == patient_id,
        )
        result = await session.execute(stmt)
        return result.scalar_one_or_none()

    @staticmethod
    async def _resolve_patient_target(
        session: AsyncSession,
        patient: Patient,
        settings: ResolvedNotificationSettings,
    ) -> ResolvedPatientTarget | None:
        preference = await NotificationService._get_patient_preference(session, patient.id)
        if preference is not None and not preference.is_enabled:
            return None

        destination = patient.phone_number
        reminder_minutes_before = settings.default_reminder_minutes_before

        if preference is not None:
            if preference.contact_phone is not None:
                destination = preference.contact_phone
            if preference.reminder_minutes_before is not None:
                reminder_minutes_before = preference.reminder_minutes_before

        if destination is None:
            return None

        return ResolvedPatientTarget(
            destination=destination,
            reminder_minutes_before=reminder_minutes_before,
        )

    @staticmethod
    async def get_patient_preference_details(
        session: AsyncSession,
        patient_id: int,
    ) -> dict[str, object]:
        """Return effective per-patient notification settings."""
        patient = await NotificationService._require_patient(session, patient_id)
        settings = await NotificationService._resolve_settings(session)
        preference = await NotificationService._get_patient_preference(session, patient_id)
        target = await NotificationService._resolve_patient_target(session, patient, settings)

        return {
            "patient_id": patient.id,
            "is_enabled": preference.is_enabled if preference is not None else True,
            "contact_phone": (
                preference.contact_phone
                if preference is not None and preference.contact_phone is not None
                else patient.phone_number
            ),
            "reminder_minutes_before": preference.reminder_minutes_before if preference is not None else None,
            "resolved_reminder_minutes_before": (
                target.reminder_minutes_before if target is not None else settings.default_reminder_minutes_before
            ),
            "has_preference": preference is not None,
            "created_at": preference.created_at if preference is not None else None,
            "updated_at": preference.updated_at if preference is not None else None,
        }

    @staticmethod
    async def upsert_patient_preference(
        session: AsyncSession,
        patient_id: int,
        data: NotificationPatientPreferenceUpsertRequest,
    ) -> NotificationPatientPreference:
        """Create or update per-patient notification preferences."""
        patient = await NotificationService._require_patient(session, patient_id)
        preference = await NotificationService._get_patient_preference(session, patient.id)
        if preference is None:
            preference = NotificationPatientPreference(
                tenant_id=NotificationService._require_tenant_id(session),
                patient_id=patient.id,
            )
            session.add(preference)

        preference.is_enabled = data.is_enabled
        preference.contact_phone = data.contact_phone
        preference.reminder_minutes_before = data.reminder_minutes_before

        await session.flush()
        await NotificationService.sync_future_reminders_for_patient(session, patient.id)
        await NotificationService.dispatch_due_messages(session, limit=100)
        return preference

    @staticmethod
    async def _get_user(session: AsyncSession, user_id: int) -> User | None:
        stmt = select(User).where(User.id == user_id)
        result = await session.execute(stmt)
        return result.scalar_one_or_none()

    @staticmethod
    async def _require_tenant_user(session: AsyncSession, user_id: int) -> User:
        tenant_id = NotificationService._require_tenant_id(session)
        user = await NotificationService._get_user(session, user_id)
        if user is None:
            raise NotificationUserNotFound()
        if tenant_id not in (user.tenant_ids or []):
            raise NotificationUserNotAssignedToTenant()
        return user

    @staticmethod
    async def _get_user_profile(session: AsyncSession, user_id: int) -> NotificationUserProfile | None:
        tenant_id = NotificationService._require_tenant_id(session)
        stmt = select(NotificationUserProfile).where(
            NotificationUserProfile.tenant_id == tenant_id,
            NotificationUserProfile.user_id == user_id,
        )
        result = await session.execute(stmt)
        return result.scalar_one_or_none()

    @staticmethod
    async def get_user_profile_details(
        session: AsyncSession,
        user_id: int,
    ) -> dict[str, object]:
        """Return effective per-user notification profile details."""
        user = await NotificationService._require_tenant_user(session, user_id)
        profile = await NotificationService._get_user_profile(session, user.id)
        return {
            "user_id": user.id,
            "is_enabled": profile.is_enabled if profile is not None else True,
            "contact_phone": profile.contact_phone if profile is not None else None,
            "receive_appointment_notifications": (
                profile.receive_appointment_notifications if profile is not None else True
            ),
            "receive_reminders": profile.receive_reminders if profile is not None else True,
            "has_profile": profile is not None,
            "created_at": profile.created_at if profile is not None else None,
            "updated_at": profile.updated_at if profile is not None else None,
        }

    @staticmethod
    async def upsert_user_profile(
        session: AsyncSession,
        user_id: int,
        data: NotificationUserProfileUpsertRequest,
    ) -> NotificationUserProfile:
        """Create or update per-user notification delivery settings."""
        user = await NotificationService._require_tenant_user(session, user_id)
        profile = await NotificationService._get_user_profile(session, user.id)
        if profile is None:
            profile = NotificationUserProfile(
                tenant_id=NotificationService._require_tenant_id(session),
                user_id=user.id,
            )
            session.add(profile)

        profile.is_enabled = data.is_enabled
        profile.contact_phone = data.contact_phone
        profile.receive_appointment_notifications = data.receive_appointment_notifications
        profile.receive_reminders = data.receive_reminders

        await session.flush()
        await NotificationService.sync_future_reminders_for_tenant(session)
        await NotificationService.dispatch_due_messages(session, limit=100)
        return profile

    @staticmethod
    def _apply_message_filters(
        stmt,
        *,
        tenant_id,
        message_status: NotificationMessageStatus | None,
        event_type: NotificationEventType | None,
        recipient_type: NotificationRecipientType | None,
        appointment_id: int | None,
        patient_id: int | None,
        recipient_user_id: int | None,
    ):
        stmt = stmt.where(NotificationMessage.tenant_id == tenant_id)

        if message_status is not None:
            stmt = stmt.where(NotificationMessage.status == message_status.value)
        if event_type is not None:
            stmt = stmt.where(NotificationMessage.event_type == event_type.value)
        if recipient_type is not None:
            stmt = stmt.where(NotificationMessage.recipient_type == recipient_type.value)
        if appointment_id is not None:
            stmt = stmt.where(NotificationMessage.appointment_id == appointment_id)
        if patient_id is not None:
            stmt = stmt.where(NotificationMessage.patient_id == patient_id)
        if recipient_user_id is not None:
            stmt = stmt.where(NotificationMessage.recipient_user_id == recipient_user_id)

        return stmt

    @staticmethod
    async def list_messages(
        session: AsyncSession,
        pagination: PaginationParams,
        *,
        message_status: NotificationMessageStatus | None,
        event_type: NotificationEventType | None,
        recipient_type: NotificationRecipientType | None,
        appointment_id: int | None,
        patient_id: int | None,
        recipient_user_id: int | None,
    ) -> tuple[list[NotificationMessage], int]:
        """List notification messages in tenant scope."""
        tenant_id = NotificationService._require_tenant_id(session)

        count_stmt = select(func.count()).select_from(NotificationMessage)
        count_stmt = NotificationService._apply_message_filters(
            count_stmt,
            tenant_id=tenant_id,
            message_status=message_status,
            event_type=event_type,
            recipient_type=recipient_type,
            appointment_id=appointment_id,
            patient_id=patient_id,
            recipient_user_id=recipient_user_id,
        )

        stmt = select(NotificationMessage).order_by(
            NotificationMessage.scheduled_for.desc(),
            NotificationMessage.id.desc(),
        )
        stmt = NotificationService._apply_message_filters(
            stmt,
            tenant_id=tenant_id,
            message_status=message_status,
            event_type=event_type,
            recipient_type=recipient_type,
            appointment_id=appointment_id,
            patient_id=patient_id,
            recipient_user_id=recipient_user_id,
        )

        total_result = await session.execute(count_stmt)
        total = total_result.scalar_one()

        if pagination.is_paginated:
            stmt = stmt.offset(pagination.skip).limit(pagination.limit)

        result = await session.execute(stmt)
        return list(result.scalars().all()), total

    @staticmethod
    def _format_datetime(value: datetime) -> str:
        """Format datetimes consistently for message bodies."""
        return value.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC")

    @staticmethod
    def _build_message_content(
        *,
        event_type: NotificationEventType,
        recipient_type: NotificationRecipientType,
        appointment: ScheduleAppointment,
        patient_name: str,
    ) -> str:
        scheduled_for = NotificationService._format_datetime(appointment.starts_at)
        if event_type == NotificationEventType.APPOINTMENT_CREATED:
            if recipient_type == NotificationRecipientType.PATIENT:
                return f"Hello {patient_name}, your appointment is confirmed for {scheduled_for}."
            return f"Appointment confirmed for patient {patient_name} at {scheduled_for}."

        if event_type == NotificationEventType.APPOINTMENT_UPDATED:
            if recipient_type == NotificationRecipientType.PATIENT:
                return f"Hello {patient_name}, your appointment was updated to {scheduled_for}."
            return f"Appointment updated for patient {patient_name}. New time: {scheduled_for}."

        if event_type == NotificationEventType.APPOINTMENT_CANCELED:
            if recipient_type == NotificationRecipientType.PATIENT:
                return f"Hello {patient_name}, your appointment scheduled for {scheduled_for} was canceled."
            return f"Appointment canceled for patient {patient_name}. Original time: {scheduled_for}."

        if recipient_type == NotificationRecipientType.PATIENT:
            return f"Hello {patient_name}, this is a reminder for your appointment at {scheduled_for}."
        return f"Reminder: patient {patient_name} has an appointment at {scheduled_for}."

    @staticmethod
    async def _list_user_profiles(
        session: AsyncSession,
        *,
        require_appointment_notifications: bool = False,
        require_reminders: bool = False,
    ) -> list[NotificationUserProfile]:
        tenant_id = NotificationService._require_tenant_id(session)
        stmt = (
            select(NotificationUserProfile, User)
            .join(User, User.id == NotificationUserProfile.user_id)
            .where(
                NotificationUserProfile.tenant_id == tenant_id,
                NotificationUserProfile.is_enabled.is_(True),
                User.status == UserStatus.ACTIVE.value,
            )
        )

        if require_appointment_notifications:
            stmt = stmt.where(NotificationUserProfile.receive_appointment_notifications.is_(True))
        if require_reminders:
            stmt = stmt.where(NotificationUserProfile.receive_reminders.is_(True))

        result = await session.execute(stmt)
        profiles: list[NotificationUserProfile] = []

        for profile, user in result.all():
            if profile.contact_phone is None:
                continue
            if tenant_id not in (user.tenant_ids or []):
                continue
            profiles.append(profile)

        return profiles

    @staticmethod
    def _enqueue_message(
        session: AsyncSession,
        *,
        appointment: ScheduleAppointment,
        event_type: NotificationEventType,
        recipient_type: NotificationRecipientType,
        destination: str,
        content: str,
        scheduled_for: datetime,
        patient_id: int | None,
        recipient_user_id: int | None,
    ) -> None:
        message = NotificationMessage(
            tenant_id=NotificationService._require_tenant_id(session),
            appointment_id=appointment.id,
            patient_id=patient_id,
            recipient_user_id=recipient_user_id,
            recipient_type=recipient_type.value,
            event_type=event_type.value,
            channel=NotificationChannel.WHATSAPP.value,
            status=NotificationMessageStatus.PENDING.value,
            destination=destination,
            content=content,
            scheduled_for=scheduled_for,
        )
        session.add(message)

    @staticmethod
    async def _queue_event_notifications(
        session: AsyncSession,
        appointment: ScheduleAppointment,
        patient: Patient,
        settings: ResolvedNotificationSettings,
        event_type: NotificationEventType,
    ) -> None:
        enabled = {
            NotificationEventType.APPOINTMENT_CREATED: settings.notify_on_create,
            NotificationEventType.APPOINTMENT_UPDATED: settings.notify_on_update,
            NotificationEventType.APPOINTMENT_CANCELED: settings.notify_on_cancel,
        }.get(event_type, False)

        if not enabled:
            return

        send_at = datetime.now(UTC)

        if settings.patient_notifications_enabled:
            patient_target = await NotificationService._resolve_patient_target(session, patient, settings)
            if patient_target is not None:
                NotificationService._enqueue_message(
                    session,
                    appointment=appointment,
                    event_type=event_type,
                    recipient_type=NotificationRecipientType.PATIENT,
                    destination=patient_target.destination,
                    content=NotificationService._build_message_content(
                        event_type=event_type,
                        recipient_type=NotificationRecipientType.PATIENT,
                        appointment=appointment,
                        patient_name=patient.full_name,
                    ),
                    scheduled_for=send_at,
                    patient_id=patient.id,
                    recipient_user_id=None,
                )

        if settings.user_notifications_enabled:
            user_profiles = await NotificationService._list_user_profiles(
                session,
                require_appointment_notifications=True,
            )
            for profile in user_profiles:
                NotificationService._enqueue_message(
                    session,
                    appointment=appointment,
                    event_type=event_type,
                    recipient_type=NotificationRecipientType.USER,
                    destination=profile.contact_phone or "",
                    content=NotificationService._build_message_content(
                        event_type=event_type,
                        recipient_type=NotificationRecipientType.USER,
                        appointment=appointment,
                        patient_name=patient.full_name,
                    ),
                    scheduled_for=send_at,
                    patient_id=patient.id,
                    recipient_user_id=profile.user_id,
                )

    @staticmethod
    async def _cancel_pending_messages(
        session: AsyncSession,
        *,
        appointment_id: int,
        event_type: NotificationEventType | None = None,
    ) -> None:
        now = datetime.now(UTC)
        stmt = update(NotificationMessage).where(
            NotificationMessage.tenant_id == NotificationService._require_tenant_id(session),
            NotificationMessage.appointment_id == appointment_id,
            NotificationMessage.status == NotificationMessageStatus.PENDING.value,
        )
        if event_type is not None:
            stmt = stmt.where(NotificationMessage.event_type == event_type.value)

        stmt = stmt.values(
            status=NotificationMessageStatus.CANCELED.value,
            canceled_at=now,
            updated_at=now,
        )
        await session.execute(stmt)

    @staticmethod
    async def _sync_appointment_reminders(
        session: AsyncSession,
        appointment: ScheduleAppointment,
        *,
        patient: Patient,
        settings: ResolvedNotificationSettings,
    ) -> None:
        await NotificationService._cancel_pending_messages(
            session,
            appointment_id=appointment.id,
            event_type=NotificationEventType.APPOINTMENT_REMINDER,
        )

        if appointment.is_deleted:
            return
        if appointment.status not in ACTIVE_NOTIFICATION_APPOINTMENT_STATUSES:
            return
        if appointment.starts_at <= datetime.now(UTC):
            return
        if not settings.reminders_enabled:
            return

        if settings.patient_notifications_enabled:
            patient_target = await NotificationService._resolve_patient_target(session, patient, settings)
            if patient_target is not None:
                NotificationService._enqueue_message(
                    session,
                    appointment=appointment,
                    event_type=NotificationEventType.APPOINTMENT_REMINDER,
                    recipient_type=NotificationRecipientType.PATIENT,
                    destination=patient_target.destination,
                    content=NotificationService._build_message_content(
                        event_type=NotificationEventType.APPOINTMENT_REMINDER,
                        recipient_type=NotificationRecipientType.PATIENT,
                        appointment=appointment,
                        patient_name=patient.full_name,
                    ),
                    scheduled_for=appointment.starts_at - timedelta(minutes=patient_target.reminder_minutes_before),
                    patient_id=patient.id,
                    recipient_user_id=None,
                )

        if settings.user_notifications_enabled:
            user_profiles = await NotificationService._list_user_profiles(session, require_reminders=True)
            for profile in user_profiles:
                NotificationService._enqueue_message(
                    session,
                    appointment=appointment,
                    event_type=NotificationEventType.APPOINTMENT_REMINDER,
                    recipient_type=NotificationRecipientType.USER,
                    destination=profile.contact_phone or "",
                    content=NotificationService._build_message_content(
                        event_type=NotificationEventType.APPOINTMENT_REMINDER,
                        recipient_type=NotificationRecipientType.USER,
                        appointment=appointment,
                        patient_name=patient.full_name,
                    ),
                    scheduled_for=appointment.starts_at - timedelta(minutes=settings.default_reminder_minutes_before),
                    patient_id=patient.id,
                    recipient_user_id=profile.user_id,
                )

    @staticmethod
    async def handle_appointment_created(
        session: AsyncSession,
        appointment: ScheduleAppointment,
    ) -> None:
        """Queue confirmation and reminder notifications for a new appointment."""
        patient = await NotificationService._require_patient(session, appointment.patient_id)
        settings = await NotificationService._resolve_settings(session)
        await NotificationService._queue_event_notifications(
            session,
            appointment,
            patient,
            settings,
            NotificationEventType.APPOINTMENT_CREATED,
        )
        await NotificationService._sync_appointment_reminders(session, appointment, patient=patient, settings=settings)
        await session.flush()
        await NotificationService.dispatch_due_messages(session, limit=25, appointment_id=appointment.id)

    @staticmethod
    async def handle_appointment_updated(
        session: AsyncSession,
        appointment: ScheduleAppointment,
    ) -> None:
        """Queue update and refreshed reminder notifications for an appointment."""
        patient = await NotificationService._require_patient(session, appointment.patient_id)
        settings = await NotificationService._resolve_settings(session)
        await NotificationService._queue_event_notifications(
            session,
            appointment,
            patient,
            settings,
            NotificationEventType.APPOINTMENT_UPDATED,
        )
        await NotificationService._sync_appointment_reminders(session, appointment, patient=patient, settings=settings)
        await session.flush()
        await NotificationService.dispatch_due_messages(session, limit=25, appointment_id=appointment.id)

    @staticmethod
    async def handle_appointment_canceled(
        session: AsyncSession,
        appointment: ScheduleAppointment,
    ) -> None:
        """Cancel pending reminders and queue cancellation notifications."""
        patient = await NotificationService._require_patient(session, appointment.patient_id)
        settings = await NotificationService._resolve_settings(session)
        await NotificationService._cancel_pending_messages(
            session,
            appointment_id=appointment.id,
            event_type=NotificationEventType.APPOINTMENT_REMINDER,
        )
        await NotificationService._queue_event_notifications(
            session,
            appointment,
            patient,
            settings,
            NotificationEventType.APPOINTMENT_CANCELED,
        )
        await session.flush()
        await NotificationService.dispatch_due_messages(session, limit=25, appointment_id=appointment.id)

    @staticmethod
    async def clear_appointment_notifications(session: AsyncSession, appointment_id: int) -> None:
        """Cancel any pending notification records tied to an appointment."""
        await NotificationService._cancel_pending_messages(session, appointment_id=appointment_id)
        await session.flush()

    @staticmethod
    async def dispatch_due_messages(
        session: AsyncSession,
        *,
        limit: int,
        appointment_id: int | None = None,
    ) -> dict[str, int]:
        """Dispatch due pending notifications within the current tenant."""
        tenant_id = NotificationService._require_tenant_id(session)
        now = datetime.now(UTC)

        stmt = (
            select(NotificationMessage)
            .where(
                NotificationMessage.tenant_id == tenant_id,
                NotificationMessage.status == NotificationMessageStatus.PENDING.value,
                NotificationMessage.scheduled_for <= now,
            )
            .order_by(NotificationMessage.scheduled_for.asc(), NotificationMessage.id.asc())
            .limit(limit)
            .with_for_update(skip_locked=True)
        )
        if appointment_id is not None:
            stmt = stmt.where(NotificationMessage.appointment_id == appointment_id)

        result = await session.execute(stmt)
        messages = list(result.scalars().all())

        sent_count = 0
        failed_count = 0
        delivery_backend = get_notification_delivery_backend()

        for message in messages:
            attempt_time = datetime.now(UTC)
            message.attempt_count += 1

            try:
                delivery_result = await delivery_backend.send_whatsapp(
                    destination=message.destination,
                    content=message.content,
                )
            except NotificationDeliveryError as exc:
                message.status = NotificationMessageStatus.FAILED.value
                message.failed_at = attempt_time
                message.failure_reason = str(exc)[:500]
                failed_count += 1
                continue

            message.status = NotificationMessageStatus.SENT.value
            message.sent_at = attempt_time
            message.failed_at = None
            message.failure_reason = None
            message.provider_message_id = delivery_result.provider_message_id
            sent_count += 1

        if messages:
            await session.flush()

        return {
            "processed_count": len(messages),
            "sent_count": sent_count,
            "failed_count": failed_count,
        }

    @staticmethod
    async def _list_future_appointments(
        session: AsyncSession,
        *,
        patient_id: int | None = None,
    ) -> list[ScheduleAppointment]:
        tenant_id = NotificationService._require_tenant_id(session)
        stmt = (
            select(ScheduleAppointment)
            .where(
                ScheduleAppointment.tenant_id == tenant_id,
                ScheduleAppointment.is_deleted.is_(False),
                ScheduleAppointment.status.in_(ACTIVE_NOTIFICATION_APPOINTMENT_STATUSES),
                ScheduleAppointment.starts_at > datetime.now(UTC),
            )
            .order_by(ScheduleAppointment.starts_at.asc(), ScheduleAppointment.id.asc())
        )

        if patient_id is not None:
            stmt = stmt.where(ScheduleAppointment.patient_id == patient_id)

        result = await session.execute(stmt)
        return list(result.scalars().all())

    @staticmethod
    async def sync_future_reminders_for_tenant(session: AsyncSession) -> None:
        """Rebuild reminder messages for all future appointments in the tenant."""
        settings = await NotificationService._resolve_settings(session)
        appointments = await NotificationService._list_future_appointments(session)

        for appointment in appointments:
            patient = await NotificationService._require_patient(session, appointment.patient_id)
            await NotificationService._sync_appointment_reminders(
                session,
                appointment,
                patient=patient,
                settings=settings,
            )

        await session.flush()

    @staticmethod
    async def sync_future_reminders_for_patient(session: AsyncSession, patient_id: int) -> None:
        """Rebuild reminder messages for one patient's future appointments."""
        patient = await NotificationService._require_patient(session, patient_id)
        settings = await NotificationService._resolve_settings(session)
        appointments = await NotificationService._list_future_appointments(session, patient_id=patient.id)

        for appointment in appointments:
            await NotificationService._sync_appointment_reminders(
                session,
                appointment,
                patient=patient,
                settings=settings,
            )

        await session.flush()

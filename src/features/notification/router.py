"""Notification router (API endpoints)."""

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession

from src.config.settings import settings
from src.database.dependencies import get_db_session, get_tenant_db_session
from src.features.auth.dependencies import require_tenant_membership
from src.features.user.models import User
from src.shared.pagination.pagination import PaginationParams
from src.shared.qstash import verify_qstash_request
from src.shared.redis import commit_with_staged_redis

from .qstash import sync_pending_messages_with_qstash
from .runtime import deliver_message_now
from .schemas import (
    NotificationDeliverCallbackRequest,
    NotificationDispatchRequest,
    NotificationDispatchResponse,
    NotificationEventType,
    NotificationMessageListResponse,
    NotificationMessageResponse,
    NotificationMessageStatus,
    NotificationPatientPreferenceResponse,
    NotificationPatientPreferenceUpsertRequest,
    NotificationRecipientType,
    NotificationSettingsResponse,
    NotificationSettingsUpdateRequest,
    NotificationSyncCallbackRequest,
    NotificationUserProfileResponse,
    NotificationUserProfileUpsertRequest,
)
from .service import NotificationService

router = APIRouter(
    prefix="/notifications",
    tags=["Notifications"],
)

internal_router = APIRouter(
    prefix="/internal/qstash/notifications",
    tags=["Internal Notifications"],
)


@router.get(
    "/settings",
    response_model=NotificationSettingsResponse,
    summary="Get notification settings",
)
async def get_notification_settings(
    _: User = Depends(require_tenant_membership),
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Return the tenant's effective notification settings."""
    settings = await NotificationService.get_settings(session)
    return NotificationSettingsResponse.model_validate(settings)


@router.put(
    "/settings",
    response_model=NotificationSettingsResponse,
    summary="Update notification settings",
)
async def update_notification_settings(
    data: NotificationSettingsUpdateRequest,
    _: User = Depends(require_tenant_membership),
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Create or update the tenant's notification settings."""
    settings = await NotificationService.upsert_settings(session, data)
    await commit_with_staged_redis(session)
    await session.refresh(settings)
    return NotificationSettingsResponse.model_validate(settings)


@router.get(
    "/patients/{patient_id}",
    response_model=NotificationPatientPreferenceResponse,
    summary="Get patient notification preference",
)
async def get_patient_notification_preference(
    patient_id: int,
    _: User = Depends(require_tenant_membership),
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Return the effective notification settings for one patient."""
    preference = await NotificationService.get_patient_preference_details(session, patient_id)
    return NotificationPatientPreferenceResponse.model_validate(preference)


@router.put(
    "/patients/{patient_id}",
    response_model=NotificationPatientPreferenceResponse,
    summary="Update patient notification preference",
)
async def upsert_patient_notification_preference(
    patient_id: int,
    data: NotificationPatientPreferenceUpsertRequest,
    _: User = Depends(require_tenant_membership),
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Create or update one patient's notification settings."""
    await NotificationService.upsert_patient_preference(session, patient_id, data)
    await commit_with_staged_redis(session)
    preference = await NotificationService.get_patient_preference_details(session, patient_id)
    return NotificationPatientPreferenceResponse.model_validate(preference)


@router.get(
    "/users/{user_id}",
    response_model=NotificationUserProfileResponse,
    summary="Get user notification profile",
)
async def get_user_notification_profile(
    user_id: int,
    _: User = Depends(require_tenant_membership),
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Return the notification profile for one tenant user."""
    profile = await NotificationService.get_user_profile_details(session, user_id)
    return NotificationUserProfileResponse.model_validate(profile)


@router.put(
    "/users/{user_id}",
    response_model=NotificationUserProfileResponse,
    summary="Update user notification profile",
)
async def upsert_user_notification_profile(
    user_id: int,
    data: NotificationUserProfileUpsertRequest,
    _: User = Depends(require_tenant_membership),
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Create or update a tenant user's notification profile."""
    await NotificationService.upsert_user_profile(session, user_id, data)
    await commit_with_staged_redis(session)
    profile = await NotificationService.get_user_profile_details(session, user_id)
    return NotificationUserProfileResponse.model_validate(profile)


@router.get(
    "/messages",
    response_model=NotificationMessageListResponse,
    summary="List notification messages",
)
async def list_notification_messages(
    pagination: PaginationParams = Depends(),
    message_status: NotificationMessageStatus | None = Query(default=None),
    event_type: NotificationEventType | None = Query(default=None),
    recipient_type: NotificationRecipientType | None = Query(default=None),
    appointment_id: int | None = Query(default=None, gt=0),
    patient_id: int | None = Query(default=None, gt=0),
    recipient_user_id: int | None = Query(default=None, gt=0),
    _: User = Depends(require_tenant_membership),
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """List notification messages and delivery attempts."""
    messages, total = await NotificationService.list_messages(
        session=session,
        pagination=pagination,
        message_status=message_status,
        event_type=event_type,
        recipient_type=recipient_type,
        appointment_id=appointment_id,
        patient_id=patient_id,
        recipient_user_id=recipient_user_id,
    )
    return NotificationMessageListResponse(
        messages=[NotificationMessageResponse.model_validate(message) for message in messages],
        total=total,
        page=pagination.page or 1,
        page_size=pagination.page_size or 50,
    )


@router.post(
    "/dispatch",
    response_model=NotificationDispatchResponse,
    summary="Dispatch pending notifications",
)
async def dispatch_due_notifications(
    data: NotificationDispatchRequest,
    _: User = Depends(require_tenant_membership),
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Dispatch overdue pending notifications for the current tenant."""
    result = await NotificationService.dispatch_due_messages(session, limit=data.limit)
    await session.commit()
    return NotificationDispatchResponse.model_validate(result)


@internal_router.post("/deliver")
async def deliver_notification_callback(
    request: Request,
    session: AsyncSession = Depends(get_db_session),
):
    """Deliver one pending notification through a signed QStash callback."""
    raw_body = await verify_qstash_request(
        request,
        path=f"{settings.api_prefix}/internal/qstash/notifications/deliver",
    )
    payload = NotificationDeliverCallbackRequest.model_validate_json(raw_body)
    return await deliver_message_now(payload.tenant_id, payload.message_id, session=session)


@internal_router.post("/sync")
async def sync_notification_schedule_callback(request: Request):
    """Backfill QStash reminder schedules through a signed daily callback."""
    raw_body = await verify_qstash_request(
        request,
        path=f"{settings.api_prefix}/internal/qstash/notifications/sync",
    )
    NotificationSyncCallbackRequest.model_validate_json(raw_body)
    return await sync_pending_messages_with_qstash()

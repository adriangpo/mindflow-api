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

from .openapi import (
    NotificationSyncResponse,
    internal_delivery_request_schema,
    internal_sync_request_schema,
    qstash_signature_responses,
    tenant_access_responses,
)
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
    summary="Read tenant notification settings",
    description=(
        "Returns the effective notification settings for the current tenant. "
        "If no settings row exists yet, the service still resolves and returns "
        "the feature defaults instead of failing."
    ),
    response_description="Effective notification settings for the current tenant.",
    responses=tenant_access_responses(),
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
    summary="Upsert tenant notification settings",
    description=(
        "Creates the tenant notification settings row when missing or replaces the "
        "stored toggles and reminder window when it already exists. "
        "After the database mutation succeeds, future reminder jobs for the tenant "
        "are rebuilt and staged Redis/QStash operations are flushed after commit."
    ),
    response_description="Persisted notification settings after the upsert.",
    responses=tenant_access_responses(),
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
    summary="Read a patient's notification preference",
    description=(
        "Returns the effective notification delivery target for one patient in the "
        "current tenant. The service resolves the final destination by checking the "
        "patient preference first and falling back to the patient's base phone number. "
        "If the patient has no custom reminder window, the tenant default remains in effect."
    ),
    response_description="Effective patient notification preference and resolved reminder timing.",
    responses=tenant_access_responses(not_found_detail="Paciente não encontrado para notificações"),
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
    summary="Upsert a patient's notification preference",
    description=(
        "Creates or updates the patient-specific notification override for the current tenant. "
        "The stored contact phone, when provided, replaces the patient phone number for delivery. "
        "After the row is flushed, future reminders for that patient's appointments are rebuilt "
        "before the transaction is committed."
    ),
    response_description="Effective patient notification preference after the upsert.",
    responses=tenant_access_responses(not_found_detail="Paciente não encontrado para notificações"),
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
    summary="Read a tenant user's notification profile",
    description=(
        "Returns the effective notification profile for one user assigned to the current tenant. "
        "If no profile row exists yet, the response still resolves feature defaults. "
        "The target user must exist and be assigned to the active tenant."
    ),
    response_description="Effective tenant user notification profile.",
    responses={
        **tenant_access_responses(not_found_detail="Usuário não encontrado para notificações"),
        409: {
            "description": "Target user exists but is not assigned to the current tenant.",
            "content": {"application/json": {"example": {"detail": "Usuário não está vinculado ao tenant atual"}}},
        },
    },
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
    summary="Upsert a tenant user's notification profile",
    description=(
        "Creates or updates the notification profile for one user assigned to the current tenant. "
        "When delivery is enabled for appointment notifications or reminders, a contact phone is required "
        "by schema validation. After the profile is flushed, future reminders for the tenant are rebuilt."
    ),
    response_description="Effective tenant user notification profile after the upsert.",
    responses={
        **tenant_access_responses(not_found_detail="Usuário não encontrado para notificações"),
        409: {
            "description": "Target user exists but is not assigned to the current tenant.",
            "content": {"application/json": {"example": {"detail": "Usuário não está vinculado ao tenant atual"}}},
        },
    },
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
    description=(
        "Returns the tenant-scoped notification outbox/history ordered by scheduled date descending. "
        "Filters can be combined to inspect delivery state, event type, recipient type, or the source "
        "appointment, patient, or recipient user. Pagination can be disabled by sending "
        "both page and page_size as null."
    ),
    response_description="Paginated notification messages for the current tenant.",
    responses=tenant_access_responses(),
)
async def list_notification_messages(
    pagination: PaginationParams = Depends(),
    message_status: NotificationMessageStatus | None = Query(
        default=None,
        description="Filter by delivery status: pending, sent, failed, or canceled.",
    ),
    event_type: NotificationEventType | None = Query(
        default=None,
        description="Filter by appointment event type that generated the message.",
    ),
    recipient_type: NotificationRecipientType | None = Query(
        default=None,
        description="Filter by recipient group: patient or user.",
    ),
    appointment_id: int | None = Query(
        default=None,
        gt=0,
        description="Filter messages generated from one appointment id.",
    ),
    patient_id: int | None = Query(
        default=None,
        gt=0,
        description="Filter messages for one patient id.",
    ),
    recipient_user_id: int | None = Query(
        default=None,
        gt=0,
        description="Filter messages delivered to one user id.",
    ),
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
    summary="Dispatch due notifications",
    description=(
        "Manually processes due pending notifications for the current tenant. "
        "The request limit is capped to keep dispatch batches bounded. "
        "Depending on runtime mode, the service either drains Redis-backed work "
        "or processes QStash-backed rows directly."
    ),
    response_description="Dispatch counters for the processed batch.",
    responses=tenant_access_responses(),
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


@internal_router.post(
    "/deliver",
    response_model=NotificationDispatchResponse,
    summary="Deliver one pending notification",
    description=(
        "Processes one pending notification through the signed QStash callback path. "
        "The raw request body is signature-verified before the payload is parsed, and "
        "delivery is idempotent when the message was already sent or moved out of the pending state."
    ),
    response_description="Delivery counters for the callback attempt.",
    responses={
        **qstash_signature_responses(),
        404: {
            "description": "QStash delivery callback is unavailable outside qstash mode.",
            "content": {"application/json": {"example": {"detail": "QStash callbacks are disabled"}}},
        },
    },
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {
                "application/json": {
                    "schema": internal_delivery_request_schema(),
                }
            },
        }
    },
)
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


@internal_router.post(
    "/sync",
    response_model=NotificationSyncResponse,
    summary="Backfill QStash reminder schedules",
    description=(
        "Runs the daily signed callback that backfills QStash schedules for pending reminder messages "
        "that have entered the 7-day delay window. The raw body is signature-verified "
        "before the JSON payload is parsed."
    ),
    response_description="Reminder backfill counters for the active callback run.",
    responses={
        **qstash_signature_responses(),
        404: {
            "description": "QStash sync callback is unavailable outside qstash mode.",
            "content": {"application/json": {"example": {"detail": "QStash callbacks are disabled"}}},
        },
    },
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {
                "application/json": {
                    "schema": internal_sync_request_schema(),
                }
            },
        }
    },
)
async def sync_notification_schedule_callback(request: Request):
    """Backfill QStash reminder schedules through a signed daily callback."""
    raw_body = await verify_qstash_request(
        request,
        path=f"{settings.api_prefix}/internal/qstash/notifications/sync",
    )
    NotificationSyncCallbackRequest.model_validate_json(raw_body)
    return await sync_pending_messages_with_qstash()

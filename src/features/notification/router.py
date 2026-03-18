"""Notification router (API endpoints)."""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from src.database.dependencies import get_tenant_db_session
from src.features.auth.dependencies import require_role, require_tenant_membership
from src.features.user.models import User, UserRole
from src.shared.pagination.pagination import PaginationParams

from .schemas import (
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
    NotificationUserProfileResponse,
    NotificationUserProfileUpsertRequest,
)
from .service import NotificationService

router = APIRouter(
    prefix="/notifications",
    tags=["Notificações"],
    dependencies=[Depends(require_role(UserRole.TENANT_OWNER, UserRole.ASSISTANT))],
)


@router.get(
    "/settings",
    response_model=NotificationSettingsResponse,
    summary="Obter configurações de notificação",
)
async def get_notification_settings(
    _: User = Depends(require_tenant_membership),
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Obtém as configurações efetivas de notificação do tenant."""
    settings = await NotificationService.get_settings(session)
    return NotificationSettingsResponse.model_validate(settings)


@router.put(
    "/settings",
    response_model=NotificationSettingsResponse,
    summary="Atualizar configurações de notificação",
)
async def update_notification_settings(
    data: NotificationSettingsUpdateRequest,
    _: User = Depends(require_tenant_membership),
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Cria ou atualiza as configurações de notificação do tenant."""
    settings = await NotificationService.upsert_settings(session, data)
    await session.commit()
    await session.refresh(settings)
    return NotificationSettingsResponse.model_validate(settings)


@router.get(
    "/patients/{patient_id}",
    response_model=NotificationPatientPreferenceResponse,
    summary="Obter preferência de notificação do paciente",
)
async def get_patient_notification_preference(
    patient_id: int,
    _: User = Depends(require_tenant_membership),
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Obtém as configurações efetivas de notificação de um paciente."""
    preference = await NotificationService.get_patient_preference_details(session, patient_id)
    return NotificationPatientPreferenceResponse.model_validate(preference)


@router.put(
    "/patients/{patient_id}",
    response_model=NotificationPatientPreferenceResponse,
    summary="Atualizar preferência de notificação do paciente",
)
async def upsert_patient_notification_preference(
    patient_id: int,
    data: NotificationPatientPreferenceUpsertRequest,
    _: User = Depends(require_tenant_membership),
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Cria ou atualiza as configurações de notificação de um paciente."""
    await NotificationService.upsert_patient_preference(session, patient_id, data)
    await session.commit()
    preference = await NotificationService.get_patient_preference_details(session, patient_id)
    return NotificationPatientPreferenceResponse.model_validate(preference)


@router.get(
    "/users/{user_id}",
    response_model=NotificationUserProfileResponse,
    summary="Obter perfil de notificação do usuário",
)
async def get_user_notification_profile(
    user_id: int,
    _: User = Depends(require_tenant_membership),
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Obtém o perfil de notificação de um usuário do tenant."""
    profile = await NotificationService.get_user_profile_details(session, user_id)
    return NotificationUserProfileResponse.model_validate(profile)


@router.put(
    "/users/{user_id}",
    response_model=NotificationUserProfileResponse,
    summary="Atualizar perfil de notificação do usuário",
)
async def upsert_user_notification_profile(
    user_id: int,
    data: NotificationUserProfileUpsertRequest,
    _: User = Depends(require_tenant_membership),
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Cria ou atualiza o perfil de notificação de um usuário do tenant."""
    await NotificationService.upsert_user_profile(session, user_id, data)
    await session.commit()
    profile = await NotificationService.get_user_profile_details(session, user_id)
    return NotificationUserProfileResponse.model_validate(profile)


@router.get(
    "/messages",
    response_model=NotificationMessageListResponse,
    summary="Listar mensagens de notificação",
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
    """Lista mensagens de notificação e tentativas de envio."""
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
    summary="Disparar notificações pendentes",
)
async def dispatch_due_notifications(
    data: NotificationDispatchRequest,
    _: User = Depends(require_tenant_membership),
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Dispara notificações pendentes já vencidas no tenant atual."""
    result = await NotificationService.dispatch_due_messages(session, limit=data.limit)
    await session.commit()
    return NotificationDispatchResponse.model_validate(result)

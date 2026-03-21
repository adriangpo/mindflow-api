"""QStash-backed notification scheduling helpers."""

import logging
from datetime import UTC, datetime, timedelta
from typing import Literal, TypedDict, cast
from uuid import UUID

from qstash.http import QStashError
from qstash.message import PublishResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.config.settings import settings
from src.database.client import get_session, set_tenant_context
from src.features.tenant.models import Tenant
from src.shared.qstash import build_public_url, get_qstash_client

from .models import NotificationMessage
from .schemas import NotificationMessageStatus

logger = logging.getLogger(__name__)

QSTASH_DELAY_HORIZON = timedelta(days=7)
NOTIFICATION_SYNC_SCHEDULE_ID = "mindflow-notification-daily-sync"
NOTIFICATION_SYNC_CRON = "0 0 * * *"
_SESSION_INFO_KEY = "staged_notification_qstash_operations"


class NotificationQStashEnqueueOperation(TypedDict):
    """Queued QStash publish operation staged in one DB session."""

    kind: Literal["enqueue"]
    tenant_id: UUID
    message_id: int


class NotificationQStashCancelOperation(TypedDict):
    """Queued QStash cancel operation staged in one DB session."""

    kind: Literal["cancel"]
    qstash_message_id: str


NotificationQStashOperation = NotificationQStashEnqueueOperation | NotificationQStashCancelOperation


def notification_deliver_callback_path() -> str:
    """Return the signed callback path used for one notification delivery."""
    return f"{settings.api_prefix}/internal/qstash/notifications/deliver"


def notification_sync_callback_path() -> str:
    """Return the signed callback path used for reminder backfill sync."""
    return f"{settings.api_prefix}/internal/qstash/notifications/sync"


def should_schedule_message_with_qstash(scheduled_for: datetime) -> bool:
    """Return whether one notification can be scheduled within QStash free-plan delay limits."""
    return scheduled_for <= datetime.now(UTC) + QSTASH_DELAY_HORIZON


async def enqueue_notification_message(
    *,
    tenant_id: UUID,
    message_id: int,
    scheduled_for: datetime,
) -> str | None:
    """Publish one notification delivery callback to QStash."""
    if not should_schedule_message_with_qstash(scheduled_for):
        return None

    now = datetime.now(UTC)
    delay_seconds = max(int((scheduled_for - now).total_seconds()), 0)
    response = await get_qstash_client().message.publish_json(
        url=build_public_url(notification_deliver_callback_path()),
        body={"message_id": message_id, "tenant_id": str(tenant_id)},
        method="POST",
        headers={"Content-Type": "application/json"},
        delay=delay_seconds or None,
        deduplication_id=f"notification:{message_id}",
    )
    return cast(PublishResponse, response).message_id


async def cancel_notification_message(qstash_message_id: str) -> None:
    """Cancel one previously published QStash notification callback."""
    try:
        await get_qstash_client().message.cancel(qstash_message_id)
    except Exception:
        logger.exception("Failed to cancel QStash notification message %s", qstash_message_id)


def stage_notification_qstash_enqueue(
    session: AsyncSession,
    tenant_id: UUID,
    message_id: int,
    scheduled_for: datetime,
) -> None:
    """Stage one QStash delivery publish when the reminder falls within the free-plan horizon."""
    if not should_schedule_message_with_qstash(scheduled_for):
        return

    operations = session.info.setdefault(_SESSION_INFO_KEY, [])
    operations.append(
        NotificationQStashEnqueueOperation(
            kind="enqueue",
            tenant_id=tenant_id,
            message_id=message_id,
        )
    )


def stage_notification_qstash_cancel(session: AsyncSession, qstash_message_ids: list[str]) -> None:
    """Stage QStash cancellation calls for pending notification callbacks."""
    if not qstash_message_ids:
        return

    operations = session.info.setdefault(_SESSION_INFO_KEY, [])
    operations.extend(
        NotificationQStashCancelOperation(kind="cancel", qstash_message_id=qstash_message_id)
        for qstash_message_id in qstash_message_ids
    )


async def flush_staged_qstash_operations(session: AsyncSession) -> None:
    """Flush QStash publish/cancel operations staged for the current transaction."""
    operations: list[NotificationQStashOperation] = session.info.get(_SESSION_INFO_KEY, [])
    if not operations:
        return

    has_db_mutations = False

    for operation in operations:
        if operation["kind"] == "cancel":
            await cancel_notification_message(operation["qstash_message_id"])
            continue

        stmt = (
            select(NotificationMessage)
            .where(
                NotificationMessage.tenant_id == operation["tenant_id"],
                NotificationMessage.id == operation["message_id"],
            )
            .with_for_update(skip_locked=True)
        )
        result = await session.execute(stmt)
        message = result.scalar_one_or_none()
        if message is None:
            continue
        if message.status != NotificationMessageStatus.PENDING.value:
            continue
        if message.qstash_message_id is not None:
            continue

        qstash_message_id = await enqueue_notification_message(
            tenant_id=operation["tenant_id"],
            message_id=message.id,
            scheduled_for=message.scheduled_for,
        )
        if qstash_message_id is None:
            continue

        message.qstash_message_id = qstash_message_id
        has_db_mutations = True

    if has_db_mutations:
        await session.commit()

    session.info[_SESSION_INFO_KEY] = []


async def _list_active_tenant_ids() -> list[UUID]:
    async with get_session() as session:
        result = await session.execute(select(Tenant.id).where(Tenant.is_active.is_(True)))
        return list(result.scalars().all())


async def ensure_notification_sync_schedule() -> None:
    """Ensure the recurring daily reminder sync schedule exists in QStash."""
    expected_destination = build_public_url(notification_sync_callback_path())
    client = get_qstash_client()

    try:
        existing_schedule = await client.schedule.get(NOTIFICATION_SYNC_SCHEDULE_ID)
    except QStashError:
        existing_schedule = None

    if (
        existing_schedule is not None
        and existing_schedule.destination == expected_destination
        and existing_schedule.cron == NOTIFICATION_SYNC_CRON
        and existing_schedule.method == "POST"
        and not existing_schedule.paused
    ):
        return

    if existing_schedule is not None:
        await client.schedule.delete(NOTIFICATION_SYNC_SCHEDULE_ID)

    await client.schedule.create_json(
        destination=expected_destination,
        cron=NOTIFICATION_SYNC_CRON,
        body={"kind": "notification_sync"},
        method="POST",
        headers={"Content-Type": "application/json"},
        schedule_id=NOTIFICATION_SYNC_SCHEDULE_ID,
    )


async def sync_pending_messages_with_qstash(*, limit_per_tenant: int = 1000) -> dict[str, int]:
    """Backfill QStash schedules for pending messages now inside the 7-day delay window."""
    tenant_ids = await _list_active_tenant_ids()
    scheduled_count = 0
    failed_count = 0

    for tenant_id in tenant_ids:
        async with get_session() as session:
            await set_tenant_context(session, tenant_id)
            stmt = (
                select(NotificationMessage)
                .where(
                    NotificationMessage.tenant_id == tenant_id,
                    NotificationMessage.status == NotificationMessageStatus.PENDING.value,
                    NotificationMessage.qstash_message_id.is_(None),
                    NotificationMessage.scheduled_for <= datetime.now(UTC) + QSTASH_DELAY_HORIZON,
                )
                .order_by(NotificationMessage.scheduled_for.asc(), NotificationMessage.id.asc())
                .limit(limit_per_tenant)
            )
            result = await session.execute(stmt)
            pending_messages = list(result.scalars().all())

            for message in pending_messages:
                try:
                    qstash_message_id = await enqueue_notification_message(
                        tenant_id=tenant_id,
                        message_id=message.id,
                        scheduled_for=message.scheduled_for,
                    )
                except Exception:
                    failed_count += 1
                    logger.exception("Failed to backfill QStash schedule for notification %s", message.id)
                    continue

                if qstash_message_id is None:
                    continue

                message.qstash_message_id = qstash_message_id
                scheduled_count += 1

    return {
        "tenant_count": len(tenant_ids),
        "scheduled_count": scheduled_count,
        "failed_count": failed_count,
    }

"""Redis-backed notification scheduling and delivery runtime."""

import asyncio
import logging
from datetime import UTC, datetime
from typing import cast
from uuid import UUID, uuid7

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.config.settings import settings
from src.database.client import get_session, set_tenant_context
from src.features.tenant.models import Tenant
from src.shared.redis import ensure_stream_group, get_redis

from .delivery import NotificationDeliveryError, get_notification_delivery_backend
from .models import NotificationMessage
from .queue import (
    NOTIFICATION_DELIVERY_GROUP,
    NOTIFICATION_SCHEDULE_KEY,
    notification_delivery_stream,
    parse_schedule_member,
)
from .schemas import NotificationMessageStatus

logger = logging.getLogger(__name__)


async def _list_active_tenant_ids() -> list[UUID]:
    async with get_session() as session:
        result = await session.execute(select(Tenant.id).where(Tenant.is_active.is_(True)))
        return list(result.scalars().all())


async def ensure_delivery_runtime(tenant_id: UUID) -> None:
    """Ensure the per-tenant delivery stream consumer group exists."""
    await ensure_stream_group(notification_delivery_stream(tenant_id), NOTIFICATION_DELIVERY_GROUP)


async def enqueue_due_scheduled_messages(*, limit: int = 100, tenant_id: UUID | None = None) -> int:
    """Move due reminder members from the schedule ZSET into tenant delivery streams."""
    redis = get_redis()
    now_score = datetime.now(UTC).timestamp()
    due_members = await redis.zrangebyscore(
        NOTIFICATION_SCHEDULE_KEY,
        min="-inf",
        max=now_score,
        start=0,
        num=max(limit * 5, limit),
    )
    if not due_members:
        return 0

    selected_members: list[tuple[UUID, int, str]] = []
    for member in due_members:
        member_tenant_id, message_id = parse_schedule_member(member)
        if tenant_id is not None and member_tenant_id != tenant_id:
            continue
        selected_members.append((member_tenant_id, message_id, member))
        if len(selected_members) >= limit:
            break

    if not selected_members:
        return 0

    moved_count = 0
    pipeline = redis.pipeline(transaction=False)
    for member_tenant_id, message_id, member in selected_members:
        removed = await redis.zrem(NOTIFICATION_SCHEDULE_KEY, member)
        if removed != 1:
            continue
        pipeline.xadd(
            notification_delivery_stream(member_tenant_id),
            {
                "tenant_id": str(member_tenant_id),
                "message_id": str(message_id),
            },
        )
        moved_count += 1

    if moved_count:
        await pipeline.execute()
    return moved_count


async def _load_pending_message(session, tenant_id: UUID, message_id: int) -> NotificationMessage | None:
    stmt = (
        select(NotificationMessage)
        .where(
            NotificationMessage.tenant_id == tenant_id,
            NotificationMessage.id == message_id,
        )
        .with_for_update(skip_locked=True)
    )
    result = await session.execute(stmt)
    message = cast(NotificationMessage | None, result.scalar_one_or_none())
    if message is None:
        return None
    if message.status != NotificationMessageStatus.PENDING.value:
        return None
    if message.scheduled_for > datetime.now(UTC):
        return None
    return message


async def _deliver_pending_message(
    session: AsyncSession,
    tenant_id: UUID,
    message_id: int,
) -> dict[str, int]:
    if session.info.get("tenant_id") != tenant_id:
        await set_tenant_context(session, tenant_id)

    message = await _load_pending_message(session, tenant_id, message_id)
    if message is None:
        return {"processed_count": 0, "sent_count": 0, "failed_count": 0}

    delivery_backend = get_notification_delivery_backend()
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
        message.qstash_message_id = None
        return {"processed_count": 1, "sent_count": 0, "failed_count": 1}

    message.status = NotificationMessageStatus.SENT.value
    message.sent_at = attempt_time
    message.failed_at = None
    message.failure_reason = None
    message.provider_message_id = delivery_result.provider_message_id
    message.qstash_message_id = None
    return {"processed_count": 1, "sent_count": 1, "failed_count": 0}


async def _deliver_message_record(
    tenant_id: UUID,
    message_id: int,
    *,
    session: AsyncSession | None = None,
) -> dict[str, int]:
    if session is not None:
        return await _deliver_pending_message(session, tenant_id, message_id)

    async with get_session() as worker_session:
        return await _deliver_pending_message(worker_session, tenant_id, message_id)


async def _collect_claimed_entries(tenant_id: UUID, consumer_name: str) -> list[tuple[str, dict[str, str]]]:
    redis = get_redis()
    stream = notification_delivery_stream(tenant_id)
    result = await redis.xautoclaim(
        stream,
        NOTIFICATION_DELIVERY_GROUP,
        consumer_name,
        min_idle_time=settings.notification_delivery_claim_idle_ms,
        start_id="0-0",
        count=10,
    )
    if not result:
        return []
    if len(result) == 3:
        _, entries, _ = result
    else:
        _, entries = result
    return list(entries)


async def process_delivery_batch_for_tenant(
    tenant_id: UUID,
    *,
    consumer_name: str,
    limit: int,
    block_ms: int | None,
    session: AsyncSession | None = None,
) -> dict[str, int]:
    """Process one Redis-backed delivery batch for a tenant."""
    await ensure_delivery_runtime(tenant_id)

    redis = get_redis()
    stream = notification_delivery_stream(tenant_id)
    entries = await _collect_claimed_entries(tenant_id, consumer_name)
    if not entries:
        read_result = await redis.xreadgroup(
            NOTIFICATION_DELIVERY_GROUP,
            consumer_name,
            {stream: ">"},
            count=limit,
            block=block_ms if block_ms is not None else settings.notification_delivery_block_ms,
        )
        if not read_result:
            return {"processed_count": 0, "sent_count": 0, "failed_count": 0}
        _, entries = read_result[0]

    totals = {"processed_count": 0, "sent_count": 0, "failed_count": 0}
    for entry_id, fields in entries:
        try:
            counts = await _deliver_message_record(
                tenant_id,
                int(fields["message_id"]),
                session=session,
            )
        except Exception:
            logger.exception("Notification delivery failed for tenant %s entry %s", tenant_id, entry_id)
            continue

        for key, value in counts.items():
            totals[key] += value

        await redis.xack(stream, NOTIFICATION_DELIVERY_GROUP, entry_id)
        await redis.xdel(stream, entry_id)

    return totals


async def dispatch_due_messages_now(
    tenant_id: UUID,
    *,
    limit: int,
    session: AsyncSession | None = None,
) -> dict[str, int]:
    """Synchronously promote and process due notifications for one tenant."""
    await enqueue_due_scheduled_messages(limit=limit, tenant_id=tenant_id)
    return await process_delivery_batch_for_tenant(
        tenant_id,
        consumer_name=f"manual-{uuid7()}",
        limit=limit,
        block_ms=1,
        session=session,
    )


async def deliver_message_now(
    tenant_id: UUID,
    message_id: int,
    *,
    session: AsyncSession | None = None,
) -> dict[str, int]:
    """Deliver one pending notification message immediately."""
    return await _deliver_message_record(tenant_id, message_id, session=session)


async def run_notification_scheduler_loop() -> None:
    """Continuously promote due reminder items into tenant delivery streams."""
    while True:
        try:
            await enqueue_due_scheduled_messages(limit=100)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Notification scheduler iteration failed")

        await asyncio.sleep(1)


async def run_notification_delivery_loop() -> None:
    """Continuously deliver queued notification messages for all active tenants."""
    consumer_name = f"worker-{uuid7()}"
    while True:
        try:
            tenant_ids = await _list_active_tenant_ids()
            for tenant_id in tenant_ids:
                await process_delivery_batch_for_tenant(
                    tenant_id,
                    consumer_name=consumer_name,
                    limit=100,
                    block_ms=1,
                )
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Notification delivery loop iteration failed")

        await asyncio.sleep(1)


async def run_notification_runtime() -> None:
    """Run notification scheduler and delivery loops together."""
    await asyncio.gather(
        run_notification_scheduler_loop(),
        run_notification_delivery_loop(),
    )

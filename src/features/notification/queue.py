"""Redis queue helpers for notification scheduling and delivery."""

from datetime import datetime
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from src.shared.redis import stage_redis_operation

NOTIFICATION_DELIVERY_GROUP = "notifications:workers"
NOTIFICATION_SCHEDULE_KEY = "notifications:schedule"


def notification_delivery_stream(tenant_id: UUID) -> str:
    """Return the Redis stream key for one tenant delivery queue."""
    return f"notifications:deliveries:{tenant_id}"


def build_schedule_member(tenant_id: UUID, message_id: int) -> str:
    """Build a Redis sorted-set member for one scheduled notification."""
    return f"{tenant_id}|{message_id}"


def parse_schedule_member(member: str) -> tuple[UUID, int]:
    """Parse a scheduled notification member from Redis."""
    tenant_id_raw, message_id_raw = member.split("|", maxsplit=1)
    return UUID(tenant_id_raw), int(message_id_raw)


def stage_notification_delivery(session: AsyncSession, tenant_id: UUID, message_id: int) -> None:
    """Stage an immediate notification delivery enqueue."""
    stage_redis_operation(
        session,
        {
            "kind": "xadd",
            "stream": notification_delivery_stream(tenant_id),
            "fields": {
                "tenant_id": str(tenant_id),
                "message_id": str(message_id),
            },
        },
    )


def stage_notification_schedule(
    session: AsyncSession,
    tenant_id: UUID,
    message_id: int,
    scheduled_for: datetime,
) -> None:
    """Stage a future notification reminder schedule entry."""
    stage_redis_operation(
        session,
        {
            "kind": "zadd",
            "key": NOTIFICATION_SCHEDULE_KEY,
            "member": build_schedule_member(tenant_id, message_id),
            "score": scheduled_for.timestamp(),
        },
    )


def stage_notification_schedule_removal(session: AsyncSession, tenant_id: UUID, message_ids: list[int]) -> None:
    """Stage removal of scheduled reminder entries from Redis."""
    if not message_ids:
        return
    stage_redis_operation(
        session,
        {
            "kind": "zrem",
            "key": NOTIFICATION_SCHEDULE_KEY,
            "members": [build_schedule_member(tenant_id, message_id) for message_id in message_ids],
        },
    )

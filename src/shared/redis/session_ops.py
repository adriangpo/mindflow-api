"""Helpers for staging Redis operations until after DB commit."""

from typing import Literal, TypedDict

from sqlalchemy.ext.asyncio import AsyncSession

from .client import get_redis

_SESSION_INFO_KEY = "staged_redis_operations"
RedisScalar = bytes | bytearray | memoryview[int] | str | int | float


class RedisXAddOperation(TypedDict):
    """Redis XADD operation staged in session.info."""

    kind: Literal["xadd"]
    stream: str
    fields: dict[RedisScalar, RedisScalar]


class RedisZAddOperation(TypedDict):
    """Redis ZADD operation staged in session.info."""

    kind: Literal["zadd"]
    key: str
    member: str
    score: float


class RedisZRemOperation(TypedDict):
    """Redis ZREM operation staged in session.info."""

    kind: Literal["zrem"]
    key: str
    members: list[str]


RedisOperation = RedisXAddOperation | RedisZAddOperation | RedisZRemOperation


def stage_redis_operation(session: AsyncSession, operation: RedisOperation) -> None:
    """Stage a Redis operation to run only after the DB commit succeeds."""
    operations = session.info.setdefault(_SESSION_INFO_KEY, [])
    operations.append(operation)


async def flush_staged_redis_operations(session: AsyncSession) -> None:
    """Run staged Redis operations after a successful commit."""
    operations: list[RedisOperation] = session.info.get(_SESSION_INFO_KEY, [])
    if not operations:
        return

    redis = get_redis()
    pipeline = redis.pipeline(transaction=False)

    for operation in operations:
        if operation["kind"] == "xadd":
            pipeline.xadd(operation["stream"], fields=operation["fields"])
            continue
        if operation["kind"] == "zadd":
            pipeline.zadd(operation["key"], {operation["member"]: operation["score"]})
            continue
        if operation["members"]:
            pipeline.zrem(operation["key"], *operation["members"])

    await pipeline.execute()
    session.info[_SESSION_INFO_KEY] = []


async def commit_with_staged_redis(session: AsyncSession) -> None:
    """Commit the session and then flush staged Redis and notification callback operations."""
    await session.commit()
    await flush_staged_redis_operations(session)
    if session.info.get("staged_notification_qstash_operations"):
        from src.features.notification.qstash import flush_staged_qstash_operations

        await flush_staged_qstash_operations(session)

"""Shared Redis client and stream helpers."""

import json
import logging
from collections.abc import Awaitable
from typing import Any, cast

from redis.asyncio import Redis, from_url
from redis.exceptions import ResponseError

from src.config.settings import settings

logger = logging.getLogger(__name__)

_redis: Redis | None = None


def get_redis() -> Redis:
    """Return the initialized Redis client."""
    global _redis
    if _redis is None:
        raise RuntimeError("Redis not initialized. Call init_redis() first.")
    return _redis


async def init_redis() -> None:
    """Initialize the shared Redis client."""
    global _redis
    if _redis is not None:
        return

    _redis = from_url(
        settings.redis_url,
        decode_responses=True,
    )
    await cast(Awaitable[bool], _redis.ping())
    logger.info("Redis connection successful")


async def close_redis() -> None:
    """Close the shared Redis client."""
    global _redis
    if _redis is None:
        return

    await _redis.aclose()
    _redis = None


async def ensure_stream_group(stream: str, group: str) -> None:
    """Create a Redis stream consumer group if it does not exist."""
    redis = get_redis()
    try:
        await redis.xgroup_create(stream, group, id="0-0", mkstream=True)
    except ResponseError as exc:
        if "BUSYGROUP" not in str(exc):
            raise


def dumps_json(value: Any) -> str:
    """Serialize JSON data for Redis storage."""
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def loads_json(value: str | bytes) -> Any:
    """Deserialize JSON data from Redis storage."""
    if isinstance(value, bytes):
        value = value.decode("utf-8")
    return json.loads(value)

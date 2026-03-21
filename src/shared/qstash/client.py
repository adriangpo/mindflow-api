"""Shared QStash configuration, client, and signature helpers."""

import logging

from fastapi import HTTPException, Request, status
from qstash import AsyncQStash, Receiver

from src.config.settings import settings

logger = logging.getLogger(__name__)

_qstash_client: AsyncQStash | None = None
_qstash_receiver: Receiver | None = None


class QStashConfigurationError(RuntimeError):
    """Raised when QStash-specific configuration is incomplete."""


def _require_qstash_setting(name: str, value: str) -> str:
    normalized = value.strip()
    if normalized:
        return normalized
    raise QStashConfigurationError(f"{name} must be configured when JOB_DISPATCH_MODE=qstash")


def build_public_url(path: str) -> str:
    """Build an externally reachable absolute URL from one application path."""
    base_url = _require_qstash_setting("PUBLIC_BASE_URL", settings.public_base_url)
    normalized_path = path if path.startswith("/") else f"/{path}"
    return f"{base_url}{normalized_path}"


def get_qstash_client() -> AsyncQStash:
    """Return the shared QStash async client."""
    global _qstash_client
    if _qstash_client is None:
        _qstash_client = AsyncQStash(
            _require_qstash_setting("QSTASH_TOKEN", settings.qstash_token),
            base_url=_require_qstash_setting("QSTASH_URL", settings.qstash_url),
        )
    return _qstash_client


def get_qstash_receiver() -> Receiver:
    """Return the shared QStash receiver used for callback verification."""
    global _qstash_receiver
    if _qstash_receiver is None:
        _qstash_receiver = Receiver(
            _require_qstash_setting("QSTASH_CURRENT_SIGNING_KEY", settings.qstash_current_signing_key),
            _require_qstash_setting("QSTASH_NEXT_SIGNING_KEY", settings.qstash_next_signing_key),
        )
    return _qstash_receiver


async def verify_qstash_request(request: Request, *, path: str) -> str:
    """Verify a signed QStash callback and return the raw request body."""
    if not settings.qstash_enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="QStash callbacks are disabled")

    signature = request.headers.get("Upstash-Signature")
    if signature is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing QStash signature")

    body_bytes = await request.body()
    raw_body = body_bytes.decode("utf-8")
    expected_url = build_public_url(path)

    try:
        get_qstash_receiver().verify(
            signature=signature,
            body=raw_body,
            url=expected_url,
        )
    except Exception as exc:
        logger.warning("Rejected QStash callback for %s: %s", expected_url, exc)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid QStash signature") from exc

    return raw_body

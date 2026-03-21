"""Notification delivery backend abstraction."""

import logging
from asyncio import to_thread
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Protocol
from uuid import uuid7

from src.config.settings import settings

TwilioClient: Any | None
TwilioSDKError: type[Exception]

try:
    from twilio.base.exceptions import TwilioException as _TwilioSDKError
    from twilio.rest import Client as _TwilioClient
except ImportError:  # pragma: no cover - import path depends on installed extras
    TwilioClient = None

    class _TwilioFallbackSDKError(Exception):
        """Fallback Twilio exception type when the SDK is unavailable."""

    TwilioSDKError = _TwilioFallbackSDKError
else:
    TwilioClient = _TwilioClient
    TwilioSDKError = _TwilioSDKError


logger = logging.getLogger(__name__)


class NotificationDeliveryError(Exception):
    """Raised when the delivery backend cannot send a notification."""


@dataclass(slots=True)
class NotificationDeliveryResult:
    """Successful delivery metadata returned by the backend."""

    provider_message_id: str


class NotificationDeliveryBackend(Protocol):
    """Protocol for outbound notification delivery backends."""

    async def send_whatsapp(self, *, destination: str, content: str) -> NotificationDeliveryResult:
        """Send a WhatsApp message."""


class LoggingNotificationDeliveryBackend:
    """Development-safe backend that logs outbound notifications."""

    async def send_whatsapp(self, *, destination: str, content: str) -> NotificationDeliveryResult:
        """Persist a successful stub send in logs and return synthetic metadata."""
        logger.info("Notificação de WhatsApp simulada enviada para %s: %s", destination, content)
        return NotificationDeliveryResult(provider_message_id=str(uuid7()))


class TwilioNotificationDeliveryBackend:
    """Twilio-backed WhatsApp delivery implementation."""

    def __init__(
        self,
        *,
        account_sid: str,
        auth_token: str,
        from_whatsapp_number: str,
        default_country_code: str,
        client: Any | None = None,
    ):
        self._account_sid = account_sid
        self._auth_token = auth_token
        self._from_whatsapp_number = from_whatsapp_number
        self._default_country_code = default_country_code
        self._client = client

    @staticmethod
    def _normalize_e164(number: str, *, default_country_code: str | None = None) -> str:
        normalized = number.strip()
        if not normalized:
            raise NotificationDeliveryError("Número de telefone vazio")

        if normalized.startswith("whatsapp:"):
            normalized = normalized.removeprefix("whatsapp:")

        if normalized.startswith("+"):
            digits = "".join(char for char in normalized if char.isdigit())
            if not digits:
                raise NotificationDeliveryError("O número de telefone deve conter dígitos")
            return f"+{digits}"

        digits = "".join(char for char in normalized if char.isdigit())
        if not digits:
            raise NotificationDeliveryError("O número de telefone deve conter dígitos")

        if default_country_code is None:
            return f"+{digits}"
        return f"{default_country_code}{digits}"

    @classmethod
    def _build_whatsapp_address(cls, number: str, *, default_country_code: str | None = None) -> str:
        return f"whatsapp:{cls._normalize_e164(number, default_country_code=default_country_code)}"

    def _get_client(self) -> Any:
        if self._client is not None:
            return self._client

        if TwilioClient is None:
            raise NotificationDeliveryError("O SDK do Twilio não está instalado")
        if not self._account_sid or not self._auth_token or not self._from_whatsapp_number:
            raise NotificationDeliveryError(
                "O WhatsApp do Twilio não está totalmente configurado; defina "
                "TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN e TWILIO_WHATSAPP_FROM_NUMBER"
            )

        self._client = TwilioClient(self._account_sid, self._auth_token)
        return self._client

    def _send_whatsapp_sync(self, *, destination: str, content: str) -> NotificationDeliveryResult:
        client = self._get_client()
        from_address = self._build_whatsapp_address(self._from_whatsapp_number)
        to_address = self._build_whatsapp_address(
            destination,
            default_country_code=self._default_country_code,
        )

        message = client.messages.create(
            body=content,
            from_=from_address,
            to=to_address,
        )
        return NotificationDeliveryResult(provider_message_id=message.sid)

    async def send_whatsapp(self, *, destination: str, content: str) -> NotificationDeliveryResult:
        """Send a WhatsApp message through Twilio."""
        try:
            return await to_thread(
                self._send_whatsapp_sync,
                destination=destination,
                content=content,
            )
        except TwilioSDKError as exc:
            logger.exception("Falha no envio de notificação via Twilio")
            raise NotificationDeliveryError("Falha no envio da notificação via Twilio") from exc


@lru_cache(maxsize=1)
def get_notification_delivery_backend() -> NotificationDeliveryBackend:
    """Resolve the outbound notification backend from app settings."""
    if settings.notification_provider == "stub":
        return LoggingNotificationDeliveryBackend()

    if settings.notification_provider == "twilio":
        return TwilioNotificationDeliveryBackend(
            account_sid=settings.twilio_account_sid,
            auth_token=settings.twilio_auth_token,
            from_whatsapp_number=settings.twilio_whatsapp_from_number,
            default_country_code=settings.notification_default_country_code,
        )

    if settings.twilio_account_sid and settings.twilio_auth_token and settings.twilio_whatsapp_from_number:
        return TwilioNotificationDeliveryBackend(
            account_sid=settings.twilio_account_sid,
            auth_token=settings.twilio_auth_token,
            from_whatsapp_number=settings.twilio_whatsapp_from_number,
            default_country_code=settings.notification_default_country_code,
        )

    return LoggingNotificationDeliveryBackend()

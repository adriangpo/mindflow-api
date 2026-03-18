"""Tests for notification delivery backend selection and Twilio formatting."""

from types import SimpleNamespace

import pytest

from src.config.settings import settings
from src.features.notification.delivery import (
    LoggingNotificationDeliveryBackend,
    TwilioNotificationDeliveryBackend,
    get_notification_delivery_backend,
)


@pytest.fixture(autouse=True)
def clear_notification_backend_cache():
    """Clear cached delivery backend before and after each test."""
    get_notification_delivery_backend.cache_clear()
    yield
    get_notification_delivery_backend.cache_clear()


class TestNotificationDeliveryBackendResolution:
    """Tests for backend resolution from settings."""

    def test_auto_mode_falls_back_to_stub_when_twilio_is_not_configured(self, monkeypatch):
        monkeypatch.setattr(settings, "notification_provider", "auto")
        monkeypatch.setattr(settings, "twilio_account_sid", "")
        monkeypatch.setattr(settings, "twilio_auth_token", "")
        monkeypatch.setattr(settings, "twilio_whatsapp_from_number", "")
        get_notification_delivery_backend.cache_clear()

        backend = get_notification_delivery_backend()

        assert isinstance(backend, LoggingNotificationDeliveryBackend)

    def test_auto_mode_uses_twilio_when_credentials_are_present(self, monkeypatch):
        monkeypatch.setattr(settings, "notification_provider", "auto")
        monkeypatch.setattr(settings, "twilio_account_sid", "AC123")
        monkeypatch.setattr(settings, "twilio_auth_token", "secret")
        monkeypatch.setattr(settings, "twilio_whatsapp_from_number", "+14155238886")
        monkeypatch.setattr(settings, "notification_default_country_code", "+55")
        get_notification_delivery_backend.cache_clear()

        backend = get_notification_delivery_backend()

        assert isinstance(backend, TwilioNotificationDeliveryBackend)


class TestTwilioNotificationDeliveryBackend:
    """Tests for Twilio backend message formatting."""

    async def test_send_whatsapp_formats_sender_and_destination_as_whatsapp_addresses(self):
        calls: list[dict[str, str]] = []

        class FakeMessages:
            def create(self, **kwargs):
                calls.append(kwargs)
                return SimpleNamespace(sid="SM123")

        fake_client = SimpleNamespace(messages=FakeMessages())
        backend = TwilioNotificationDeliveryBackend(
            account_sid="AC123",
            auth_token="secret",
            from_whatsapp_number="+14155238886",
            default_country_code="+55",
            client=fake_client,
        )

        result = await backend.send_whatsapp(
            destination="14999999999",
            content="Lembrete de consulta",
        )

        assert result.provider_message_id == "SM123"
        assert calls == [
            {
                "body": "Lembrete de consulta",
                "from_": "whatsapp:+14155238886",
                "to": "whatsapp:+5514999999999",
            }
        ]

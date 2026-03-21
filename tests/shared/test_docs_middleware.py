"""Tests for admin-only API documentation middleware."""

from types import SimpleNamespace

import pytest
from httpx import ASGITransport, AsyncClient

from src.config.settings import settings
from src.features.user.models import UserRole
from src.main import app
from src.shared.middlewares import docs_middleware as docs_middleware_module

PROTECTED_DOC_PATHS = ("/docs", "/redoc", "/openapi.json")


@pytest.mark.parametrize("path", PROTECTED_DOC_PATHS)
async def test_docs_routes_are_public_in_development(monkeypatch: pytest.MonkeyPatch, path: str):
    """Ensure docs routes stay public in development mode."""
    monkeypatch.setattr(settings, "environment", "development")

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        response = await client.get(path)

    assert response.status_code == 200


@pytest.mark.parametrize("path", PROTECTED_DOC_PATHS)
async def test_docs_routes_require_authentication_outside_development(monkeypatch: pytest.MonkeyPatch, path: str):
    """Ensure docs routes reject anonymous requests outside development."""
    monkeypatch.setattr(settings, "environment", "staging")

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        response = await client.get(path)

    assert response.status_code == 403
    assert response.json() == {"detail": "Not authenticated."}


@pytest.mark.parametrize("path", PROTECTED_DOC_PATHS)
async def test_docs_routes_require_admin_role_outside_development(monkeypatch: pytest.MonkeyPatch, path: str):
    """Ensure docs routes reject authenticated non-admin users outside development."""
    monkeypatch.setattr(settings, "environment", "production")

    async def _return_non_admin(*_args, **_kwargs):
        return SimpleNamespace(roles=[UserRole.TENANT_OWNER.value])

    monkeypatch.setattr(docs_middleware_module, "get_current_user", _return_non_admin)

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        response = await client.get(path, headers={"Authorization": "Bearer test-token"})

    assert response.status_code == 403
    assert response.json() == {"detail": "Insufficient permissions."}


@pytest.mark.parametrize("path", PROTECTED_DOC_PATHS)
async def test_docs_routes_allow_admin_outside_development(monkeypatch: pytest.MonkeyPatch, path: str):
    """Ensure docs routes remain accessible to admins outside development."""
    monkeypatch.setattr(settings, "environment", "production")

    async def _return_admin(*_args, **_kwargs):
        return SimpleNamespace(roles=[UserRole.ADMIN.value])

    monkeypatch.setattr(docs_middleware_module, "get_current_user", _return_admin)

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        response = await client.get(path, headers={"Authorization": "Bearer test-token"})

    assert response.status_code == 200

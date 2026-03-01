"""Tests for tenant feature (service + API)."""

from uuid import uuid7

import pytest
from fastapi import status

from src.config.settings import settings
from src.features.tenant.exceptions import (
    TenantInvalidSlug,
    TenantNameAlreadyExists,
    TenantSlugAlreadyExists,
)
from src.features.tenant.schemas import TenantCreateRequest
from src.features.tenant.service import TenantService


class TestTenantService:
    """Service layer tests for tenants."""

    async def test_create_tenant_success(self, session):
        data = TenantCreateRequest(name="Acme Clinic")

        tenant = await TenantService.create_tenant(session, data)

        assert tenant.name == "Acme Clinic"
        assert tenant.slug == "acme-clinic"
        assert tenant.is_active is True

    async def test_create_tenant_duplicate_name(self, session):
        await TenantService.create_tenant(session, TenantCreateRequest(name="Acme"))

        with pytest.raises(TenantNameAlreadyExists):
            await TenantService.create_tenant(session, TenantCreateRequest(name="Acme"))

    async def test_create_tenant_slug_collision_gets_suffix(self, session):
        tenant_1 = await TenantService.create_tenant(session, TenantCreateRequest(name="Acme Clinic"))
        tenant_2 = await TenantService.create_tenant(session, TenantCreateRequest(name="Acme Clinic  "))
        await session.flush()

        assert tenant_1.slug == "acme-clinic"
        assert tenant_2.slug == "acme-clinic-2"

    async def test_create_tenant_with_custom_slug(self, session):
        tenant = await TenantService.create_tenant(session, TenantCreateRequest(name="Acme Clinic", slug="my-clinic"))
        assert tenant.slug == "my-clinic"

    async def test_create_tenant_with_duplicate_custom_slug(self, session):
        await TenantService.create_tenant(session, TenantCreateRequest(name="Clinic A", slug="shared-slug"))
        with pytest.raises(TenantSlugAlreadyExists):
            await TenantService.create_tenant(session, TenantCreateRequest(name="Clinic B", slug="shared-slug"))

    async def test_create_tenant_with_invalid_custom_slug(self, session):
        with pytest.raises(TenantInvalidSlug):
            await TenantService.create_tenant(session, TenantCreateRequest(name="Clinic A", slug="invalid slug!"))


class TestTenantEndpoints:
    """API tests for tenant management endpoints."""

    async def test_create_tenant_admin_only(self, admin_client):
        client, admin_user = admin_client

        response = await client.post(
            f"{settings.api_prefix}/tenants",
            json={"name": "Blue Clinic", "slug": "blue-clinic", "is_active": True},
        )

        assert response.status_code == status.HTTP_200_OK
        assert response.json()["slug"] == "blue-clinic"

    async def test_create_tenant_non_admin_forbidden(self, auth_client):
        client, user = auth_client

        response = await client.post(
            f"{settings.api_prefix}/tenants",
            json={"name": "Blue Clinic", "is_active": True},
        )

        assert response.status_code == status.HTTP_403_FORBIDDEN

    async def test_list_tenants_admin_only(self, admin_client):
        client, admin_user = admin_client

        await client.post(f"{settings.api_prefix}/tenants", json={"name": "Clinic A"})
        await client.post(f"{settings.api_prefix}/tenants", json={"name": "Clinic B"})

        response = await client.get(f"{settings.api_prefix}/tenants")

        assert response.status_code == status.HTTP_200_OK
        assert response.json()["total"] >= 2

    async def test_update_tenant(self, admin_client):
        client, admin_user = admin_client

        create_response = await client.post(
            f"{settings.api_prefix}/tenants",
            json={"name": "Old Name", "is_active": True},
        )
        tenant_id = create_response.json()["id"]

        update_response = await client.put(
            f"{settings.api_prefix}/tenants/{tenant_id}",
            json={"name": "New Name", "is_active": False},
        )

        assert update_response.status_code == status.HTTP_200_OK
        payload = update_response.json()
        assert payload["name"] == "New Name"
        assert payload["slug"] == "new-name"

    async def test_delete_tenant(self, admin_client):
        client, admin_user = admin_client

        create_response = await client.post(
            f"{settings.api_prefix}/tenants",
            json={"name": "Delete Me", "is_active": True},
        )
        tenant_id = create_response.json()["id"]

        delete_response = await client.delete(f"{settings.api_prefix}/tenants/{tenant_id}")

        assert delete_response.status_code == status.HTTP_200_OK
        assert "deactivated successfully" in delete_response.json()["message"]

        get_response = await client.get(f"{settings.api_prefix}/tenants/{tenant_id}")
        assert get_response.status_code == status.HTTP_200_OK
        assert get_response.json()["is_active"] is False

    async def test_get_tenant_not_found(self, admin_client):
        client, admin_user = admin_client

        response = await client.get(f"{settings.api_prefix}/tenants/{uuid7()}")

        assert response.status_code == status.HTTP_404_NOT_FOUND

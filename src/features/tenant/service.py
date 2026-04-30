"""Tenant service layer."""

import logging
import re
import unicodedata
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.shared.pagination.pagination import PaginationParams

from .exceptions import TenantInvalidSlug, TenantNameAlreadyExists, TenantSlugAlreadyExists
from .models import Tenant
from .schemas import TenantCreateRequest, TenantUpdateRequest

logger = logging.getLogger(__name__)
SLUG_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


class TenantService:
    """Service for tenant operations."""

    @staticmethod
    def _slugify(value: str) -> str:
        """Generate a normalized slug from tenant name."""
        normalized = unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode("ascii")
        slug = re.sub(r"[^a-zA-Z0-9]+", "-", normalized.lower()).strip("-")
        slug = re.sub(r"-{2,}", "-", slug)
        if not slug:
            return "tenant"
        return slug[:120].rstrip("-")

    @staticmethod
    def _normalize_and_validate_slug(value: str) -> str:
        """Normalize and validate a user-provided slug."""
        slug = value.strip().lower()
        if not slug or not SLUG_PATTERN.fullmatch(slug):
            raise TenantInvalidSlug()
        return slug[:120].rstrip("-")

    @staticmethod
    async def _ensure_slug_available(session: AsyncSession, slug: str, exclude_tenant_id: UUID | None = None) -> None:
        """Ensure a slug is not already used by another tenant."""
        stmt = select(Tenant).where(Tenant.slug == slug)
        if exclude_tenant_id is not None:
            stmt = stmt.where(Tenant.id != exclude_tenant_id)
        result = await session.execute(stmt)
        if result.scalar_one_or_none() is not None:
            raise TenantSlugAlreadyExists()

    @staticmethod
    async def _generate_unique_slug(session: AsyncSession, name: str, exclude_tenant_id: UUID | None = None) -> str:
        """Generate a unique slug for a tenant name."""
        base_slug = TenantService._slugify(name)
        slug = base_slug
        counter = 2

        while True:
            stmt = select(Tenant).where(Tenant.slug == slug)
            if exclude_tenant_id is not None:
                stmt = stmt.where(Tenant.id != exclude_tenant_id)
            result = await session.execute(stmt)
            if result.scalar_one_or_none() is None:
                return slug

            suffix = f"-{counter}"
            slug = f"{base_slug[: 120 - len(suffix)].rstrip('-')}{suffix}"
            counter += 1

    @staticmethod
    async def create_tenant(session: AsyncSession, data: TenantCreateRequest) -> Tenant:
        """Create a new tenant."""
        existing_name_stmt = select(Tenant).where(Tenant.name == data.name)
        existing_name_result = await session.execute(existing_name_stmt)
        if existing_name_result.scalar_one_or_none():
            raise TenantNameAlreadyExists()

        if data.slug is not None:
            slug = TenantService._normalize_and_validate_slug(data.slug)
            await TenantService._ensure_slug_available(session, slug)
        else:
            slug = await TenantService._generate_unique_slug(session, data.name)

        tenant = Tenant(name=data.name, slug=slug, is_active=True)
        session.add(tenant)
        logger.info("Tenant created: %s", tenant.slug)
        return tenant

    @staticmethod
    async def get_tenant(session: AsyncSession, tenant_id: UUID) -> Tenant | None:
        """Get tenant by id."""
        stmt = select(Tenant).where(Tenant.id == tenant_id)
        result = await session.execute(stmt)
        return result.scalar_one_or_none()

    @staticmethod
    async def get_tenants(session: AsyncSession, pagination: PaginationParams) -> tuple[list[Tenant], int]:
        """Get paginated tenants list."""
        count_stmt = select(func.count()).select_from(Tenant)
        total_result = await session.execute(count_stmt)
        total = total_result.scalar_one()

        stmt = select(Tenant)
        if pagination.is_paginated:
            stmt = stmt.offset(pagination.skip).limit(pagination.limit)

        result = await session.execute(stmt)
        tenants = list(result.scalars().all())
        return tenants, total

    @staticmethod
    async def update_tenant(session: AsyncSession, tenant: Tenant, data: TenantUpdateRequest) -> Tenant:
        """Update tenant fields."""
        if data.name is not None and data.name != tenant.name:
            existing_name_stmt = select(Tenant).where(Tenant.name == data.name)
            existing_name_result = await session.execute(existing_name_stmt)
            if existing_name_result.scalar_one_or_none():
                raise TenantNameAlreadyExists()
            tenant.name = data.name

            if data.slug is None:
                tenant.slug = await TenantService._generate_unique_slug(session, data.name, exclude_tenant_id=tenant.id)

        if data.slug is not None:
            normalized_slug = TenantService._normalize_and_validate_slug(data.slug)
            if normalized_slug != tenant.slug:
                await TenantService._ensure_slug_available(session, normalized_slug, exclude_tenant_id=tenant.id)
                tenant.slug = normalized_slug

        logger.info("Tenant updated: %s", tenant.id)
        return tenant

    @staticmethod
    async def delete_tenant(tenant: Tenant) -> None:
        """Deactivate tenant instead of deleting it."""
        tenant.is_active = False
        logger.info("Tenant deactivated: %s", tenant.id)

    @staticmethod
    async def get_accessible_tenants(session: AsyncSession, tenant_ids: list[UUID], is_admin: bool) -> list[Tenant]:
        """Return active tenants the user can access.

        Admins receive every active tenant; other users receive only their assigned active tenants.
        """
        if is_admin:
            stmt = select(Tenant).where(Tenant.is_active.is_(True))
        else:
            if not tenant_ids:
                return []
            stmt = select(Tenant).where(Tenant.id.in_(tenant_ids), Tenant.is_active.is_(True))

        result = await session.execute(stmt)
        return list(result.scalars().all())

    @staticmethod
    async def reactivate_tenant(tenant: Tenant) -> None:
        """Reactivate a previously deactivated tenant."""
        tenant.is_active = True
        logger.info("Tenant reactivated: %s", tenant.id)

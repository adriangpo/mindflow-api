"""Tenant management router (admin only)."""

import logging
from uuid import UUID

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from src.database.dependencies import get_db_session
from src.features.auth.dependencies import get_current_active_user, require_role
from src.features.user.models import User, UserRole
from src.shared.pagination.pagination import PaginationParams

from .exceptions import TenantNotFound
from .schemas import TenantCreateRequest, TenantListResponse, TenantResponse, TenantUpdateRequest
from .service import TenantService

logger = logging.getLogger(__name__)
router = APIRouter(
    prefix="/tenants",
    tags=["Tenant Management"],
    dependencies=[Depends(require_role(UserRole.ADMIN))],
)


@router.post("", response_model=TenantResponse)
async def create_tenant(
    data: TenantCreateRequest,
    current_user: User = Depends(get_current_active_user),
    session: AsyncSession = Depends(get_db_session),
):
    """Create a tenant (admin only)."""
    tenant = await TenantService.create_tenant(session, data)
    await session.commit()
    logger.info(f"Tenant created by admin {current_user.username}: {tenant.slug}")
    return TenantResponse.model_validate(tenant)


@router.get("", response_model=TenantListResponse)
async def list_tenants(
    pagination: PaginationParams = Depends(),
    session: AsyncSession = Depends(get_db_session),
):
    """List tenants (admin only)."""
    tenants, total = await TenantService.get_tenants(session, pagination)
    return TenantListResponse(
        tenants=[TenantResponse.model_validate(tenant) for tenant in tenants],
        total=total,
        page=pagination.page or 1,
        page_size=pagination.page_size or 50,
    )


@router.get("/{tenant_id}", response_model=TenantResponse)
async def get_tenant(tenant_id: UUID, session: AsyncSession = Depends(get_db_session)):
    """Get tenant by id (admin only)."""
    tenant = await TenantService.get_tenant(session, tenant_id)
    if not tenant:
        raise TenantNotFound()
    return TenantResponse.model_validate(tenant)


@router.put("/{tenant_id}", response_model=TenantResponse)
async def update_tenant(
    tenant_id: UUID,
    data: TenantUpdateRequest,
    current_user: User = Depends(get_current_active_user),
    session: AsyncSession = Depends(get_db_session),
):
    """Update tenant (admin only)."""
    tenant = await TenantService.get_tenant(session, tenant_id)
    if not tenant:
        raise TenantNotFound()

    updated = await TenantService.update_tenant(session, tenant, data)
    await session.commit()
    logger.info(f"Tenant updated by admin {current_user.username}: {tenant_id}")
    return TenantResponse.model_validate(updated)


@router.delete("/{tenant_id}")
async def delete_tenant(
    tenant_id: UUID,
    current_user: User = Depends(get_current_active_user),
    session: AsyncSession = Depends(get_db_session),
):
    """Deactivate tenant (admin only)."""
    tenant = await TenantService.get_tenant(session, tenant_id)
    if not tenant:
        raise TenantNotFound()

    await TenantService.delete_tenant(tenant)
    await session.commit()
    logger.info(f"Tenant deactivated by admin {current_user.username}: {tenant_id}")
    return {"message": "Tenant deactivated successfully"}

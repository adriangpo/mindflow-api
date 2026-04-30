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
from .openapi import (
    TENANT_CONFLICT_RESPONSE,
    TENANT_FORBIDDEN_RESPONSE,
    TENANT_LIST_RESPONSE_EXAMPLE,
    TENANT_MESSAGE_RESPONSE_EXAMPLE,
    TENANT_NOT_FOUND_RESPONSE,
    TENANT_RESPONSE_EXAMPLE,
    TENANT_UNAUTHORIZED_RESPONSE,
    TenantMessageResponse,
)
from .schemas import TenantCreateRequest, TenantListResponse, TenantResponse, TenantUpdateRequest
from .service import TenantService

logger = logging.getLogger(__name__)
router = APIRouter(
    prefix="/tenants",
    tags=["Tenant Management"],
    dependencies=[Depends(require_role(UserRole.ADMIN))],
)


@router.post(
    "",
    response_model=TenantResponse,
    summary="Create a tenant",
    description=(
        "Create a new global tenant record. The `name` must be unique. When `slug` is omitted, the service derives "
        "one from the name and appends a numeric suffix when needed to avoid collisions. When `slug` is provided, "
        "it is normalized to lowercase, must match the hyphenated slug pattern, and must be unique. Extra payload "
        "fields are ignored by the request model, so flags such as `is_active` have no write effect."
    ),
    response_description="The tenant that was created.",
    responses={
        200: {
            "description": "Tenant created successfully.",
            "content": {
                "application/json": {
                    "examples": {
                        "tenant": {
                            "summary": "Created tenant",
                            "value": TENANT_RESPONSE_EXAMPLE,
                        }
                    }
                }
            },
        },
        400: TENANT_CONFLICT_RESPONSE,
        401: TENANT_UNAUTHORIZED_RESPONSE,
        403: TENANT_FORBIDDEN_RESPONSE,
    },
)
async def create_tenant(
    data: TenantCreateRequest,
    current_user: User = Depends(get_current_active_user),
    session: AsyncSession = Depends(get_db_session),
):
    """Create a tenant."""
    tenant = await TenantService.create_tenant(session, data)
    await session.commit()
    logger.info("Tenant created by admin %s: %s", current_user.username, tenant.slug)
    return TenantResponse.model_validate(tenant)


@router.get(
    "",
    response_model=TenantListResponse,
    summary="List tenants",
    description=(
        "Return all tenant records, including active and inactive entries. Pagination uses the shared "
        "`PaginationParams` contract. When pagination is disabled by setting both `page` and `page_size` to `null`, "
        "the service returns the full list."
    ),
    response_description="Paginated tenant records.",
    responses={
        200: {
            "description": "Tenant list returned successfully.",
            "content": {
                "application/json": {
                    "examples": {
                        "tenant_list": {
                            "summary": "Paginated tenant list",
                            "value": TENANT_LIST_RESPONSE_EXAMPLE,
                        }
                    }
                }
            },
        },
        401: TENANT_UNAUTHORIZED_RESPONSE,
        403: TENANT_FORBIDDEN_RESPONSE,
    },
)
async def list_tenants(
    pagination: PaginationParams = Depends(),
    session: AsyncSession = Depends(get_db_session),
):
    """List tenants."""
    tenants, total = await TenantService.get_tenants(session, pagination)
    return TenantListResponse(
        tenants=[TenantResponse.model_validate(tenant) for tenant in tenants],
        total=total,
        page=pagination.page or 1,
        page_size=pagination.page_size or 50,
    )


@router.get(
    "/{tenant_id}",
    response_model=TenantResponse,
    summary="Get a tenant",
    description=(
        "Fetch one tenant by UUID. The lookup includes both active and inactive tenants. A missing UUID returns "
        "`404 Tenant not found`."
    ),
    response_description="The tenant identified by `tenant_id`.",
    responses={
        200: {
            "description": "Tenant returned successfully.",
            "content": {
                "application/json": {
                    "examples": {
                        "tenant": {
                            "summary": "Tenant record",
                            "value": TENANT_RESPONSE_EXAMPLE,
                        }
                    }
                }
            },
        },
        401: TENANT_UNAUTHORIZED_RESPONSE,
        403: TENANT_FORBIDDEN_RESPONSE,
        404: TENANT_NOT_FOUND_RESPONSE,
    },
)
async def get_tenant(tenant_id: UUID, session: AsyncSession = Depends(get_db_session)):
    """Get tenant by id."""
    tenant = await TenantService.get_tenant(session, tenant_id)
    if not tenant:
        raise TenantNotFound()
    return TenantResponse.model_validate(tenant)


@router.put(
    "/{tenant_id}",
    response_model=TenantResponse,
    summary="Update a tenant",
    description=(
        "Update tenant `name` and/or `slug`. When `name` changes and no `slug` is sent, the service regenerates the "
        "slug from the new name. When `slug` is sent, it is normalized, validated, and checked for uniqueness before "
        "being saved. The `is_active` flag is not writable through this endpoint."
    ),
    response_description="The updated tenant.",
    responses={
        200: {
            "description": "Tenant updated successfully.",
            "content": {
                "application/json": {
                    "examples": {
                        "tenant": {
                            "summary": "Updated tenant",
                            "value": TENANT_RESPONSE_EXAMPLE,
                        }
                    }
                }
            },
        },
        400: TENANT_CONFLICT_RESPONSE,
        401: TENANT_UNAUTHORIZED_RESPONSE,
        403: TENANT_FORBIDDEN_RESPONSE,
        404: TENANT_NOT_FOUND_RESPONSE,
    },
)
async def update_tenant(
    tenant_id: UUID,
    data: TenantUpdateRequest,
    current_user: User = Depends(get_current_active_user),
    session: AsyncSession = Depends(get_db_session),
):
    """Update a tenant."""
    tenant = await TenantService.get_tenant(session, tenant_id)
    if not tenant:
        raise TenantNotFound()

    updated = await TenantService.update_tenant(session, tenant, data)
    await session.commit()
    logger.info("Tenant updated by admin %s: %s", current_user.username, tenant_id)
    return TenantResponse.model_validate(updated)


@router.delete(
    "/{tenant_id}",
    response_model=TenantMessageResponse,
    summary="Deactivate a tenant",
    description=(
        "Soft-deactivate a tenant by setting `is_active=false`. The row is not deleted and repeated calls keep the "
        "same final inactive state."
    ),
    response_description="A confirmation message.",
    responses={
        200: {
            "description": "Tenant deactivated successfully.",
            "content": {
                "application/json": {
                    "examples": {
                        "message": {
                            "summary": "Deactivation confirmation",
                            "value": TENANT_MESSAGE_RESPONSE_EXAMPLE,
                        }
                    }
                }
            },
        },
        401: TENANT_UNAUTHORIZED_RESPONSE,
        403: TENANT_FORBIDDEN_RESPONSE,
        404: TENANT_NOT_FOUND_RESPONSE,
    },
)
async def delete_tenant(
    tenant_id: UUID,
    current_user: User = Depends(get_current_active_user),
    session: AsyncSession = Depends(get_db_session),
):
    """Deactivate tenant."""
    tenant = await TenantService.get_tenant(session, tenant_id)
    if not tenant:
        raise TenantNotFound()

    await TenantService.delete_tenant(tenant)
    await session.commit()
    logger.info("Tenant deactivated by admin %s: %s", current_user.username, tenant_id)
    return TenantMessageResponse(message="Tenant deactivated successfully")


@router.post(
    "/{tenant_id}/reactivate",
    response_model=TenantMessageResponse,
    summary="Reactivate a tenant",
    description=(
        "Reactivate a previously deactivated tenant by setting `is_active=true`. "
        "The row is not modified if the tenant is already active. "
        "A missing UUID returns `404 Tenant not found`."
    ),
    response_description="A confirmation message.",
    responses={
        200: {
            "description": "Tenant reactivated successfully.",
            "content": {
                "application/json": {
                    "examples": {
                        "message": {
                            "summary": "Reactivation confirmation",
                            "value": {"message": "Tenant reactivated successfully"},
                        }
                    }
                }
            },
        },
        401: TENANT_UNAUTHORIZED_RESPONSE,
        403: TENANT_FORBIDDEN_RESPONSE,
        404: TENANT_NOT_FOUND_RESPONSE,
    },
)
async def reactivate_tenant(
    tenant_id: UUID,
    current_user: User = Depends(get_current_active_user),
    session: AsyncSession = Depends(get_db_session),
):
    """Reactivate a deactivated tenant."""
    tenant = await TenantService.get_tenant(session, tenant_id)
    if not tenant:
        raise TenantNotFound()

    await TenantService.reactivate_tenant(tenant)
    await session.commit()
    logger.info("Tenant reactivated by admin %s: %s", current_user.username, tenant_id)
    return TenantMessageResponse(message="Tenant reactivated successfully")

"""Tenant schemas (DTOs)."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field


class TenantCreateRequest(BaseModel):
    """Tenant creation request."""

    name: str = Field(..., min_length=2, max_length=255)
    slug: str | None = Field(default=None, min_length=2, max_length=120)


class TenantUpdateRequest(BaseModel):
    """Tenant update request."""

    name: str | None = Field(None, min_length=2, max_length=255)
    slug: str | None = Field(None, min_length=2, max_length=120)
    # For inactivating a tenant, use the delete route.


class TenantResponse(BaseModel):
    """Tenant response."""

    id: UUID
    name: str
    slug: str
    is_active: bool
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class TenantSummaryResponse(BaseModel):
    """Minimal tenant projection returned for user-accessible tenant listings."""

    id: UUID
    name: str
    slug: str

    model_config = {"from_attributes": True}


class TenantListResponse(BaseModel):
    """Tenant list response."""

    tenants: list[TenantResponse]
    total: int
    page: int
    page_size: int

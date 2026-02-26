"""Tenant-related dependencies for route protection."""

from uuid import UUID

from fastapi import HTTPException, Request


async def require_tenant(request: Request) -> UUID:
    """Dependency that requires X-Tenant-ID header to be present.

    This dependency should be applied at the router level using
    include_router(..., dependencies=[Depends(require_tenant)])
    for routes that require tenant context.

    Args:
        request: The incoming FastAPI request

    Returns:
        The tenant ID as a UUID

    Raises:
        HTTPException: 400 Bad Request if X-Tenant-ID is missing

    Example:
        app.include_router(
            user_router,
            prefix="/api",
            dependencies=[Depends(require_tenant)]
        )

    """
    tenant_id: str | None = getattr(request.state, "tenant_id", None)

    if not tenant_id:
        raise HTTPException(
            status_code=400,
            detail="X-Tenant-ID header is required",
        )

    # Validate that tenant_id is a valid UUID
    try:
        tenant_uuid = UUID(tenant_id)
    except ValueError, AttributeError:
        raise HTTPException(
            status_code=400,
            detail="X-Tenant-ID must be a valid UUID",
        ) from None

    return tenant_uuid

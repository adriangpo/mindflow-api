"""Multi-tenancy middleware for extracting and setting tenant context.

This middleware extracts the tenant ID from the X-Tenant-ID header
and stores it in request.state for use by the RLS-enforced database session.
It does NOT validate the presence of the header - validation is done at the
router level using the require_tenant dependency.
"""

from collections.abc import Callable

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response


class TenantMiddleware(BaseHTTPMiddleware):
    """Middleware to extract tenant ID from request headers.

    Extracts the X-Tenant-ID header from incoming requests and stores it
    in request.state for use by the RLS-enforced database session.

    This middleware does NOT enforce tenant requirements - it only extracts
    and stores the header value. Use the require_tenant dependency on routers
    that need tenant enforcement.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Extract tenant ID from header and set in request state.

        Args:
            request: The incoming request
            call_next: The next middleware or route handler

        Returns:
            The response from the next middleware or handler

        """
        tenant_id_header = request.headers.get("X-Tenant-ID")

        # Store tenant_id in request state (None if not present)
        request.state.tenant_id = tenant_id_header

        response: Response = await call_next(request)
        return response

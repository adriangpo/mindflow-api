"""Middleware to set current user in context for audit logging."""

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from .audit import clear_current_user, set_current_user


class AuditContextMiddleware(BaseHTTPMiddleware):
    """Middleware that sets the current user in context for audit logging.

    This middleware extracts the authenticated user from the request state
    (set by the authentication dependencies) and stores it in the audit context.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        """Process request and set user context."""
        # Clear any previous user context
        clear_current_user()

        try:
            # Check if user is attached to request state by auth dependencies
            if hasattr(request.state, "user"):
                set_current_user(request.state.user)

            # Process request
            response: Response = await call_next(request)

            return response
        finally:
            # Always clear context after request
            clear_current_user()

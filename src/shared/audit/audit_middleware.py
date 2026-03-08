"""Middleware to scope audit context to a single request."""

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from .audit import clear_current_user


class AuditContextMiddleware(BaseHTTPMiddleware):
    """Middleware that scopes and clears audit user context per request."""

    async def dispatch(self, request: Request, call_next) -> Response:
        """Process request and guarantee context cleanup."""
        # Clear any previous user context
        clear_current_user()

        try:
            # Process request
            response: Response = await call_next(request)

            return response
        finally:
            # Always clear context after request
            clear_current_user()

"""Middleware for protecting API documentation routes to admin users only."""

from fastapi import Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer

from src.database.client import get_session
from src.features.auth.dependencies import get_current_user
from src.features.auth.exceptions import InvalidTokenException
from src.features.user.models import UserRole


async def admin_docs_middleware(request: Request, call_next):
    """Middleware to protect API documentation routes to admin users only.

    Protects:
    - /docs (Swagger UI)
    - /redoc (ReDoc)
    - /openapi.json (OpenAPI schema)

    Non-authenticated or non-admin users receive a 403 Forbidden response.

    Args:
        request: FastAPI request object
        call_next: Next middleware/route handler

    Returns:
        Response object - either 403 for unauthorized, or the next handler's response

    """
    protected_paths = {"/docs", "/redoc", "/openapi.json"}

    if request.url.path in protected_paths:
        # Check if user is authenticated and has admin role
        security = HTTPBearer(auto_error=False)
        credentials = await security(request)

        if credentials is None:
            return JSONResponse(
                status_code=403,
                content={"detail": "Not authenticated."},
            )

        try:
            async with get_session() as session:
                user = await get_current_user(credentials, session=session)
                if UserRole.ADMIN.value not in user.roles:
                    return JSONResponse(
                        status_code=403,
                        content={"detail": "Insufficient permissions."},
                    )
        except InvalidTokenException, Exception:
            return JSONResponse(
                status_code=403,
                content={"detail": "Not authenticated."},
            )

    return await call_next(request)

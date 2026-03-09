import logging
from contextlib import asynccontextmanager
from typing import Any

from fastapi import APIRouter, Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address

from src.config.cors_config import CORSConfigurationError
from src.config.settings import settings
from src.database.client import close_db, init_db
from src.features.auth.router import router as auth_router
from src.features.patient.router import router as patient_router
from src.features.schedule.router import router as schedule_router
from src.features.schedule_config.router import router as schedule_configuration_router
from src.features.tenant.router import router as tenant_router
from src.features.user.router import router as user_router
from src.shared.audit.audit_middleware import AuditContextMiddleware
from src.shared.middlewares.docs_middleware import admin_docs_middleware
from src.shared.tenancy.dependencies import require_tenant
from src.shared.tenancy.tenant_middleware import TenantMiddleware

logger = logging.getLogger(__name__)

# Initialize rate limiter
limiter = Limiter(key_func=get_remote_address)


async def rate_limit_handler(request: Request, exc: Exception) -> JSONResponse:
    """Handle rate limit exceeded errors."""
    _ = request, exc
    return JSONResponse(
        status_code=429,
        content={"detail": "Rate limit exceeded"},
    )


@asynccontextmanager
async def lifespan(_: FastAPI):
    """Handle startup and shutdown events."""
    # Startup
    await init_db()
    yield
    # Shutdown
    await close_db()


class CustomFastAPI(FastAPI):
    def openapi(self) -> dict[str, Any]:
        """Generate and return the customized OpenAPI schema.

        This override extends FastAPI's default OpenAPI generation by
        registering a global ``TenantHeader`` security scheme and applying
        it only to routes that depend on the ``require_tenant`` dependency.

        The generated schema is cached in ``self.openapi_schema`` to avoid
        recomputation on subsequent calls.

        Returns:
            dict[str, Any]: The OpenAPI schema dictionary.

        """
        if self.openapi_schema:
            return self.openapi_schema

        openapi_schema: dict[str, Any] = get_openapi(
            title=self.title,
            version=self.version,
            description=self.description,
            routes=self.routes,
        )

        # Ensure components/securitySchemes exist
        components = openapi_schema.setdefault("components", {})
        security_schemes = components.setdefault("securitySchemes", {})

        # Register tenant header scheme
        security_schemes["TenantHeader"] = {
            "type": "apiKey",
            "in": "header",
            "name": "X-Tenant-ID",
            "description": "Tenant UUID used by tenant-protected endpoints.",
        }

        paths = openapi_schema.get("paths", {})

        # Apply security only to routes that use require_tenant dependency
        for route in self.routes:
            if not isinstance(route, APIRoute):
                continue

            has_tenant_dependency = any(
                dependency.call == require_tenant for dependency in route.dependant.dependencies
            )

            if not has_tenant_dependency:
                continue

            path_item = paths.get(route.path)
            if not path_item:
                continue

            for method in route.methods or []:
                method_lower = method.lower()
                operation = path_item.get(method_lower)

                if not operation:
                    continue

                existing_security = operation.get("security")

                if existing_security:
                    operation["security"] = [{**requirement, "TenantHeader": []} for requirement in existing_security]
                else:
                    operation["security"] = [{"TenantHeader": []}]

        self.openapi_schema = openapi_schema
        return self.openapi_schema


# Admin-only API documentation
# Routes are protected by admin_docs_middleware
app = CustomFastAPI(
    title=settings.app_name,
    version=settings.app_version,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# Add rate limiting middleware
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, rate_limit_handler)
app.add_middleware(SlowAPIMiddleware)

# Add admin-only documentation middleware
app.middleware("http")(admin_docs_middleware)

# Configure CORS middleware with environment-aware settings
try:
    cors_config = settings.get_cors_configuration()
    cors_config.log_configuration()

    middleware_config = cors_config.get_middleware_config()
    app.add_middleware(
        CORSMiddleware,
        allow_origins=middleware_config["allow_origins"],
        allow_origin_regex=middleware_config["allow_origin_regex"],
        allow_credentials=middleware_config["allow_credentials"],
        allow_methods=middleware_config["allow_methods"],
        allow_headers=middleware_config["allow_headers"],
        max_age=middleware_config["max_age"],
    )
except CORSConfigurationError as exc:
    logger.error("CORS configuration error: %s", exc)
    raise

# Add tenant middleware for multi-tenancy support
app.add_middleware(TenantMiddleware)
app.add_middleware(AuditContextMiddleware)

# Router Registration

# Public routers - accessible without X-Tenant-ID header
public_routers: list[APIRouter] = [
    auth_router,
    user_router,
    tenant_router,
]

# Tenant-protected routers - require X-Tenant-ID header
tenant_routers: list[APIRouter] = [
    schedule_configuration_router,
    schedule_router,
    patient_router,
]


# Register public routers (no tenant requirement)
for router in public_routers:
    app.include_router(router, prefix=settings.api_prefix)

# Register tenant-protected routers (require X-Tenant-ID header)
for router in tenant_routers:
    app.include_router(
        router,
        prefix=settings.api_prefix,
        dependencies=[Depends(require_tenant)],
    )


@app.get("/")
async def root():
    """Root endpoint used as a basic availability probe."""
    return {"message": "Mindflow API", "status": "running"}


@app.get("/health")
async def health():
    """Health endpoint used by monitoring and orchestration checks."""
    return {"status": "healthy"}

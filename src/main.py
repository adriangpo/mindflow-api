import logging
from contextlib import asynccontextmanager

from fastapi import APIRouter, Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address

from src.config.cors_config import CORSConfigurationError
from src.config.settings import settings
from src.database.client import close_db, init_db
from src.features.auth.router import router as auth_router
from src.features.user.router import router as user_router
from src.shared.middlewares.docs_middleware import admin_docs_middleware
from src.shared.tenancy.dependencies import require_tenant
from src.shared.tenancy.tenant_middleware import TenantMiddleware

logger = logging.getLogger(__name__)

# Initialize rate limiter
limiter = Limiter(key_func=get_remote_address)


async def rate_limit_handler(request: Request, exc: Exception) -> JSONResponse:
    """Handle rate limit exceeded errors."""
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


# Admin-only API documentation
# Routes are protected by require_role(UserRole.ADMIN) middleware
app = FastAPI(
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
    logger.error(f"CORS configuration error: {exc}")
    raise

# Add tenant middleware for multi-tenancy support
app.add_middleware(TenantMiddleware)

# Router Registration

# Public routers - accessible without X-Tenant-ID header
public_routers: list[APIRouter] = [
    auth_router,
    user_router,
]

# Tenant-protected routers - require X-Tenant-ID header
tenant_routers: list[APIRouter] = []

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
    return {"message": "Mindflow API", "status": "running"}


@app.get("/health")
async def health():
    return {"status": "healthy"}

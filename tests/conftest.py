"""Test configuration and fixtures.

Optimized test setup using transaction rollback strategy with multi-tenancy support:
1. Database schema is migrated once per test session with Alembic
2. Each test runs in a transaction that is rolled back after completion
3. Tests are isolated but fast - no database recreation
4. Uses SQLAlchemy's connection + SAVEPOINT pattern for proper isolation
5. Multi-tenancy is supported via tenant_id fixtures and RLS enforcement
"""

import asyncio
import os
import subprocess
from collections.abc import AsyncGenerator, Generator
from pathlib import Path
from uuid import UUID, uuid7

import pytest
import pytest_asyncio
from dotenv import load_dotenv
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, AsyncSession, create_async_engine
from sqlalchemy.pool import NullPool

from src.config.settings import settings
from src.database import client as db_module
from src.database.client import set_tenant_context
from src.database.dependencies import get_db_session, get_tenant_db_session
from src.features.auth.dependencies import get_current_active_user, get_current_user
from src.features.tenant.models import Tenant
from src.features.user.models import User, UserRole, UserStatus
from src.main import app

# Load test environment variables
test_env_path = Path(__file__).parent.parent / ".env.test"
load_dotenv(test_env_path, override=True)


def _resolve_test_db_url() -> str:
    """Resolve the PostgreSQL URL used by tests.

    Priority:
    1. TEST_POSTGRES_URL (explicit test URL)
    2. Component-based vars from .env.test (TEST_POSTGRES_*)
    3. Backward-compatible component vars (POSTGRES_*)
    4. Safe default matching docker-compose postgres_test service
    """
    explicit_test_url = os.getenv("TEST_POSTGRES_URL")
    if explicit_test_url:
        return explicit_test_url

    test_host = os.getenv("TEST_POSTGRES_HOST")
    test_port = os.getenv("TEST_POSTGRES_PORT")
    test_user = os.getenv("TEST_POSTGRES_USER")
    test_password = os.getenv("TEST_POSTGRES_PASSWORD")
    test_db = os.getenv("TEST_POSTGRES_DB")

    has_test_components = any([test_host, test_port, test_user, test_password, test_db])
    if has_test_components:
        return (
            "postgresql+asyncpg://"
            f"{test_user or 'mindflow_test'}:{test_password or 'mindflow_test'}@"
            f"{test_host or 'localhost'}:{test_port or '5433'}/{test_db or 'mindflow_test'}"
        )

    standard_host = os.getenv("POSTGRES_HOST")
    standard_port = os.getenv("POSTGRES_PORT")
    standard_user = os.getenv("POSTGRES_USER")
    standard_password = os.getenv("POSTGRES_PASSWORD")
    standard_db = os.getenv("POSTGRES_DB")

    has_standard_components = any([standard_host, standard_port, standard_user, standard_password, standard_db])
    if has_standard_components:
        return (
            "postgresql+asyncpg://"
            f"{standard_user or 'mindflow_test'}:{standard_password or 'mindflow_test'}@"
            f"{standard_host or 'localhost'}:{standard_port or '5433'}/{standard_db or 'mindflow_test'}"
        )

    return "postgresql+asyncpg://mindflow_test:mindflow_test@localhost:5433/mindflow_test"


# Set test environment
os.environ["TESTING"] = "true"
os.environ["POSTGRES_URL"] = _resolve_test_db_url()

PROJECT_ROOT = Path(__file__).resolve().parents[1]


# Event Loop Management


@pytest.fixture(scope="session")
def event_loop() -> Generator[asyncio.AbstractEventLoop]:
    """Create a single event loop for the entire test session."""
    # Use asyncio.new_event_loop() which uses the current policy
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    yield loop
    loop.close()


# Tenant Management


@pytest.fixture
def tenant_id() -> UUID:
    """Create a unique test tenant ID for each test.

    Each test gets its own tenant context to ensure isolation.
    This UUID is stored in request.state.tenant_id by the middleware
    and used to set the PostgreSQL app.current_tenant variable.
    """
    return uuid7()


# Database Setup - Session Scope (Created Once)


@pytest.fixture(scope="session", autouse=True)
def apply_test_migrations() -> Generator[None]:
    """Apply Alembic migrations to the test database schema.

    This keeps tests aligned with migration-defined behavior (including RLS policies).
    """
    env = os.environ.copy()

    subprocess.run(
        ["alembic", "downgrade", "base"],
        cwd=PROJECT_ROOT,
        env=env,
        check=True,
    )
    subprocess.run(
        ["alembic", "upgrade", "head"],
        cwd=PROJECT_ROOT,
        env=env,
        check=True,
    )
    yield
    subprocess.run(
        ["alembic", "downgrade", "base"],
        cwd=PROJECT_ROOT,
        env=env,
        check=True,
    )


@pytest_asyncio.fixture(scope="session")
async def db_engine(event_loop, apply_test_migrations) -> AsyncGenerator[AsyncEngine]:
    """Create database engine once for all tests.

    Schema setup is handled by Alembic in apply_test_migrations.
    Individual tests use transactions for isolation.
    """
    _ = event_loop, apply_test_migrations

    # Use test database URL
    test_db_url = os.environ["POSTGRES_URL"]

    engine = create_async_engine(
        test_db_url,
        echo=False,
        poolclass=NullPool,  # Avoid connection pool reuse across tests
    )

    yield engine

    await engine.dispose()


# Database Fixtures - Function Scope (Per Test with Rollback)


@pytest_asyncio.fixture
async def db_connection(db_engine: AsyncEngine) -> AsyncGenerator[AsyncConnection]:
    """Create a database connection and outer transaction per test.

    The outer transaction is always rolled back to keep tests isolated.
    """
    async with db_engine.connect() as connection:
        transaction = await connection.begin()
        try:
            yield connection
        finally:
            await transaction.rollback()


@pytest_asyncio.fixture
async def session(db_connection: AsyncConnection, tenant_id: UUID) -> AsyncGenerator[AsyncSession]:
    """Create a database session per test with tenant context.

    Uses SAVEPOINT mode to allow service methods to commit without breaking test isolation.
    All changes are rolled back when the outer transaction completes.

    The tenant context is set in PostgreSQL via SET LOCAL app.current_tenant,
    which is used by RLS policies to enforce tenant isolation.
    """
    async_session = AsyncSession(
        bind=db_connection,
        expire_on_commit=False,
        join_transaction_mode="create_savepoint",
    )

    try:
        # Set the tenant context for RLS policy enforcement
        await set_tenant_context(async_session, tenant_id)
        yield async_session
    finally:
        await async_session.close()


@pytest_asyncio.fixture(autouse=True)
async def ensure_test_tenant_exists(session: AsyncSession, tenant_id: UUID):
    """Ensure a tenant row exists for the test tenant_id.

    Tenant-scoped tables now use a foreign key to ``tenants.id``.
    """
    existing_tenant = await session.scalar(select(Tenant.id).where(Tenant.id == tenant_id))
    if existing_tenant is None:
        tenant = Tenant(
            id=tenant_id,
            name=f"Tenant {tenant_id.hex[:12]}",
            slug=f"tenant-{tenant_id.hex[:12]}",
            is_active=True,
        )
        session.add(tenant)
        await session.flush()
    yield


# Mock Database Initialization


@pytest.fixture(autouse=True)
def mock_db_initialization():
    """Mock init_db and close_db so lifespan doesn't interfere with tests."""
    # Store original functions
    original_init_db = db_module.init_db
    original_close_db = db_module.close_db

    # Mock the database initialization functions
    async def mock_init_db():
        pass

    async def mock_close_db():
        pass

    db_module.init_db = mock_init_db
    db_module.close_db = mock_close_db

    yield

    # Restore original functions
    db_module.init_db = original_init_db
    db_module.close_db = original_close_db


@pytest.fixture(autouse=True)
def isolated_storage_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Isolate runtime file storage per test and keep the repository clean."""
    storage_root = tmp_path / "storage"
    monkeypatch.setattr(settings, "storage_root", storage_root)
    return storage_root


# FastAPI Client & Dependency Overrides


@pytest_asyncio.fixture(autouse=True)
async def override_get_db_session(session: AsyncSession):
    """Override the database session dependency with test session.

    This ensures that FastAPI endpoints use the same transactional session
    as the test, maintaining proper isolation.
    """

    async def _get_test_session():
        yield session

    app.dependency_overrides[get_db_session] = _get_test_session
    app.dependency_overrides[get_tenant_db_session] = _get_test_session
    yield
    app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def client(tenant_id: UUID) -> AsyncGenerator[AsyncClient]:
    """Create an async HTTP test client with tenant context.

    The X-Tenant-ID header is automatically added to all requests,
    which is required by the TenantMiddleware to set the tenant context.

    This client is unauthenticated by default. Use auth_client or admin_client
    for authenticated requests.
    """
    headers = {"X-Tenant-ID": str(tenant_id)}
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers=headers,
    ) as ac:
        yield ac


# Test User Factories


@pytest_asyncio.fixture
async def make_user(session: AsyncSession, tenant_id: UUID):
    """Factory fixture to create test users with custom fields.

    All users are created with the test tenant_id, ensuring proper
    isolation in a multi-tenant environment.

    Usage:
        user = await make_user()                          # defaults
        admin = await make_user(roles=[UserRole.ADMIN])   # admin
        locked = await make_user(status=UserStatus.LOCKED)  # locked user

    The user is automatically added to the database and will be rolled back
    after the test completes.
    """
    _ = tenant_id
    counter = 0  # Counter for unique email/username generation

    async def _factory(
        email=None,
        username=None,
        full_name="Test User",
        password="TestPass123!",
        roles=None,
        status=UserStatus.ACTIVE,
        is_logged_in=False,
        permissions=None,
        tenant_ids=None,
        **kwargs,
    ) -> User:
        nonlocal counter
        counter += 1

        # Generate unique email and username if not provided
        if email is None:
            email = f"testuser{counter}@example.com"
        if username is None:
            username = f"testuser{counter}"

        hashed_password = User.hash_password(password)

        user = User(
            email=email,
            username=username,
            full_name=full_name,
            hashed_password=hashed_password,
            roles=[role.value for role in (roles or [UserRole.TENANT_OWNER])],
            status=status.value,
            is_logged_in=is_logged_in,
            permissions=permissions or [],
            tenant_ids=tenant_ids or [],
            **kwargs,
        )

        session.add(user)
        await session.flush()
        await session.refresh(user)
        return user

    yield _factory


@pytest_asyncio.fixture
async def auth_client(client: AsyncClient, make_user):
    """Authenticated client with a regular user.

    Overrides the auth dependency directly - no JWT issued, no login endpoint hit.
    Fast and reliable for testing authenticated endpoints.

    Returns:
        tuple: (client, user) - both the HTTP client and the authenticated user

    """
    user = await make_user()

    async def override_get_current_user():
        return user

    app.dependency_overrides[get_current_user] = override_get_current_user
    app.dependency_overrides[get_current_active_user] = override_get_current_user

    yield client, user

    # Cleanup is handled by autouse override_get_db_session fixture


@pytest_asyncio.fixture
async def admin_client(client: AsyncClient, make_user):
    """Authenticated client with an admin user.

    Same as auth_client but the user has ADMIN role.

    Returns:
        tuple: (client, user) - both the HTTP client and the admin user

    """
    user = await make_user(roles=[UserRole.ADMIN])

    async def override_get_current_user():
        return user

    app.dependency_overrides[get_current_user] = override_get_current_user
    app.dependency_overrides[get_current_active_user] = override_get_current_user

    yield client, user

    # Cleanup is handled by autouse override_get_db_session fixture

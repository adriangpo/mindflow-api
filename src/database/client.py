"""PostgreSQL client and connection management with SQLAlchemy."""

import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import text
from sqlalchemy.engine import URL, make_url
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from src.config.settings import settings

logger = logging.getLogger(__name__)

# Global SQLAlchemy engine
_engine: AsyncEngine | None = None
_async_session_factory: async_sessionmaker[AsyncSession] | None = None


def _normalize_query_value(value: str | tuple[str, ...] | None) -> str | None:
    """Collapse SQLAlchemy URL query values into one normalized string."""
    if value is None:
        return None
    if isinstance(value, tuple):
        if not value:
            return None
        return value[-1]
    return value


def _normalize_asyncpg_engine_configuration(database_url: str) -> tuple[URL, dict[str, Any]]:
    """Normalize one PostgreSQL URL for SQLAlchemy's asyncpg dialect.

    Neon and other providers often expose libpq-oriented query parameters such
    as ``sslmode=require`` or ``channel_binding=require`` in copied connection
    strings. SQLAlchemy's asyncpg dialect forwards unknown query parameters as
    keyword arguments to ``asyncpg.connect()``, which rejects those libpq-only
    names. This helper rewrites the supported subset into asyncpg-compatible
    connect arguments and drops unsupported ones.
    """
    url = make_url(database_url)
    normalized_query = dict(url.query)
    connect_args: dict[str, Any] = {
        "prepared_statement_name_func": lambda: f"__asyncpg_{uuid4()}__",
    }

    sslmode = _normalize_query_value(normalized_query.pop("sslmode", None))
    if sslmode is not None and "ssl" not in normalized_query:
        connect_args["ssl"] = sslmode

    sslnegotiation = _normalize_query_value(normalized_query.pop("sslnegotiation", None))
    if sslnegotiation is not None:
        if sslnegotiation.lower() == "direct":
            connect_args["direct_tls"] = True
        else:
            logger.warning("Ignoring unsupported sslnegotiation value for asyncpg: %s", sslnegotiation)

    channel_binding = _normalize_query_value(normalized_query.pop("channel_binding", None))
    if channel_binding is not None:
        logger.warning("Ignoring unsupported channel_binding value for asyncpg: %s", channel_binding)

    return url.set(query=normalized_query), connect_args


def get_engine() -> AsyncEngine:
    """Get the SQLAlchemy async engine instance."""
    global _engine
    if _engine is None:
        raise RuntimeError("Database not initialized. Call init_db() first.")
    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    """Get the SQLAlchemy async session factory."""
    global _async_session_factory
    if _async_session_factory is None:
        raise RuntimeError("Database not initialized. Call init_db() first.")
    return _async_session_factory


@asynccontextmanager
async def get_session() -> AsyncGenerator[AsyncSession]:
    """Get an async database session.

    Usage:
        async with get_session() as session:
            result = await session.execute(select(User))
            users = result.scalars().all()
    """
    session_factory = get_session_factory()
    async with session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def set_tenant_context(session: AsyncSession, tenant_id: UUID) -> None:
    """Set the current tenant context for Row-Level Security (RLS).

    This function executes a PostgreSQL SET LOCAL statement that sets the
    app.current_tenant variable to the given tenant_id. This variable is used
    by RLS policies to enforce tenant isolation at the database level.

    Args:
        session: SQLAlchemy async session
        tenant_id: UUID of the current tenant

    Note:
        SET LOCAL is transaction-scoped, meaning it only applies to the current
        transaction. When the transaction ends, the variable is reset.
        This is exactly what we want for multi-tenant isolation.

    """
    await session.execute(text(f"SET LOCAL app.current_tenant = '{tenant_id}'"))
    session.info["tenant_id"] = tenant_id
    logger.debug("Tenant context set in session: %s", tenant_id)


async def init_db() -> None:
    """Initialize PostgreSQL connection and SQLAlchemy.

    This function:
    1. Creates the async engine
    2. Creates the session factory
    3. Verifies connection
    """
    global _engine, _async_session_factory

    try:
        logger.info("Connecting to PostgreSQL at %s", settings.postgres_url.split("@")[-1])
        engine_url, connect_args = _normalize_asyncpg_engine_configuration(settings.postgres_url)

        # Create async engine
        _engine = create_async_engine(
            engine_url,
            echo=settings.postgres_echo,
            poolclass=NullPool,
            pool_pre_ping=True,
            connect_args=connect_args,
        )

        # Create session factory
        _async_session_factory = async_sessionmaker(
            _engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )

        # Verify connection
        async with _engine.begin() as conn:
            await conn.execute(text("SELECT 1"))

        logger.info("PostgreSQL connection successful")
        logger.info("Database initialization complete")

    except Exception as e:
        logger.exception("Failed to initialize database: %s", e)
        raise


async def close_db() -> None:
    """Close PostgreSQL connection gracefully."""
    global _engine, _async_session_factory

    if _engine is not None:
        logger.info("Closing PostgreSQL connection")
        await _engine.dispose()
        _engine = None
        _async_session_factory = None
        logger.info("PostgreSQL connection closed")

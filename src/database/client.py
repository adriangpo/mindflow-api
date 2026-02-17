"""PostgreSQL client and connection management with SQLAlchemy."""

import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

from src.config.settings import settings

logger = logging.getLogger(__name__)

# Global SQLAlchemy engine
_engine: AsyncEngine | None = None
_async_session_factory: async_sessionmaker[AsyncSession] | None = None


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
    logger.debug(f"Tenant context set in session: {tenant_id}")


async def init_db() -> None:
    """Initialize PostgreSQL connection and SQLAlchemy.

    This function:
    1. Creates the async engine
    2. Creates the session factory
    3. Verifies connection
    """
    global _engine, _async_session_factory

    try:
        logger.info(f"Connecting to PostgreSQL at {settings.postgres_url.split('@')[-1]}")

        # Create async engine
        _engine = create_async_engine(
            settings.postgres_url,
            echo=settings.postgres_echo,
            pool_size=settings.postgres_pool_size,
            max_overflow=settings.postgres_max_overflow,
            pool_timeout=settings.postgres_pool_timeout,
            pool_recycle=settings.postgres_pool_recycle,
            pool_pre_ping=True,  # Verify connections before using
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
        logger.error(f"Failed to initialize database: {e}")
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

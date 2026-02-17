"""SQLAlchemy base models and utilities."""

from datetime import UTC, datetime
from uuid import UUID, uuid7

from sqlalchemy import UUID as SQLALCHEMY_UUID
from sqlalchemy import DateTime, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy models."""

    pass


class TimestampMixin:
    """Mixin for adding created_at and updated_at timestamp columns."""

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
        server_default=func.now(),
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
        nullable=False,
        server_default=func.now(),
        server_onupdate=func.now(),
    )


class TenantMixin:
    """Mixin for adding tenant_id to models for multi-tenancy with RLS.

    All tenant-scoped models should inherit from this mixin in addition to Base and
    any other mixins (like TimestampMixin). PostGres Row-Level Security (RLS) policies
    will enforce that only rows belonging to the current tenant can be accessed.

    Example:
        class User(Base, TenantMixin, TimestampMixin):
            __tablename__ = "users"
            # ... other fields ...

    """

    tenant_id: Mapped[UUID] = mapped_column(
        SQLALCHEMY_UUID(as_uuid=True),
        nullable=False,
        index=True,
        default=uuid7,
    )

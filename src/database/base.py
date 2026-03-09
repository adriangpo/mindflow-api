"""SQLAlchemy base models and utilities."""

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import UUID as SQLALCHEMY_UUID
from sqlalchemy import DateTime, ForeignKey, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy models."""


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
    """Mixin for adding tenant_id to tenant-scoped models.

    The tenant reference points to ``tenants.id`` and is used together with
    PostgreSQL Row-Level Security (RLS) session context.

    Example:
        class ScheduleConfiguration(Base, TenantMixin, TimestampMixin):
            __tablename__ = "schedule_configurations"
            # ... other fields ...

    """

    tenant_id: Mapped[UUID] = mapped_column(
        SQLALCHEMY_UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

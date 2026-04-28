"""Tenant domain models."""

from uuid import UUID, uuid7

from sqlalchemy import UUID as SQLALCHEMY_UUID
from sqlalchemy import Boolean, String
from sqlalchemy.orm import Mapped, mapped_column

from src.database.base import Base, TimestampMixin
from src.shared.audit.audit import AuditableMixin


class Tenant(Base, TimestampMixin, AuditableMixin):
    """Globally-scoped tenant representing a clinic or professional workspace boundary."""

    __tablename__ = "tenants"

    id: Mapped[UUID] = mapped_column(
        SQLALCHEMY_UUID(as_uuid=True),
        primary_key=True,
        default=uuid7,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    slug: Mapped[str] = mapped_column(String(120), nullable=False, unique=True, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default="true")

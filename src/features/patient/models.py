"""Patient domain models."""

from datetime import date, datetime
from decimal import Decimal

from sqlalchemy import Boolean, Date, DateTime, Integer, Numeric, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from src.database.base import Base, TenantMixin, TimestampMixin
from src.shared.audit.audit import AuditableMixin


class Patient(Base, TenantMixin, TimestampMixin, AuditableMixin):
    """Tenant-scoped patient registry model."""

    __tablename__ = "patients"
    __table_args__ = (UniqueConstraint("tenant_id", "cpf", name="uq_patient_tenant_cpf"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    full_name: Mapped[str] = mapped_column(String(255), nullable=False)
    birth_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    cpf: Mapped[str | None] = mapped_column(String(11), nullable=True)
    cep: Mapped[str | None] = mapped_column(String(8), nullable=True)
    phone_number: Mapped[str | None] = mapped_column(String(11), nullable=True)
    session_price: Mapped[Decimal | None] = mapped_column(Numeric(10, 2), nullable=True)
    session_frequency: Mapped[str | None] = mapped_column(String(50), nullable=True)
    first_session_date: Mapped[date | None] = mapped_column(Date, nullable=True)

    guardian_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    guardian_phone: Mapped[str | None] = mapped_column(String(11), nullable=True)

    profile_photo_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    initial_record: Mapped[str | None] = mapped_column(Text, nullable=True)

    is_registered: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default="true")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default="true", index=True)
    inactivated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    retention_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

"""Schedule configuration domain models."""

from datetime import time

from sqlalchemy import ForeignKey, Integer, String, Time, UniqueConstraint
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import Mapped, mapped_column

from src.database.base import Base, TenantMixin, TimestampMixin
from src.shared.audit.audit import AuditableMixin


class ScheduleConfiguration(Base, TenantMixin, TimestampMixin, AuditableMixin):
    """Tenant-wide schedule configuration model."""

    __tablename__ = "schedule_configurations"
    __table_args__ = (UniqueConstraint("tenant_id", name="uq_schedule_configuration_tenant"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Working days (e.g. monday, tuesday...)
    working_days: Mapped[list[str]] = mapped_column(ARRAY(String), nullable=False)
    start_time: Mapped[time] = mapped_column(Time(timezone=False), nullable=False)
    end_time: Mapped[time] = mapped_column(Time(timezone=False), nullable=False)
    appointment_duration_minutes: Mapped[int] = mapped_column(Integer, nullable=False)
    break_between_appointments_minutes: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
    )

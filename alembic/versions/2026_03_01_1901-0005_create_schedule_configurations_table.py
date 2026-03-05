"""create schedule configurations table

Revision ID: 0005_schedule_config
Revises: 0004_tenants
Create Date: 2026-03-01 18:03:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0005_schedule_config"
down_revision: str | None = "0004_tenants"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Apply migration."""
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if not inspector.has_table("schedule_configurations"):
        op.create_table(
            "schedule_configurations",
            sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
            sa.Column("user_id", sa.Integer(), nullable=False),
            sa.Column("working_days", postgresql.ARRAY(sa.String()), nullable=False),
            sa.Column("start_time", sa.Time(timezone=False), nullable=False),
            sa.Column("end_time", sa.Time(timezone=False), nullable=False),
            sa.Column("appointment_duration_minutes", sa.Integer(), nullable=False),
            sa.Column("break_between_appointments_minutes", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("tenant_id", sa.UUID(), nullable=False),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.text("now()"),
            ),
            sa.Column(
                "updated_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.text("now()"),
            ),
            sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("tenant_id", "user_id", name="uq_schedule_configuration_tenant_user"),
        )

    index_names = {idx["name"] for idx in inspector.get_indexes("schedule_configurations")}
    if op.f("ix_schedule_configurations_user_id") not in index_names:
        op.create_index(op.f("ix_schedule_configurations_user_id"), "schedule_configurations", ["user_id"], unique=False)
    if op.f("ix_schedule_configurations_tenant_id") not in index_names:
        op.create_index(
            op.f("ix_schedule_configurations_tenant_id"), "schedule_configurations", ["tenant_id"], unique=False
        )


def downgrade() -> None:
    """Revert migration."""
    op.drop_index(op.f("ix_schedule_configurations_tenant_id"), table_name="schedule_configurations")
    op.drop_index(op.f("ix_schedule_configurations_user_id"), table_name="schedule_configurations")
    op.drop_table("schedule_configurations")

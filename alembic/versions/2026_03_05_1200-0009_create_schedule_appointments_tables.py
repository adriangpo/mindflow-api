"""create schedule appointments and history tables

Revision ID: 0009_schedule_appointments
Revises: 0008_schedule_config_tenant_fk
Create Date: 2026-03-05 12:00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0009_schedule_appointments"
down_revision: str | None = "0008_schedule_config_tenant_fk"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _index_names(inspector, table_name: str) -> set[str]:
    if not inspector.has_table(table_name):
        return set()
    return {index["name"] for index in inspector.get_indexes(table_name)}


def upgrade() -> None:
    """Apply migration."""
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if not inspector.has_table("schedule_appointments"):
        op.create_table(
            "schedule_appointments",
            sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
            sa.Column("patient_id", sa.Integer(), nullable=False),
            sa.Column("schedule_configuration_id", sa.Integer(), nullable=True),
            sa.Column("created_by_user_id", sa.Integer(), nullable=False),
            sa.Column("starts_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("ends_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("modality", sa.String(length=30), nullable=False),
            sa.Column("status", sa.String(length=30), nullable=False, server_default="scheduled"),
            sa.Column("payment_status", sa.String(length=30), nullable=False, server_default="pending"),
            sa.Column("notes", sa.Text(), nullable=True),
            sa.Column("price_override", sa.Numeric(precision=10, scale=2), nullable=True),
            sa.Column("allow_canceled_report", sa.Boolean(), nullable=False, server_default=sa.text("false")),
            sa.Column("out_of_schedule_warning", sa.Boolean(), nullable=False, server_default=sa.text("false")),
            sa.Column("out_of_schedule_warning_reason", sa.String(length=500), nullable=True),
            sa.Column("is_deleted", sa.Boolean(), nullable=False, server_default=sa.text("false")),
            sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("deleted_reason", sa.Text(), nullable=True),
            sa.Column("deleted_by_user_id", sa.Integer(), nullable=True),
            sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
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
            sa.CheckConstraint("starts_at < ends_at", name="ck_schedule_appointments_time_window"),
            sa.ForeignKeyConstraint(["patient_id"], ["patients.id"], ondelete="RESTRICT"),
            sa.ForeignKeyConstraint(["schedule_configuration_id"], ["schedule_configurations.id"], ondelete="SET NULL"),
            sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"], ondelete="RESTRICT"),
            sa.ForeignKeyConstraint(["deleted_by_user_id"], ["users.id"], ondelete="SET NULL"),
            sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
        )

    inspector = sa.inspect(bind)
    appointment_index_names = _index_names(inspector, "schedule_appointments")
    if op.f("ix_schedule_appointments_tenant_id") not in appointment_index_names:
        op.create_index(op.f("ix_schedule_appointments_tenant_id"), "schedule_appointments", ["tenant_id"], unique=False)
    if op.f("ix_schedule_appointments_patient_id") not in appointment_index_names:
        op.create_index(op.f("ix_schedule_appointments_patient_id"), "schedule_appointments", ["patient_id"], unique=False)
    if op.f("ix_schedule_appointments_created_by_user_id") not in appointment_index_names:
        op.create_index(
            op.f("ix_schedule_appointments_created_by_user_id"),
            "schedule_appointments",
            ["created_by_user_id"],
            unique=False,
        )
    if op.f("ix_schedule_appointments_starts_at") not in appointment_index_names:
        op.create_index(op.f("ix_schedule_appointments_starts_at"), "schedule_appointments", ["starts_at"], unique=False)
    if op.f("ix_schedule_appointments_is_deleted") not in appointment_index_names:
        op.create_index(
            op.f("ix_schedule_appointments_is_deleted"),
            "schedule_appointments",
            ["is_deleted"],
            unique=False,
        )

    if not inspector.has_table("schedule_appointment_history"):
        op.create_table(
            "schedule_appointment_history",
            sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
            sa.Column("appointment_id", sa.Integer(), nullable=False),
            sa.Column("changed_by_user_id", sa.Integer(), nullable=True),
            sa.Column("event_type", sa.String(length=40), nullable=False),
            sa.Column("reason", sa.Text(), nullable=True),
            sa.Column("from_status", sa.String(length=30), nullable=True),
            sa.Column("to_status", sa.String(length=30), nullable=True),
            sa.Column("from_payment_status", sa.String(length=30), nullable=True),
            sa.Column("to_payment_status", sa.String(length=30), nullable=True),
            sa.Column("from_starts_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("to_starts_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("change_summary", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
            sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
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
            sa.ForeignKeyConstraint(["appointment_id"], ["schedule_appointments.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["changed_by_user_id"], ["users.id"], ondelete="SET NULL"),
            sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
        )

    inspector = sa.inspect(bind)
    history_index_names = _index_names(inspector, "schedule_appointment_history")
    if op.f("ix_schedule_appointment_history_tenant_id") not in history_index_names:
        op.create_index(
            op.f("ix_schedule_appointment_history_tenant_id"),
            "schedule_appointment_history",
            ["tenant_id"],
            unique=False,
        )
    if op.f("ix_schedule_appointment_history_appointment_id") not in history_index_names:
        op.create_index(
            op.f("ix_schedule_appointment_history_appointment_id"),
            "schedule_appointment_history",
            ["appointment_id"],
            unique=False,
        )
    if op.f("ix_schedule_appointment_history_event_type") not in history_index_names:
        op.create_index(
            op.f("ix_schedule_appointment_history_event_type"),
            "schedule_appointment_history",
            ["event_type"],
            unique=False,
        )

    op.execute("ALTER TABLE schedule_appointments ENABLE ROW LEVEL SECURITY")
    op.execute("DROP POLICY IF EXISTS schedule_appointments_tenant_isolation ON schedule_appointments")
    op.execute(
        """
        CREATE POLICY schedule_appointments_tenant_isolation ON schedule_appointments
        FOR ALL
        USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
        WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
        """
    )

    op.execute("ALTER TABLE schedule_appointment_history ENABLE ROW LEVEL SECURITY")
    op.execute("DROP POLICY IF EXISTS schedule_appointment_history_tenant_isolation ON schedule_appointment_history")
    op.execute(
        """
        CREATE POLICY schedule_appointment_history_tenant_isolation ON schedule_appointment_history
        FOR ALL
        USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
        WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
        """
    )


def downgrade() -> None:
    """Revert migration."""
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if inspector.has_table("schedule_appointment_history"):
        op.execute("DROP POLICY IF EXISTS schedule_appointment_history_tenant_isolation ON schedule_appointment_history")
        history_index_names = _index_names(inspector, "schedule_appointment_history")
        if op.f("ix_schedule_appointment_history_event_type") in history_index_names:
            op.drop_index(op.f("ix_schedule_appointment_history_event_type"), table_name="schedule_appointment_history")
        if op.f("ix_schedule_appointment_history_appointment_id") in history_index_names:
            op.drop_index(
                op.f("ix_schedule_appointment_history_appointment_id"),
                table_name="schedule_appointment_history",
            )
        if op.f("ix_schedule_appointment_history_tenant_id") in history_index_names:
            op.drop_index(op.f("ix_schedule_appointment_history_tenant_id"), table_name="schedule_appointment_history")
        op.drop_table("schedule_appointment_history")

    inspector = sa.inspect(bind)
    if inspector.has_table("schedule_appointments"):
        op.execute("DROP POLICY IF EXISTS schedule_appointments_tenant_isolation ON schedule_appointments")
        appointment_index_names = _index_names(inspector, "schedule_appointments")
        if op.f("ix_schedule_appointments_is_deleted") in appointment_index_names:
            op.drop_index(op.f("ix_schedule_appointments_is_deleted"), table_name="schedule_appointments")
        if op.f("ix_schedule_appointments_starts_at") in appointment_index_names:
            op.drop_index(op.f("ix_schedule_appointments_starts_at"), table_name="schedule_appointments")
        if op.f("ix_schedule_appointments_created_by_user_id") in appointment_index_names:
            op.drop_index(op.f("ix_schedule_appointments_created_by_user_id"), table_name="schedule_appointments")
        if op.f("ix_schedule_appointments_patient_id") in appointment_index_names:
            op.drop_index(op.f("ix_schedule_appointments_patient_id"), table_name="schedule_appointments")
        if op.f("ix_schedule_appointments_tenant_id") in appointment_index_names:
            op.drop_index(op.f("ix_schedule_appointments_tenant_id"), table_name="schedule_appointments")
        op.drop_table("schedule_appointments")

"""add finance feature

Revision ID: 0011_add_finance_feature
Revises: 0010_medical_records
Create Date: 2026-03-17 12:00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0011_add_finance_feature"
down_revision: str | None = "0010_medical_records"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _index_names(inspector, table_name: str) -> set[str]:
    if not inspector.has_table(table_name):
        return set()
    return {index["name"] for index in inspector.get_indexes(table_name)}


def _column_names(inspector, table_name: str) -> set[str]:
    if not inspector.has_table(table_name):
        return set()
    return {column["name"] for column in inspector.get_columns(table_name)}


def upgrade() -> None:
    """Apply migration."""
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if not inspector.has_table("financial_entries"):
        op.create_table(
            "financial_entries",
            sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
            sa.Column("created_by_user_id", sa.Integer(), nullable=False),
            sa.Column("entry_type", sa.String(length=20), nullable=False),
            sa.Column("classification", sa.String(length=20), nullable=False),
            sa.Column("description", sa.String(length=255), nullable=False),
            sa.Column("amount", sa.Numeric(precision=10, scale=2), nullable=False),
            sa.Column("occurred_on", sa.Date(), nullable=False),
            sa.Column("notes", sa.Text(), nullable=True),
            sa.Column("is_reversed", sa.Boolean(), nullable=False, server_default=sa.text("false")),
            sa.Column("reversed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("reversed_by_user_id", sa.Integer(), nullable=True),
            sa.Column("reversal_reason", sa.Text(), nullable=True),
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
            sa.CheckConstraint("amount > 0", name="ck_financial_entries_amount_positive"),
            sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"], ondelete="RESTRICT"),
            sa.ForeignKeyConstraint(["reversed_by_user_id"], ["users.id"], ondelete="SET NULL"),
            sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
        )

    inspector = sa.inspect(bind)
    financial_entry_indexes = _index_names(inspector, "financial_entries")
    if op.f("ix_financial_entries_tenant_id") not in financial_entry_indexes:
        op.create_index(op.f("ix_financial_entries_tenant_id"), "financial_entries", ["tenant_id"], unique=False)
    if op.f("ix_financial_entries_created_by_user_id") not in financial_entry_indexes:
        op.create_index(
            op.f("ix_financial_entries_created_by_user_id"),
            "financial_entries",
            ["created_by_user_id"],
            unique=False,
        )
    if op.f("ix_financial_entries_entry_type") not in financial_entry_indexes:
        op.create_index(op.f("ix_financial_entries_entry_type"), "financial_entries", ["entry_type"], unique=False)
    if op.f("ix_financial_entries_classification") not in financial_entry_indexes:
        op.create_index(
            op.f("ix_financial_entries_classification"),
            "financial_entries",
            ["classification"],
            unique=False,
        )
    if op.f("ix_financial_entries_occurred_on") not in financial_entry_indexes:
        op.create_index(op.f("ix_financial_entries_occurred_on"), "financial_entries", ["occurred_on"], unique=False)
    if op.f("ix_financial_entries_is_reversed") not in financial_entry_indexes:
        op.create_index(
            op.f("ix_financial_entries_is_reversed"),
            "financial_entries",
            ["is_reversed"],
            unique=False,
        )

    appointment_columns = _column_names(inspector, "schedule_appointments")
    if "charge_amount" not in appointment_columns:
        op.add_column(
            "schedule_appointments",
            sa.Column(
                "charge_amount",
                sa.Numeric(precision=10, scale=2),
                nullable=False,
                server_default="0.00",
            ),
        )
    if "paid_at" not in appointment_columns:
        op.add_column("schedule_appointments", sa.Column("paid_at", sa.DateTime(timezone=True), nullable=True))

    inspector = sa.inspect(bind)
    appointment_index_names = _index_names(inspector, "schedule_appointments")
    if op.f("ix_schedule_appointments_paid_at") not in appointment_index_names:
        op.create_index(op.f("ix_schedule_appointments_paid_at"), "schedule_appointments", ["paid_at"], unique=False)

    op.execute(
        """
        UPDATE schedule_appointments AS sa
        SET charge_amount = COALESCE(sa.price_override, p.session_price, 0.00)
        FROM patients AS p
        WHERE sa.patient_id = p.id
        """
    )
    op.execute(
        """
        UPDATE schedule_appointments
        SET charge_amount = 0.00
        WHERE charge_amount IS NULL
        """
    )
    op.execute(
        """
        WITH first_paid_history AS (
            SELECT
                appointment_id,
                MIN(created_at) AS first_paid_at
            FROM schedule_appointment_history
            WHERE to_payment_status = 'paid'
            GROUP BY appointment_id
        )
        UPDATE schedule_appointments AS sa
        SET paid_at = CASE
            WHEN sa.payment_status = 'paid' THEN COALESCE(fph.first_paid_at, sa.updated_at, sa.created_at)
            ELSE NULL
        END
        FROM first_paid_history AS fph
        WHERE sa.id = fph.appointment_id
        """
    )
    op.execute(
        """
        UPDATE schedule_appointments
        SET paid_at = COALESCE(paid_at, updated_at, created_at)
        WHERE payment_status = 'paid' AND paid_at IS NULL
        """
    )

    op.execute("ALTER TABLE financial_entries ENABLE ROW LEVEL SECURITY")
    op.execute("DROP POLICY IF EXISTS financial_entries_tenant_isolation ON financial_entries")
    op.execute(
        """
        CREATE POLICY financial_entries_tenant_isolation ON financial_entries
        FOR ALL
        USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
        WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
        """
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


def downgrade() -> None:
    """Revert migration."""
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if inspector.has_table("financial_entries"):
        op.execute("DROP POLICY IF EXISTS financial_entries_tenant_isolation ON financial_entries")
        financial_entry_indexes = _index_names(inspector, "financial_entries")

        if op.f("ix_financial_entries_is_reversed") in financial_entry_indexes:
            op.drop_index(op.f("ix_financial_entries_is_reversed"), table_name="financial_entries")
        if op.f("ix_financial_entries_occurred_on") in financial_entry_indexes:
            op.drop_index(op.f("ix_financial_entries_occurred_on"), table_name="financial_entries")
        if op.f("ix_financial_entries_classification") in financial_entry_indexes:
            op.drop_index(op.f("ix_financial_entries_classification"), table_name="financial_entries")
        if op.f("ix_financial_entries_entry_type") in financial_entry_indexes:
            op.drop_index(op.f("ix_financial_entries_entry_type"), table_name="financial_entries")
        if op.f("ix_financial_entries_created_by_user_id") in financial_entry_indexes:
            op.drop_index(op.f("ix_financial_entries_created_by_user_id"), table_name="financial_entries")
        if op.f("ix_financial_entries_tenant_id") in financial_entry_indexes:
            op.drop_index(op.f("ix_financial_entries_tenant_id"), table_name="financial_entries")

        op.drop_table("financial_entries")

    inspector = sa.inspect(bind)
    if inspector.has_table("schedule_appointments"):
        appointment_index_names = _index_names(inspector, "schedule_appointments")
        appointment_columns = _column_names(inspector, "schedule_appointments")

        if op.f("ix_schedule_appointments_paid_at") in appointment_index_names:
            op.drop_index(op.f("ix_schedule_appointments_paid_at"), table_name="schedule_appointments")

        if "paid_at" in appointment_columns:
            op.drop_column("schedule_appointments", "paid_at")

        if "charge_amount" in appointment_columns:
            op.drop_column("schedule_appointments", "charge_amount")

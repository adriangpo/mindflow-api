"""create medical records table

Revision ID: 0010_medical_records
Revises: 0009_schedule_appointments
Create Date: 2026-03-08 21:00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0010_medical_records"
down_revision: str | None = "0009_schedule_appointments"
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

    if not inspector.has_table("medical_records"):
        op.create_table(
            "medical_records",
            sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
            sa.Column("patient_id", sa.Integer(), nullable=False),
            sa.Column("appointment_id", sa.Integer(), nullable=True),
            sa.Column("recorded_by_user_id", sa.Integer(), nullable=False),
            sa.Column(
                "recorded_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.text("now()"),
            ),
            sa.Column("title", sa.String(length=255), nullable=True),
            sa.Column("content", sa.Text(), nullable=False),
            sa.Column("clinical_assessment", sa.Text(), nullable=True),
            sa.Column("treatment_plan", sa.Text(), nullable=True),
            sa.Column(
                "attachments",
                postgresql.JSONB(astext_type=sa.Text()),
                nullable=False,
                server_default=sa.text("'[]'::jsonb"),
            ),
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
            sa.ForeignKeyConstraint(["patient_id"], ["patients.id"], ondelete="RESTRICT"),
            sa.ForeignKeyConstraint(["appointment_id"], ["schedule_appointments.id"], ondelete="SET NULL"),
            sa.ForeignKeyConstraint(["recorded_by_user_id"], ["users.id"], ondelete="RESTRICT"),
            sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
        )

    inspector = sa.inspect(bind)
    index_names = _index_names(inspector, "medical_records")

    if op.f("ix_medical_records_tenant_id") not in index_names:
        op.create_index(op.f("ix_medical_records_tenant_id"), "medical_records", ["tenant_id"], unique=False)

    if op.f("ix_medical_records_patient_id") not in index_names:
        op.create_index(op.f("ix_medical_records_patient_id"), "medical_records", ["patient_id"], unique=False)

    if op.f("ix_medical_records_appointment_id") not in index_names:
        op.create_index(op.f("ix_medical_records_appointment_id"), "medical_records", ["appointment_id"], unique=False)

    if op.f("ix_medical_records_recorded_by_user_id") not in index_names:
        op.create_index(
            op.f("ix_medical_records_recorded_by_user_id"),
            "medical_records",
            ["recorded_by_user_id"],
            unique=False,
        )

    if op.f("ix_medical_records_recorded_at") not in index_names:
        op.create_index(op.f("ix_medical_records_recorded_at"), "medical_records", ["recorded_at"], unique=False)

    op.execute("ALTER TABLE medical_records ENABLE ROW LEVEL SECURITY")
    op.execute("DROP POLICY IF EXISTS medical_records_tenant_isolation ON medical_records")
    op.execute(
        """
        CREATE POLICY medical_records_tenant_isolation ON medical_records
        FOR ALL
        USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
        WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
        """
    )


def downgrade() -> None:
    """Revert migration."""
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if inspector.has_table("medical_records"):
        op.execute("DROP POLICY IF EXISTS medical_records_tenant_isolation ON medical_records")

        index_names = _index_names(inspector, "medical_records")

        if op.f("ix_medical_records_recorded_at") in index_names:
            op.drop_index(op.f("ix_medical_records_recorded_at"), table_name="medical_records")

        if op.f("ix_medical_records_recorded_by_user_id") in index_names:
            op.drop_index(op.f("ix_medical_records_recorded_by_user_id"), table_name="medical_records")

        if op.f("ix_medical_records_appointment_id") in index_names:
            op.drop_index(op.f("ix_medical_records_appointment_id"), table_name="medical_records")

        if op.f("ix_medical_records_patient_id") in index_names:
            op.drop_index(op.f("ix_medical_records_patient_id"), table_name="medical_records")

        if op.f("ix_medical_records_tenant_id") in index_names:
            op.drop_index(op.f("ix_medical_records_tenant_id"), table_name="medical_records")

        op.drop_table("medical_records")

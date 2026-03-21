"""create patients table

Revision ID: 0007_patients
Revises: 0006_sched_cfg_tenant_unique
Create Date: 2026-03-04 21:00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0007_patients"
down_revision: str | None = "0006_sched_cfg_tenant_unique"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Apply migration."""
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if not inspector.has_table("patients"):
        op.create_table(
            "patients",
            sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
            sa.Column("full_name", sa.String(length=255), nullable=False),
            sa.Column("birth_date", sa.Date(), nullable=True),
            sa.Column("cpf", sa.String(length=11), nullable=True),
            sa.Column("cep", sa.String(length=8), nullable=True),
            sa.Column("phone_number", sa.String(length=11), nullable=True),
            sa.Column("session_price", sa.Numeric(precision=10, scale=2), nullable=True),
            sa.Column("session_frequency", sa.String(length=50), nullable=True),
            sa.Column("first_session_date", sa.Date(), nullable=True),
            sa.Column("guardian_name", sa.String(length=255), nullable=True),
            sa.Column("guardian_phone", sa.String(length=11), nullable=True),
            sa.Column("profile_photo_url", sa.String(length=500), nullable=True),
            sa.Column("initial_record", sa.Text(), nullable=True),
            sa.Column("is_registered", sa.Boolean(), nullable=False, server_default=sa.text("true")),
            sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
            sa.Column("inactivated_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("retention_expires_at", sa.DateTime(timezone=True), nullable=True),
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
            sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("tenant_id", "cpf", name="uq_patient_tenant_cpf"),
        )

    index_names = {idx["name"] for idx in inspector.get_indexes("patients")}
    if op.f("ix_patients_tenant_id") not in index_names:
        op.create_index(op.f("ix_patients_tenant_id"), "patients", ["tenant_id"], unique=False)
    if op.f("ix_patients_is_active") not in index_names:
        op.create_index(op.f("ix_patients_is_active"), "patients", ["is_active"], unique=False)

    op.execute("ALTER TABLE patients ENABLE ROW LEVEL SECURITY")
    op.execute("DROP POLICY IF EXISTS patients_tenant_isolation ON patients")
    op.execute(
        """
        CREATE POLICY patients_tenant_isolation ON patients
        FOR ALL
        USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
        WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
        """
    )


def downgrade() -> None:
    """Revert migration."""
    op.execute("DROP POLICY IF EXISTS patients_tenant_isolation ON patients")
    op.drop_index(op.f("ix_patients_is_active"), table_name="patients")
    op.drop_index(op.f("ix_patients_tenant_id"), table_name="patients")
    op.drop_table("patients")

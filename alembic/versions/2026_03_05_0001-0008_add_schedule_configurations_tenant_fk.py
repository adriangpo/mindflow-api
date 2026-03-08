"""add tenant fk to schedule configurations

Revision ID: 0008_schedule_config_tenant_fk
Revises: 0007_patients
Create Date: 2026-03-05 00:01:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0008_schedule_config_tenant_fk"
down_revision: str | None = "0007_patients"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

FK_NAME = "fk_schedule_configurations_tenant_id_tenants"
POLICY_NAME = "schedule_configurations_tenant_isolation"


def _tenant_fk_exists(inspector) -> bool:
    """Check whether schedule_configurations.tenant_id already references tenants.id."""
    for fk in inspector.get_foreign_keys("schedule_configurations"):
        constrained_columns = fk.get("constrained_columns") or []
        if constrained_columns != ["tenant_id"]:
            continue
        if fk.get("referred_table") == "tenants":
            return True
    return False


def _reapply_schedule_configuration_tenant_policy() -> None:
    """Ensure schedule_configurations tenant isolation policy is present and current."""
    op.execute("ALTER TABLE schedule_configurations ENABLE ROW LEVEL SECURITY")
    op.execute(f"DROP POLICY IF EXISTS {POLICY_NAME} ON schedule_configurations")
    op.execute(
        f"""
        CREATE POLICY {POLICY_NAME} ON schedule_configurations
        FOR ALL
        USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
        WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
        """
    )


def upgrade() -> None:
    """Apply migration."""
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    # Remove orphaned schedule configurations before enforcing tenant FK.
    op.execute("""
        DELETE FROM schedule_configurations sc
        WHERE NOT EXISTS (
            SELECT 1
            FROM tenants t
            WHERE t.id = sc.tenant_id
        )
        """)

    if not _tenant_fk_exists(inspector):
        op.create_foreign_key(
            FK_NAME,
            "schedule_configurations",
            "tenants",
            ["tenant_id"],
            ["id"],
            ondelete="CASCADE",
        )

    _reapply_schedule_configuration_tenant_policy()


def downgrade() -> None:
    """Revert migration."""
    op.execute(f"DROP POLICY IF EXISTS {POLICY_NAME} ON schedule_configurations")
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    fk_names = {fk["name"] for fk in inspector.get_foreign_keys("schedule_configurations")}
    if FK_NAME in fk_names:
        op.drop_constraint(FK_NAME, "schedule_configurations", type_="foreignkey")
    _reapply_schedule_configuration_tenant_policy()

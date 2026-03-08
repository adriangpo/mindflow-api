"""make schedule configuration unique per tenant

Revision ID: 0006_sched_cfg_tenant_unique
Revises: 0005_schedule_config
Create Date: 2026-03-04 20:00:00
"""

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0006_sched_cfg_tenant_unique"
down_revision: str | None = "0005_schedule_config"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

POLICY_NAME = "schedule_configurations_tenant_isolation"


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
    # Keep only one record per tenant before adding tenant-level uniqueness.
    op.execute("""
        DELETE FROM schedule_configurations sc
        USING (
            SELECT id
            FROM (
                SELECT
                    id,
                    ROW_NUMBER() OVER (
                        PARTITION BY tenant_id
                        ORDER BY updated_at DESC, id DESC
                    ) AS row_num
                FROM schedule_configurations
            ) ranked
            WHERE ranked.row_num > 1
        ) duplicates
        WHERE sc.id = duplicates.id
        """)

    op.drop_constraint(
        "uq_schedule_configuration_tenant_user",
        "schedule_configurations",
        type_="unique",
    )
    op.create_unique_constraint(
        "uq_schedule_configuration_tenant",
        "schedule_configurations",
        ["tenant_id"],
    )
    _reapply_schedule_configuration_tenant_policy()


def downgrade() -> None:
    """Revert migration."""
    op.execute(f"DROP POLICY IF EXISTS {POLICY_NAME} ON schedule_configurations")
    op.drop_constraint(
        "uq_schedule_configuration_tenant",
        "schedule_configurations",
        type_="unique",
    )
    op.create_unique_constraint(
        "uq_schedule_configuration_tenant_user",
        "schedule_configurations",
        ["tenant_id", "user_id"],
    )
    _reapply_schedule_configuration_tenant_policy()

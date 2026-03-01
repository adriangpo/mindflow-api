"""create tenants table and user tenant_ids field

Revision ID: 0004_tenants
Revises: 0003_audit
Create Date: 2026-03-01 19:00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0004_tenants"
down_revision: str | None = "0003_audit"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Apply migration."""
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if not inspector.has_table("tenants"):
        op.create_table(
            "tenants",
            sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
            sa.Column("name", sa.String(length=255), nullable=False),
            sa.Column("slug", sa.String(length=120), nullable=False),
            sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
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
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("name"),
            sa.UniqueConstraint("slug"),
        )

    index_names = {idx["name"] for idx in inspector.get_indexes("tenants")}
    if op.f("ix_tenants_slug") not in index_names:
        op.create_index(op.f("ix_tenants_slug"), "tenants", ["slug"], unique=True)

    columns = {column["name"] for column in inspector.get_columns("users")}
    if "tenant_ids" not in columns:
        op.add_column(
            "users",
            sa.Column(
                "tenant_ids",
                postgresql.ARRAY(postgresql.UUID(as_uuid=True)),
                nullable=False,
                server_default="{}",
            ),
        )


def downgrade() -> None:
    """Revert migration."""
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    columns = {column["name"] for column in inspector.get_columns("users")}
    if "tenant_ids" in columns:
        op.drop_column("users", "tenant_ids")

    if inspector.has_table("tenants"):
        index_names = {idx["name"] for idx in inspector.get_indexes("tenants")}
        if op.f("ix_tenants_slug") in index_names:
            op.drop_index(op.f("ix_tenants_slug"), table_name="tenants")
        op.drop_table("tenants")

"""create users table

Revision ID: 0001_users
Revises:
Create Date: 2026-03-01 18:00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0001_users"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Apply migration."""
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if not inspector.has_table("users"):
        op.create_table(
            "users",
            sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
            sa.Column("email", sa.String(length=255), nullable=False),
            sa.Column("username", sa.String(length=100), nullable=False),
            sa.Column("full_name", sa.String(length=255), nullable=False),
            sa.Column("hashed_password", sa.String(length=255), nullable=False),
            sa.Column(
                "roles",
                postgresql.ARRAY(sa.String()),
                nullable=False,
                server_default="{tenant_owner}",
            ),
            sa.Column(
                "permissions",
                postgresql.ARRAY(sa.String()),
                nullable=False,
                server_default="{}",
            ),
            sa.Column(
                "status",
                sa.String(length=50),
                nullable=False,
                server_default="active",
            ),
            sa.Column("is_logged_in", sa.Boolean(), nullable=False, server_default=sa.text("false")),
            sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("failed_login_attempts", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
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
            sa.UniqueConstraint("email"),
            sa.UniqueConstraint("username"),
        )

    index_names = {idx["name"] for idx in inspector.get_indexes("users")}
    if op.f("ix_users_status") not in index_names:
        op.create_index(op.f("ix_users_status"), "users", ["status"], unique=False)


def downgrade() -> None:
    """Revert migration."""
    op.drop_index(op.f("ix_users_status"), table_name="users")
    op.drop_table("users")

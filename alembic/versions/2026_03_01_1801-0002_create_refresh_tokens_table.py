"""create refresh tokens table

Revision ID: 0002_auth
Revises: 0001_users
Create Date: 2026-03-01 18:01:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0002_auth"
down_revision: str | None = "0001_users"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Apply migration."""
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if not inspector.has_table("refresh_tokens"):
        op.create_table(
            "refresh_tokens",
            sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
            sa.Column("user_id", sa.Integer(), nullable=False),
            sa.Column("token", sa.String(length=500), nullable=False),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("revoked", sa.Boolean(), nullable=False, server_default=sa.text("false")),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.text("now()"),
            ),
            sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("ip_address", sa.String(length=45), nullable=True),
            sa.Column("user_agent", sa.String(length=500), nullable=True),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("token"),
        )

    index_names = {idx["name"] for idx in inspector.get_indexes("refresh_tokens")}
    if op.f("ix_refresh_tokens_user_id") not in index_names:
        op.create_index(op.f("ix_refresh_tokens_user_id"), "refresh_tokens", ["user_id"], unique=False)
    if op.f("ix_refresh_tokens_token") not in index_names:
        op.create_index(op.f("ix_refresh_tokens_token"), "refresh_tokens", ["token"], unique=False)
    if op.f("ix_refresh_tokens_expires_at") not in index_names:
        op.create_index(op.f("ix_refresh_tokens_expires_at"), "refresh_tokens", ["expires_at"], unique=False)
    if op.f("ix_refresh_tokens_revoked") not in index_names:
        op.create_index(op.f("ix_refresh_tokens_revoked"), "refresh_tokens", ["revoked"], unique=False)


def downgrade() -> None:
    """Revert migration."""
    op.drop_index(op.f("ix_refresh_tokens_revoked"), table_name="refresh_tokens")
    op.drop_index(op.f("ix_refresh_tokens_expires_at"), table_name="refresh_tokens")
    op.drop_index(op.f("ix_refresh_tokens_token"), table_name="refresh_tokens")
    op.drop_index(op.f("ix_refresh_tokens_user_id"), table_name="refresh_tokens")
    op.drop_table("refresh_tokens")

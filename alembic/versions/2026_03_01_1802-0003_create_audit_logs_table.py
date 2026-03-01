"""create audit logs table

Revision ID: 0003_audit
Revises: 0002_auth
Create Date: 2026-03-01 18:02:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0003_audit"
down_revision: str | None = "0002_auth"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Apply migration."""
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if not inspector.has_table("audit_logs"):
        op.create_table(
            "audit_logs",
            sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
            sa.Column("entity_type", sa.String(length=100), nullable=False),
            sa.Column("document_id", sa.String(length=100), nullable=False),
            sa.Column("action", sa.String(length=50), nullable=False),
            sa.Column(
                "timestamp",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.text("now()"),
            ),
            sa.Column("user_id", sa.String(length=100), nullable=True),
            sa.Column("before", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
            sa.Column("after", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
            sa.Column("diff", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
            sa.PrimaryKeyConstraint("id"),
        )

    index_names = {idx["name"] for idx in inspector.get_indexes("audit_logs")}
    if op.f("ix_audit_logs_entity_type") not in index_names:
        op.create_index(op.f("ix_audit_logs_entity_type"), "audit_logs", ["entity_type"], unique=False)
    if op.f("ix_audit_logs_document_id") not in index_names:
        op.create_index(op.f("ix_audit_logs_document_id"), "audit_logs", ["document_id"], unique=False)
    if op.f("ix_audit_logs_action") not in index_names:
        op.create_index(op.f("ix_audit_logs_action"), "audit_logs", ["action"], unique=False)
    if op.f("ix_audit_logs_timestamp") not in index_names:
        op.create_index(op.f("ix_audit_logs_timestamp"), "audit_logs", ["timestamp"], unique=False)
    if op.f("ix_audit_logs_user_id") not in index_names:
        op.create_index(op.f("ix_audit_logs_user_id"), "audit_logs", ["user_id"], unique=False)


def downgrade() -> None:
    """Revert migration."""
    op.drop_index(op.f("ix_audit_logs_user_id"), table_name="audit_logs")
    op.drop_index(op.f("ix_audit_logs_timestamp"), table_name="audit_logs")
    op.drop_index(op.f("ix_audit_logs_action"), table_name="audit_logs")
    op.drop_index(op.f("ix_audit_logs_document_id"), table_name="audit_logs")
    op.drop_index(op.f("ix_audit_logs_entity_type"), table_name="audit_logs")
    op.drop_table("audit_logs")

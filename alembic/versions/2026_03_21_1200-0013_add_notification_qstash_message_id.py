"""add notification qstash message id

Revision ID: 0013_notification_qstash
Revises: 0012_add_notification_feature
Create Date: 2026-03-21 12:00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0013_notification_qstash"
down_revision: str | None = "0012_add_notification_feature"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Apply migration."""
    op.add_column("notification_messages", sa.Column("qstash_message_id", sa.String(length=100), nullable=True))

    op.execute("ALTER TABLE notification_messages ENABLE ROW LEVEL SECURITY")
    op.execute("DROP POLICY IF EXISTS notification_messages_tenant_isolation ON notification_messages")
    op.execute(
        """
        CREATE POLICY notification_messages_tenant_isolation ON notification_messages
        FOR ALL
        USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
        WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
        """
    )


def downgrade() -> None:
    """Revert migration."""
    op.execute("DROP POLICY IF EXISTS notification_messages_tenant_isolation ON notification_messages")
    op.execute(
        """
        CREATE POLICY notification_messages_tenant_isolation ON notification_messages
        FOR ALL
        USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
        WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
        """
    )

    op.drop_column("notification_messages", "qstash_message_id")

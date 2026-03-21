"""add notification feature

Revision ID: 0012_add_notification_feature
Revises: 0011_add_finance_feature
Create Date: 2026-03-17 13:00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0012_add_notification_feature"
down_revision: str | None = "0011_add_finance_feature"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Apply migration."""
    op.create_table(
        "notification_settings",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column(
            "patient_notifications_enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
        ),
        sa.Column(
            "user_notifications_enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
        ),
        sa.Column(
            "reminders_enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
        ),
        sa.Column("notify_on_create", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("notify_on_update", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("notify_on_cancel", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column(
            "default_reminder_minutes_before",
            sa.Integer(),
            nullable=False,
            server_default="30",
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
        sa.CheckConstraint(
            "default_reminder_minutes_before > 0",
            name="ck_notification_settings_default_reminder_positive",
        ),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", name="uq_notification_settings_tenant"),
    )
    op.create_index(op.f("ix_notification_settings_tenant_id"), "notification_settings", ["tenant_id"], unique=False)

    op.create_table(
        "notification_patient_preferences",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("patient_id", sa.Integer(), nullable=False),
        sa.Column("is_enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("contact_phone", sa.String(length=11), nullable=True),
        sa.Column("reminder_minutes_before", sa.Integer(), nullable=True),
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
        sa.CheckConstraint(
            "reminder_minutes_before IS NULL OR reminder_minutes_before > 0",
            name="ck_notification_patient_preferences_reminder_positive",
        ),
        sa.ForeignKeyConstraint(["patient_id"], ["patients.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id",
            "patient_id",
            name="uq_notification_patient_preferences_tenant_patient",
        ),
    )
    op.create_index(
        op.f("ix_notification_patient_preferences_patient_id"),
        "notification_patient_preferences",
        ["patient_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_notification_patient_preferences_tenant_id"),
        "notification_patient_preferences",
        ["tenant_id"],
        unique=False,
    )

    op.create_table(
        "notification_user_profiles",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("is_enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("contact_phone", sa.String(length=11), nullable=True),
        sa.Column(
            "receive_appointment_notifications",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
        ),
        sa.Column("receive_reminders", sa.Boolean(), nullable=False, server_default=sa.text("true")),
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
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "user_id", name="uq_notification_user_profiles_tenant_user"),
    )
    op.create_index(
        op.f("ix_notification_user_profiles_tenant_id"),
        "notification_user_profiles",
        ["tenant_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_notification_user_profiles_user_id"),
        "notification_user_profiles",
        ["user_id"],
        unique=False,
    )

    op.create_table(
        "notification_messages",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("appointment_id", sa.Integer(), nullable=True),
        sa.Column("patient_id", sa.Integer(), nullable=True),
        sa.Column("recipient_user_id", sa.Integer(), nullable=True),
        sa.Column("recipient_type", sa.String(length=20), nullable=False),
        sa.Column("event_type", sa.String(length=40), nullable=False),
        sa.Column("channel", sa.String(length=20), nullable=False, server_default="whatsapp"),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="pending"),
        sa.Column("destination", sa.String(length=11), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("scheduled_for", sa.DateTime(timezone=True), nullable=False),
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("failed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("canceled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("attempt_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("failure_reason", sa.String(length=500), nullable=True),
        sa.Column("provider_message_id", sa.String(length=100), nullable=True),
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
        sa.CheckConstraint(
            "attempt_count >= 0",
            name="ck_notification_messages_attempt_count_non_negative",
        ),
        sa.ForeignKeyConstraint(["appointment_id"], ["schedule_appointments.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["patient_id"], ["patients.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["recipient_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_notification_messages_tenant_id"), "notification_messages", ["tenant_id"], unique=False)
    op.create_index(
        op.f("ix_notification_messages_appointment_id"),
        "notification_messages",
        ["appointment_id"],
        unique=False,
    )
    op.create_index(op.f("ix_notification_messages_patient_id"), "notification_messages", ["patient_id"], unique=False)
    op.create_index(
        op.f("ix_notification_messages_recipient_user_id"),
        "notification_messages",
        ["recipient_user_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_notification_messages_recipient_type"),
        "notification_messages",
        ["recipient_type"],
        unique=False,
    )
    op.create_index(op.f("ix_notification_messages_event_type"), "notification_messages", ["event_type"], unique=False)
    op.create_index(op.f("ix_notification_messages_status"), "notification_messages", ["status"], unique=False)
    op.create_index(
        op.f("ix_notification_messages_scheduled_for"),
        "notification_messages",
        ["scheduled_for"],
        unique=False,
    )
    op.create_index(op.f("ix_notification_messages_sent_at"), "notification_messages", ["sent_at"], unique=False)

    for table_name, policy_name in (
        ("notification_settings", "notification_settings_tenant_isolation"),
        ("notification_patient_preferences", "notification_patient_preferences_tenant_isolation"),
        ("notification_user_profiles", "notification_user_profiles_tenant_isolation"),
        ("notification_messages", "notification_messages_tenant_isolation"),
    ):
        op.execute(f"ALTER TABLE {table_name} ENABLE ROW LEVEL SECURITY")
        op.execute(f"DROP POLICY IF EXISTS {policy_name} ON {table_name}")
        op.execute(
            f"""
            CREATE POLICY {policy_name} ON {table_name}
            FOR ALL
            USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
            WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
            """
        )


def downgrade() -> None:
    """Revert migration."""
    for table_name, policy_name in (
        ("notification_messages", "notification_messages_tenant_isolation"),
        ("notification_user_profiles", "notification_user_profiles_tenant_isolation"),
        ("notification_patient_preferences", "notification_patient_preferences_tenant_isolation"),
        ("notification_settings", "notification_settings_tenant_isolation"),
    ):
        op.execute(f"DROP POLICY IF EXISTS {policy_name} ON {table_name}")

    op.drop_index(op.f("ix_notification_messages_sent_at"), table_name="notification_messages")
    op.drop_index(op.f("ix_notification_messages_scheduled_for"), table_name="notification_messages")
    op.drop_index(op.f("ix_notification_messages_status"), table_name="notification_messages")
    op.drop_index(op.f("ix_notification_messages_event_type"), table_name="notification_messages")
    op.drop_index(op.f("ix_notification_messages_recipient_type"), table_name="notification_messages")
    op.drop_index(op.f("ix_notification_messages_recipient_user_id"), table_name="notification_messages")
    op.drop_index(op.f("ix_notification_messages_patient_id"), table_name="notification_messages")
    op.drop_index(op.f("ix_notification_messages_appointment_id"), table_name="notification_messages")
    op.drop_index(op.f("ix_notification_messages_tenant_id"), table_name="notification_messages")
    op.drop_table("notification_messages")

    op.drop_index(op.f("ix_notification_user_profiles_user_id"), table_name="notification_user_profiles")
    op.drop_index(op.f("ix_notification_user_profiles_tenant_id"), table_name="notification_user_profiles")
    op.drop_table("notification_user_profiles")

    op.drop_index(
        op.f("ix_notification_patient_preferences_tenant_id"),
        table_name="notification_patient_preferences",
    )
    op.drop_index(
        op.f("ix_notification_patient_preferences_patient_id"),
        table_name="notification_patient_preferences",
    )
    op.drop_table("notification_patient_preferences")

    op.drop_index(op.f("ix_notification_settings_tenant_id"), table_name="notification_settings")
    op.drop_table("notification_settings")

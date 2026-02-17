"""Tests for the audit logging system.
Tests AuditLog model and audit helper functions.
"""

from datetime import UTC, datetime

import pytest

from src.shared.audit.audit import (
    AuditAction,
    AuditLog,
    clear_current_user,
    compute_diff,
    create_audit_log,
    get_current_user,
    serialize_model,
    set_current_user,
)


class TestComputeDiff:
    """Tests for the compute_diff helper function."""

    def test_diff_with_changed_fields(self):
        """Test diff computation with changed fields."""
        before = {"name": "Old Name", "value": 100, "status": "active"}
        after = {"name": "New Name", "value": 100, "status": "inactive"}

        diff = compute_diff(before, after)

        assert diff is not None
        assert "name" in diff
        assert diff["name"]["from"] == "Old Name"
        assert diff["name"]["to"] == "New Name"
        assert "status" in diff
        assert diff["status"]["from"] == "active"
        assert diff["status"]["to"] == "inactive"

    def test_diff_with_no_changes(self):
        """Test diff computation with no changes."""
        before = {"name": "Name", "value": 100}
        after = {"name": "Name", "value": 100}

        diff = compute_diff(before, after)

        assert diff is None

    def test_diff_with_added_fields(self):
        """Test diff computation with new fields added."""
        before = {"name": "Name"}
        after = {"name": "Name", "value": 100}

        diff = compute_diff(before, after)

        assert diff is not None
        assert "value" in diff
        assert diff["value"]["from"] is None
        assert diff["value"]["to"] == 100

    def test_diff_with_removed_fields(self):
        """Test diff computation with fields removed."""
        before = {"name": "Name", "value": 100}
        after = {"name": "Name"}

        diff = compute_diff(before, after)

        assert diff is not None
        assert "value" in diff
        assert diff["value"]["from"] == 100
        assert diff["value"]["to"] is None

    def test_diff_with_datetime_fields(self):
        """Test diff computation with datetime fields."""
        dt1 = datetime(2024, 1, 1, tzinfo=UTC)
        dt2 = datetime(2024, 1, 2, tzinfo=UTC)

        before = {"created_at": dt1}
        after = {"created_at": dt2}

        diff = compute_diff(before, after)

        assert diff is not None
        assert "created_at" in diff
        # Datetimes are converted to ISO format
        assert isinstance(diff["created_at"]["from"], str)
        assert isinstance(diff["created_at"]["to"], str)


class TestSerializeModel:
    """Tests for the serialize_model helper function."""

    def test_serialize_none(self):
        """Test serializing None returns None."""
        result = serialize_model(None)
        assert result is None

    @pytest.mark.asyncio
    async def test_serialize_user_model(self, make_user):
        """Test serializing a User model."""
        user = await make_user(username="testuser", email="test@example.com")

        serialized = serialize_model(user)

        assert serialized is not None
        assert serialized["username"] == "testuser"
        assert serialized["email"] == "test@example.com"
        assert "id" in serialized
        assert "hashed_password" in serialized


class TestUserContext:
    """Tests for user context management."""

    def test_set_and_get_current_user(self):
        """Test setting and getting current user."""
        # Initially should be None
        assert get_current_user() is None

        # Create a mock user object
        class MockUser:
            def __init__(self):
                self.id = 123
                self.username = "testuser"

        user = MockUser()
        set_current_user(user)

        # Should now return the user
        retrieved_user = get_current_user()
        assert retrieved_user is not None
        assert retrieved_user.id == 123
        assert retrieved_user.username == "testuser"

    def test_clear_current_user(self):
        """Test clearing current user."""

        # Set a user
        class MockUser:
            def __init__(self):
                self.id = 456

        user = MockUser()
        set_current_user(user)
        assert get_current_user() is not None

        # Clear it
        clear_current_user()
        assert get_current_user() is None


class TestCreateAuditLog:
    """Tests for the create_audit_log function."""

    @pytest.mark.asyncio
    async def test_create_audit_log_insert(self, session):
        """Test creating an audit log for insert action."""
        after_state = {"id": 1, "name": "Test Item", "value": 100}

        await create_audit_log(
            session=session,
            entity_type="test_items",
            document_id="1",
            action=AuditAction.INSERT,
            before=None,
            after=after_state,
        )

        await session.commit()

        # Verify audit log was created
        from sqlalchemy import select

        stmt = select(AuditLog).where(AuditLog.entity_type == "test_items")
        result = await session.execute(stmt)
        audit_log = result.scalar_one_or_none()

        assert audit_log is not None
        assert audit_log.action == AuditAction.INSERT.value
        assert audit_log.document_id == "1"
        assert audit_log.before is None
        assert audit_log.after == after_state
        assert audit_log.diff is None

    @pytest.mark.asyncio
    async def test_create_audit_log_update_with_diff(self, session):
        """Test creating an audit log for update action with diff."""
        before_state = {"id": 1, "name": "Old Name", "value": 100}
        after_state = {"id": 1, "name": "New Name", "value": 100}

        await create_audit_log(
            session=session,
            entity_type="test_items",
            document_id="1",
            action=AuditAction.UPDATE,
            before=before_state,
            after=after_state,
        )

        await session.commit()

        # Verify audit log was created with diff
        from sqlalchemy import select

        stmt = select(AuditLog).where(AuditLog.entity_type == "test_items")
        result = await session.execute(stmt)
        audit_log = result.scalar_one_or_none()

        assert audit_log is not None
        assert audit_log.action == AuditAction.UPDATE.value
        assert audit_log.before == before_state
        assert audit_log.after == after_state
        assert audit_log.diff is not None
        assert "name" in audit_log.diff

    @pytest.mark.asyncio
    async def test_create_audit_log_with_user_context(self, session, make_user):
        """Test creating an audit log with user context."""
        user = await make_user()
        set_current_user(user)

        try:
            after_state = {"id": 1, "name": "Test"}

            await create_audit_log(
                session=session,
                entity_type="test_items",
                document_id="1",
                action=AuditAction.INSERT,
                before=None,
                after=after_state,
            )

            await session.commit()

            # Verify audit log has user_id
            from sqlalchemy import select

            stmt = select(AuditLog).where(AuditLog.entity_type == "test_items")
            result = await session.execute(stmt)
            audit_log = result.scalar_one_or_none()

            assert audit_log is not None
            assert audit_log.user_id == str(user.id)
        finally:
            clear_current_user()

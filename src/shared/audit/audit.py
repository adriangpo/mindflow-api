"""Automatic audit logging mechanism for SQLAlchemy models."""

import logging
from contextvars import ContextVar
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import DateTime, Enum, Integer, String, event, inspect
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapped, mapped_column

from src.database.base import Base

logger = logging.getLogger(__name__)

# ContextVar for tracking the current authenticated user
current_user_ctx: ContextVar = ContextVar("current_user", default=None)


class AuditAction(StrEnum):
    """Audit action types."""

    INSERT = "insert"
    UPDATE = "update"
    DELETE = "delete"


class AuditLog(Base):
    """Audit log entry for tracking all database operations.

    All audit logs are stored in a single PostgreSQL table.
    """

    __tablename__ = "audit_logs"

    # Primary key
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # Entity information
    entity_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    document_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)

    # Action details
    action: Mapped[str] = mapped_column(
        Enum(AuditAction, native_enum=False, length=50),
        nullable=False,
        index=True,
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
        index=True,
    )

    # User tracking
    user_id: Mapped[str | None] = mapped_column(String(100), nullable=True, index=True)

    # State tracking (JSONB for efficient querying)
    before: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    after: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    diff: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)


def compute_diff(before: dict[str, Any], after: dict[str, Any]) -> dict[str, dict[str, Any]] | None:
    """Compute field-level differences between two document states.

    Args:
        before: Previous document state
        after: New document state

    Returns:
        Dictionary of changed fields with 'from' and 'to' values

    """
    diff = {}

    # Get all unique keys from both documents
    all_keys = set(before.keys()) | set(after.keys())

    for key in all_keys:
        before_value = before.get(key)
        after_value = after.get(key)

        # Compare values
        if before_value != after_value:
            # Special handling for datetime
            if isinstance(before_value, datetime):
                before_value = before_value.isoformat()
            if isinstance(after_value, datetime):
                after_value = after_value.isoformat()

            diff[key] = {"from": before_value, "to": after_value}

    return diff if diff else None


def serialize_model(instance: Any) -> dict[str, Any] | None:
    """Serialize a SQLAlchemy model to a dictionary for audit logging.

    Args:
        instance: SQLAlchemy model instance to serialize

    Returns:
        Serialized model as dictionary or None

    """
    if instance is None:
        return None

    # Use SQLAlchemy inspection to get all columns
    mapper = inspect(instance.__class__)
    data = {}

    for column in mapper.columns:
        value = getattr(instance, column.name)
        # Convert datetime to ISO format for JSON serialization
        if isinstance(value, datetime):
            data[column.name] = value.isoformat()
        else:
            data[column.name] = value

    return data


async def create_audit_log(
    session: AsyncSession,
    entity_type: str,
    document_id: str,
    action: AuditAction,
    before: dict[str, Any] | None = None,
    after: dict[str, Any] | None = None,
) -> None:
    """Create an audit log entry.

    Args:
        session: Database session
        entity_type: Table name of the model
        document_id: ID of the affected record
        action: Type of operation
        before: Record state before operation
        after: Record state after operation

    """
    # Get current user from context
    user = current_user_ctx.get()
    user_id = str(user.id) if user and hasattr(user, "id") else None

    # Compute diff for updates
    diff = None
    if action == AuditAction.UPDATE and before and after:
        diff = compute_diff(before, after)

    # Create audit log entry
    audit_entry = AuditLog(
        entity_type=entity_type,
        document_id=document_id,
        action=action.value,
        user_id=user_id,
        before=before,
        after=after,
        diff=diff,
    )

    # Insert asynchronously
    try:
        session.add(audit_entry)
        # Note: The session will be committed by the calling code
    except Exception as e:
        logger.error(f"Failed to create audit log: {e}", exc_info=True)


# SQLAlchemy event listeners for automatic audit logging
def setup_audit_listeners(model_class: type[Base]) -> None:
    """Set up automatic audit logging for a SQLAlchemy model.

    Args:
        model_class: SQLAlchemy model class to enable audit logging for

    Example:
        setup_audit_listeners(User)
        setup_audit_listeners(RefreshToken)

    """

    @event.listens_for(model_class, "after_insert")
    def receive_after_insert(mapper, connection, target):
        """Event listener for after insert."""
        # This runs in sync context, we'll handle audit in the service layer
        pass

    @event.listens_for(model_class, "after_update")
    def receive_after_update(mapper, connection, target):
        """Event listener for after update."""
        # This runs in sync context, we'll handle audit in the service layer
        pass

    @event.listens_for(model_class, "after_delete")
    def receive_after_delete(mapper, connection, target):
        """Event listener for after delete."""
        # This runs in sync context, we'll handle audit in the service layer
        pass


# Helper functions to set current user in context
def set_current_user(user: Any) -> None:
    """Set the current user in the context for audit logging.

    This should be called in middleware or dependencies to track
    which user is performing operations.

    Args:
        user: The authenticated user object

    """
    current_user_ctx.set(user)


def get_current_user() -> Any:
    """Get the current user from context.

    Returns:
        The current user or None

    """
    return current_user_ctx.get()


def clear_current_user() -> None:
    """Clear the current user from context."""
    current_user_ctx.set(None)

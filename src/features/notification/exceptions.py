"""Notification feature exceptions."""

from fastapi import HTTPException, status


class NotificationException(HTTPException):
    """Base notification exception."""

    def __init__(
        self,
        detail: str = "Notification operation failed",
        status_code: int = status.HTTP_400_BAD_REQUEST,
    ):
        super().__init__(status_code=status_code, detail=detail)


class NotificationPatientNotFound(NotificationException):
    """Raised when patient does not exist in tenant scope."""

    def __init__(self):
        super().__init__(detail="Patient not found for notifications", status_code=status.HTTP_404_NOT_FOUND)


class NotificationUserNotFound(NotificationException):
    """Raised when user does not exist."""

    def __init__(self):
        super().__init__(detail="User not found for notifications", status_code=status.HTTP_404_NOT_FOUND)


class NotificationUserNotAssignedToTenant(NotificationException):
    """Raised when the target user is not assigned to the current tenant."""

    def __init__(self):
        super().__init__(
            detail="User is not assigned to the current tenant",
            status_code=status.HTTP_409_CONFLICT,
        )

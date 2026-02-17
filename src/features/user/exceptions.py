"""User-related exceptions."""

from fastapi import HTTPException, status


class UserException(HTTPException):
    """Base user exception."""

    def __init__(self, detail: str = "User operation failed", status_code: int = status.HTTP_400_BAD_REQUEST):
        super().__init__(status_code=status_code, detail=detail)


class UserNotFound(UserException):
    """Raised when user is not found."""

    def __init__(self):
        super().__init__(detail="User not found", status_code=status.HTTP_404_NOT_FOUND)


class UserAlreadyExists(UserException):
    """Raised when trying to create a user that already exists."""

    def __init__(self, field: str = "user"):
        super().__init__(detail=f"{field.capitalize()} already registered")


class UsernameAlreadyExists(UserAlreadyExists):
    """Raised when username already exists."""

    def __init__(self):
        super().__init__(field="username")


class EmailAlreadyExists(UserAlreadyExists):
    """Raised when email already exists."""

    def __init__(self):
        super().__init__(field="email")


class IncorrectPassword(UserException):
    """Raised when password is incorrect."""

    def __init__(self):
        super().__init__(detail="Current password is incorrect")


class CannotDeleteOwnAccount(UserException):
    """Raised when trying to delete own account."""

    def __init__(self):
        super().__init__(detail="Cannot delete your own account")


class CannotModifyOtherUser(UserException):
    """Raised when user tries to modify another user without permission."""

    def __init__(self):
        super().__init__(
            detail="You do not have permission to modify other users", status_code=status.HTTP_403_FORBIDDEN
        )


class CannotModifyField(UserException):
    """Raised when trying to modify a field that cannot be edited."""

    def __init__(self, field: str):
        super().__init__(
            detail=f"You do not have permission to modify '{field}' field", status_code=status.HTTP_403_FORBIDDEN
        )


class InsufficientPrivileges(UserException):
    """Raised when user lacks required privileges."""

    def __init__(self, detail: str = "Insufficient privileges for this operation"):
        super().__init__(detail=detail, status_code=status.HTTP_403_FORBIDDEN)

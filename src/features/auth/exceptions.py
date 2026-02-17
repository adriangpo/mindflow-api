"""Authentication exceptions."""

from fastapi import HTTPException, status


class AuthenticationException(HTTPException):
    """Base authentication exception."""

    def __init__(self, detail: str = "Authentication failed"):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=detail,
            headers={"WWW-Authenticate": "Bearer"},
        )


class InvalidCredentialsException(AuthenticationException):
    """Raised when username or password is incorrect."""

    def __init__(self):
        super().__init__(detail="Incorrect username or password")


class InvalidTokenException(AuthenticationException):
    """Raised when JWT token is invalid or expired."""

    def __init__(self, detail: str = "Invalid or expired token"):
        super().__init__(detail=detail)


class TokenExpiredException(InvalidTokenException):
    """Raised when JWT token has expired."""

    def __init__(self):
        super().__init__(detail="Token has expired")


class InvalidTokenTypeException(InvalidTokenException):
    """Raised when token type is invalid."""

    def __init__(self, expected: str = "access"):
        super().__init__(detail=f"Invalid token type, expected {expected}")


class RefreshTokenNotFoundException(InvalidTokenException):
    """Raised when refresh token is not found or revoked."""

    def __init__(self):
        super().__init__(detail="Refresh token not found or revoked")


class RefreshTokenExpiredException(InvalidTokenException):
    """Raised when refresh token has expired."""

    def __init__(self):
        super().__init__(detail="Refresh token expired")


class InvalidTokenPayloadException(InvalidTokenException):
    """Raised when token payload is invalid."""

    def __init__(self):
        super().__init__(detail="Invalid token payload")


class UserInactiveException(HTTPException):
    """Raised when user account is inactive."""

    def __init__(self):
        super().__init__(status_code=status.HTTP_403_FORBIDDEN, detail="User account is inactive")


class UserLockedException(HTTPException):
    """Raised when user account is locked."""

    def __init__(self):
        super().__init__(status_code=status.HTTP_403_FORBIDDEN, detail="User account is locked")


class InsufficientPermissionsException(HTTPException):
    """Raised when user lacks required role or permission."""

    def __init__(self, detail: str = "Insufficient permissions"):
        super().__init__(status_code=status.HTTP_403_FORBIDDEN, detail=detail)


class InsufficientRoleException(InsufficientPermissionsException):
    """Raised when user lacks required role."""

    def __init__(self, required_roles: list[str]):
        roles_str = ", ".join(required_roles)
        super().__init__(detail=f"User does not have required role(s): {roles_str}")


class InsufficientPermissionException(InsufficientPermissionsException):
    """Raised when user lacks required permission."""

    def __init__(self, required_permissions: list[str]):
        perms_str = ", ".join(required_permissions)
        super().__init__(detail=f"User does not have required permission(s): {perms_str}")

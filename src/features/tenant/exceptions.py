"""Tenant-related exceptions."""

from fastapi import HTTPException, status


class TenantException(HTTPException):
    """Base tenant exception."""

    def __init__(self, detail: str = "Tenant operation failed", status_code: int = status.HTTP_400_BAD_REQUEST):
        super().__init__(status_code=status_code, detail=detail)


class TenantNotFound(TenantException):
    """Raised when tenant is not found."""

    def __init__(self):
        super().__init__(detail="Tenant not found", status_code=status.HTTP_404_NOT_FOUND)


class TenantNameAlreadyExists(TenantException):
    """Raised when tenant name already exists."""

    def __init__(self):
        super().__init__(detail="Tenant name already exists")


class TenantSlugAlreadyExists(TenantException):
    """Raised when tenant slug already exists."""

    def __init__(self):
        super().__init__(detail="Tenant slug already exists")


class TenantInvalidSlug(TenantException):
    """Raised when tenant slug format is invalid."""

    def __init__(self):
        super().__init__(detail="Tenant slug is invalid")

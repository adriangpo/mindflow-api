"""Patient-related exceptions."""

from fastapi import HTTPException, status


class PatientException(HTTPException):
    """Base patient exception."""

    def __init__(
        self,
        detail: str = "Patient operation failed",
        status_code: int = status.HTTP_400_BAD_REQUEST,
    ):
        super().__init__(status_code=status_code, detail=detail)


class PatientNotFound(PatientException):
    """Raised when patient is not found."""

    def __init__(self):
        super().__init__(detail="Patient not found", status_code=status.HTTP_404_NOT_FOUND)


class PatientCpfAlreadyExists(PatientException):
    """Raised when patient CPF already exists in tenant."""

    def __init__(self):
        super().__init__(detail="Patient CPF already registered in this tenant", status_code=status.HTTP_409_CONFLICT)


class PatientAlreadyInactive(PatientException):
    """Raised when patient is already inactive."""

    def __init__(self):
        super().__init__(detail="Patient is already inactive", status_code=status.HTTP_409_CONFLICT)


class PatientAlreadyActive(PatientException):
    """Raised when patient is already active."""

    def __init__(self):
        super().__init__(detail="Patient is already active", status_code=status.HTTP_409_CONFLICT)


class PatientAlreadyRegistered(PatientException):
    """Raised when trying to complete registration for an already registered patient."""

    def __init__(self):
        super().__init__(detail="Patient is already fully registered", status_code=status.HTTP_409_CONFLICT)

"""Medical record feature exceptions."""

from fastapi import HTTPException, status


class MedicalRecordException(HTTPException):
    """Base medical record exception."""

    def __init__(
        self,
        detail: str = "Medical record operation failed",
        status_code: int = status.HTTP_400_BAD_REQUEST,
    ):
        super().__init__(status_code=status_code, detail=detail)


class MedicalRecordNotFound(MedicalRecordException):
    """Raised when medical record does not exist in tenant scope."""

    def __init__(self):
        super().__init__(detail="Medical record not found", status_code=status.HTTP_404_NOT_FOUND)


class MedicalRecordPatientNotFound(MedicalRecordException):
    """Raised when referenced patient does not exist in tenant scope."""

    def __init__(self):
        super().__init__(detail="Patient not found for medical record", status_code=status.HTTP_404_NOT_FOUND)


class MedicalRecordAppointmentNotFound(MedicalRecordException):
    """Raised when referenced appointment does not exist in tenant scope."""

    def __init__(self):
        super().__init__(detail="Appointment not found for medical record", status_code=status.HTTP_404_NOT_FOUND)


class MedicalRecordAppointmentPatientMismatch(MedicalRecordException):
    """Raised when appointment and patient do not belong to the same consultation."""

    def __init__(self):
        super().__init__(
            detail="Appointment does not belong to the informed patient",
            status_code=status.HTTP_409_CONFLICT,
        )


class MedicalRecordExportEmpty(MedicalRecordException):
    """Raised when an export operation has no records to generate."""

    def __init__(self):
        super().__init__(detail="No medical records available for export", status_code=status.HTTP_404_NOT_FOUND)

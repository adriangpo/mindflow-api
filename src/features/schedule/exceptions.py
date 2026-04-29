"""Schedule feature exceptions."""

from fastapi import HTTPException, status


class ScheduleException(HTTPException):
    """Base schedule exception."""

    def __init__(
        self,
        detail: str = "Schedule operation failed",
        status_code: int = status.HTTP_400_BAD_REQUEST,
    ):
        super().__init__(status_code=status_code, detail=detail)


class ScheduleAppointmentNotFound(ScheduleException):
    """Raised when appointment does not exist in tenant."""

    def __init__(self):
        super().__init__(detail="Appointment not found", status_code=status.HTTP_404_NOT_FOUND)


class SchedulePatientNotFound(ScheduleException):
    """Raised when target patient does not exist in tenant."""

    def __init__(self):
        super().__init__(detail="Patient not found for scheduling", status_code=status.HTTP_404_NOT_FOUND)


class SchedulePatientInactive(ScheduleException):
    """Raised when trying to schedule for an inactive patient."""

    def __init__(self):
        super().__init__(
            detail="Cannot schedule appointment for inactive patient", status_code=status.HTTP_409_CONFLICT
        )


class ScheduleConfigurationRequired(ScheduleException):
    """Raised when tenant has no schedule configuration."""

    def __init__(self):
        super().__init__(
            detail="Schedule configuration is required before scheduling appointments",
            status_code=status.HTTP_409_CONFLICT,
        )


class ScheduleInvalidTimeWindow(ScheduleException):
    """Raised when appointment time range is invalid."""

    def __init__(self):
        super().__init__(
            detail="Appointment end datetime must be after start datetime",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class ScheduleSlotUnavailable(ScheduleException):
    """Raised when requested slot is already occupied."""

    def __init__(self):
        super().__init__(detail="Selected time slot is not available", status_code=status.HTTP_409_CONFLICT)


class ScheduleInvalidStatusTransition(ScheduleException):
    """Raised when requested status transition is not allowed."""

    def __init__(self, from_status: str, to_status: str):
        super().__init__(
            detail=f"Cannot change appointment status from '{from_status}' to '{to_status}'",
            status_code=status.HTTP_409_CONFLICT,
        )


class ScheduleDeleteConfirmationRequired(ScheduleException):
    """Raised when delete request is missing explicit confirmation."""

    def __init__(self):
        super().__init__(
            detail="Appointment deletion requires explicit confirmation",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class ScheduleAppointmentAlreadyDeleted(ScheduleException):
    """Raised when deleting an appointment that is already deleted."""

    def __init__(self):
        super().__init__(detail="Appointment is already deleted", status_code=status.HTTP_409_CONFLICT)


class ScheduleCustomRangeRequired(ScheduleException):
    """Raised when custom view range is incomplete."""

    def __init__(self):
        super().__init__(
            detail="custom view requires both start_date and end_date",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class ScheduleInvalidCustomRange(ScheduleException):
    """Raised when custom range has invalid boundaries."""

    def __init__(self):
        super().__init__(
            detail="end_date must be greater than or equal to start_date",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

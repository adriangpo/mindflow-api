"""Schedule configuration exceptions."""

from fastapi import HTTPException, status


class ScheduleConfigurationException(HTTPException):
    """Base schedule configuration exception."""

    def __init__(
        self,
        detail: str = "Schedule configuration operation failed",
        status_code: int = status.HTTP_400_BAD_REQUEST,
    ):
        super().__init__(status_code=status_code, detail=detail)


class ScheduleConfigurationNotFound(ScheduleConfigurationException):
    """Raised when schedule configuration is not found."""

    def __init__(self):
        super().__init__(detail="Schedule configuration not found", status_code=status.HTTP_404_NOT_FOUND)


class ScheduleConfigurationAlreadyExists(ScheduleConfigurationException):
    """Raised when user already has a schedule configuration."""

    def __init__(self):
        super().__init__(
            detail="Schedule configuration already exists for this user",
            status_code=status.HTTP_409_CONFLICT,
        )


class ScheduleConfigurationForbidden(ScheduleConfigurationException):
    """Raised when user has no permission to manage a schedule configuration."""

    def __init__(self):
        super().__init__(detail="You do not have permission for this schedule configuration", status_code=403)

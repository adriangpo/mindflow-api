"""Schedule configuration schemas (DTOs)."""

from datetime import datetime, time
from enum import StrEnum

from pydantic import BaseModel, Field, model_validator


class WeekDay(StrEnum):
    """Week day enum for schedule configuration."""

    MONDAY = "monday"
    TUESDAY = "tuesday"
    WEDNESDAY = "wednesday"
    THURSDAY = "thursday"
    FRIDAY = "friday"
    SATURDAY = "saturday"
    SUNDAY = "sunday"


class ScheduleConfigurationCreateRequest(BaseModel):
    """Schedule configuration creation request."""

    working_days: list[WeekDay] = Field(..., min_length=1)
    start_time: time
    end_time: time
    appointment_duration_minutes: int = Field(..., gt=0)
    break_between_appointments_minutes: int = Field(..., ge=0)

    @model_validator(mode="after")
    def _validate_time_window(self):
        if self.start_time >= self.end_time:
            raise ValueError("start_time must be earlier than end_time")
        return self


class ScheduleConfigurationUpdateRequest(BaseModel):
    """Schedule configuration update request."""

    working_days: list[WeekDay] | None = Field(default=None, min_length=1)
    start_time: time | None = None
    end_time: time | None = None
    appointment_duration_minutes: int | None = Field(default=None, gt=0)
    break_between_appointments_minutes: int | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def _validate_time_window_if_provided(self):
        if self.start_time is not None and self.end_time is not None and self.start_time >= self.end_time:
            raise ValueError("start_time must be earlier than end_time")
        return self


class ScheduleConfigurationResponse(BaseModel):
    """Schedule configuration response."""

    id: int
    user_id: int
    working_days: list[WeekDay]
    start_time: time
    end_time: time
    appointment_duration_minutes: int
    break_between_appointments_minutes: int
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class ScheduleConfigurationListResponse(BaseModel):
    """Schedule configuration list response."""

    configurations: list[ScheduleConfigurationResponse]
    total: int
    page: int
    page_size: int

"""OpenAPI helpers for schedule configuration routes."""

from pydantic import BaseModel, Field


class ScheduleConfigurationDeleteResponse(BaseModel):
    """Response payload returned after deleting a schedule configuration."""

    message: str = Field(
        description="Confirmation that the tenant schedule configuration was deleted.",
        examples=["Schedule configuration deleted successfully"],
    )


class ScheduleConfigurationErrorResponse(BaseModel):
    """Standard error payload returned by schedule configuration HTTP exceptions."""

    detail: str = Field(
        description="Human-readable error detail returned by the API.",
        examples=[
            "Schedule configuration not found",
            "Schedule configuration already exists for this tenant",
        ],
    )


SCHEDULE_CONFIGURATION_DELETE_EXAMPLE = {
    "summary": "Deletion acknowledgement",
    "value": {
        "message": "Schedule configuration deleted successfully",
    },
}

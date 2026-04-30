"""Medical record schemas (DTOs)."""

from datetime import datetime

from pydantic import BaseModel, Field, HttpUrl, field_validator, model_validator

from src.shared.schema_utils import _ensure_timezone_aware, _normalize_text

MAX_TITLE_LENGTH = 255
MAX_CONTENT_LENGTH = 20000
MAX_ATTACHMENTS = 20


class MedicalRecordCreateRequest(BaseModel):
    """Medical record creation request."""

    patient_id: int = Field(..., gt=0)
    appointment_id: int | None = Field(default=None, gt=0)
    recorded_at: datetime | None = None
    title: str | None = Field(default=None, max_length=MAX_TITLE_LENGTH)
    content: str = Field(..., min_length=1, max_length=MAX_CONTENT_LENGTH)
    clinical_assessment: str | None = Field(default=None, max_length=MAX_CONTENT_LENGTH)
    treatment_plan: str | None = Field(default=None, max_length=MAX_CONTENT_LENGTH)
    attachments: list[HttpUrl] = Field(default_factory=list, max_length=MAX_ATTACHMENTS)

    @field_validator("recorded_at")
    @classmethod
    def _validate_recorded_at(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return value
        return _ensure_timezone_aware(value, field_name="recorded_at")

    @field_validator("title")
    @classmethod
    def _validate_title(cls, value: str | None) -> str | None:
        return _normalize_text(value, field_name="title")

    @field_validator("content")
    @classmethod
    def _validate_content(cls, value: str) -> str:
        normalized = _normalize_text(value, field_name="content")
        if normalized is None:
            raise ValueError("content cannot be blank")
        return normalized

    @field_validator("clinical_assessment")
    @classmethod
    def _validate_clinical_assessment(cls, value: str | None) -> str | None:
        return _normalize_text(value, field_name="clinical_assessment")

    @field_validator("treatment_plan")
    @classmethod
    def _validate_treatment_plan(cls, value: str | None) -> str | None:
        return _normalize_text(value, field_name="treatment_plan")

    @field_validator("attachments")
    @classmethod
    def _validate_attachments(cls, value: list[HttpUrl]) -> list[HttpUrl]:
        serialized = [str(url) for url in value]
        if len(serialized) != len(set(serialized)):
            raise ValueError("attachments must not contain duplicates")
        return value


class MedicalRecordUpdateRequest(BaseModel):
    """Medical record update request."""

    patient_id: int | None = Field(default=None, gt=0)
    appointment_id: int | None = Field(default=None, gt=0)
    recorded_at: datetime | None = None
    title: str | None = Field(default=None, max_length=MAX_TITLE_LENGTH)
    content: str | None = Field(default=None, min_length=1, max_length=MAX_CONTENT_LENGTH)
    clinical_assessment: str | None = Field(default=None, max_length=MAX_CONTENT_LENGTH)
    treatment_plan: str | None = Field(default=None, max_length=MAX_CONTENT_LENGTH)
    attachments: list[HttpUrl] | None = Field(default=None, max_length=MAX_ATTACHMENTS)

    @field_validator("recorded_at")
    @classmethod
    def _validate_recorded_at(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return value
        return _ensure_timezone_aware(value, field_name="recorded_at")

    @field_validator("title")
    @classmethod
    def _validate_title(cls, value: str | None) -> str | None:
        return _normalize_text(value, field_name="title")

    @field_validator("content")
    @classmethod
    def _validate_content(cls, value: str | None) -> str | None:
        return _normalize_text(value, field_name="content")

    @field_validator("clinical_assessment")
    @classmethod
    def _validate_clinical_assessment(cls, value: str | None) -> str | None:
        return _normalize_text(value, field_name="clinical_assessment")

    @field_validator("treatment_plan")
    @classmethod
    def _validate_treatment_plan(cls, value: str | None) -> str | None:
        return _normalize_text(value, field_name="treatment_plan")

    @field_validator("attachments")
    @classmethod
    def _validate_attachments(cls, value: list[HttpUrl] | None) -> list[HttpUrl] | None:
        if value is None:
            return value

        serialized = [str(url) for url in value]
        if len(serialized) != len(set(serialized)):
            raise ValueError("attachments must not contain duplicates")
        return value

    @model_validator(mode="after")
    def _validate_nullable_update_fields(self):
        fields = self.model_fields_set

        if "patient_id" in fields and self.patient_id is None:
            raise ValueError("patient_id cannot be null")

        if "recorded_at" in fields and self.recorded_at is None:
            raise ValueError("recorded_at cannot be null")

        if "content" in fields and self.content is None:
            raise ValueError("content cannot be null")

        return self


class MedicalRecordResponse(BaseModel):
    """Medical record response."""

    id: int
    patient_id: int
    appointment_id: int | None
    recorded_by_user_id: int
    recorded_at: datetime
    title: str | None
    content: str
    clinical_assessment: str | None
    treatment_plan: str | None
    attachments: list[str]
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class MedicalRecordListResponse(BaseModel):
    """Medical record list response."""

    records: list[MedicalRecordResponse]
    total: int
    page: int
    page_size: int


class MedicalRecordPatientHistoryResponse(BaseModel):
    """Patient medical record history response."""

    patient_id: int
    records: list[MedicalRecordResponse]
    total: int
    page: int
    page_size: int

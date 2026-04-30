"""Patient schemas (DTOs)."""

from datetime import UTC, date, datetime
from decimal import Decimal

from pydantic import BaseModel, Field, HttpUrl, field_validator, model_validator

NAME_MIN_LENGTH = 3
PHONE_LENGTHS = {10, 11}
CPF_LENGTH = 11
CEP_LENGTH = 8


def _validate_name(value: str, *, field_name: str) -> str:
    normalized = value.strip()
    if value != normalized or not normalized:
        raise ValueError(f"{field_name} cannot start/end with spaces or be blank")
    if len(normalized) < NAME_MIN_LENGTH:
        raise ValueError(f"{field_name} must contain at least {NAME_MIN_LENGTH} characters")

    for char in normalized:
        if char.isalpha() or char in {" ", "-", "'"}:
            continue
        raise ValueError(f"{field_name} can only contain letters, spaces, hyphens, or apostrophes")

    return normalized


def _validate_digits_only(value: str, *, field_name: str, valid_lengths: set[int]) -> str:
    if not value.isdigit():
        raise ValueError(f"{field_name} must contain only digits")
    if len(value) not in valid_lengths:
        lengths = ", ".join(str(item) for item in sorted(valid_lengths))
        raise ValueError(f"{field_name} must have length {lengths}")
    return value


def _validate_birth_date(value: date) -> date:
    today = datetime.now(UTC).date()
    if value >= today:
        raise ValueError("birth_date must be before today")
    return value


def _is_minor(birth_date: date) -> bool:
    today = datetime.now(UTC).date()
    age = today.year - birth_date.year - ((today.month, today.day) < (birth_date.month, birth_date.day))
    return age < 18


def _validate_cpf(value: str) -> str:
    _validate_digits_only(value, field_name="cpf", valid_lengths={CPF_LENGTH})
    if len(set(value)) == 1:
        raise ValueError("cpf is invalid")

    digits = [int(char) for char in value]
    first_sum = sum(number * factor for number, factor in zip(digits[:9], range(10, 1, -1), strict=True))
    first_check = (first_sum * 10) % 11
    first_check = 0 if first_check == 10 else first_check

    second_sum = sum(number * factor for number, factor in zip(digits[:10], range(11, 1, -1), strict=True))
    second_check = (second_sum * 10) % 11
    second_check = 0 if second_check == 10 else second_check

    if digits[9] != first_check or digits[10] != second_check:
        raise ValueError("cpf is invalid")

    return value


class PatientCreateRequest(BaseModel):
    """Patient creation request."""

    full_name: str = Field(..., min_length=NAME_MIN_LENGTH, max_length=255)
    birth_date: date
    cpf: str = Field(..., min_length=CPF_LENGTH, max_length=CPF_LENGTH)
    cep: str = Field(..., min_length=CEP_LENGTH, max_length=CEP_LENGTH)
    phone_number: str = Field(..., min_length=min(PHONE_LENGTHS), max_length=max(PHONE_LENGTHS))
    session_price: Decimal = Field(..., gt=0, max_digits=10, decimal_places=2)
    session_frequency: str = Field(..., min_length=1, max_length=50)
    first_session_date: date | None = None
    guardian_name: str | None = Field(default=None, min_length=NAME_MIN_LENGTH, max_length=255)
    guardian_phone: str | None = Field(default=None, min_length=min(PHONE_LENGTHS), max_length=max(PHONE_LENGTHS))
    profile_photo_url: HttpUrl | None = None
    initial_record: str | None = Field(default=None, max_length=5000)

    @field_validator("full_name")
    @classmethod
    def _validate_full_name(cls, value: str) -> str:
        return _validate_name(value, field_name="full_name")

    @field_validator("birth_date")
    @classmethod
    def _validate_birth_date(cls, value: date) -> date:
        return _validate_birth_date(value)

    @field_validator("cpf")
    @classmethod
    def _validate_cpf(cls, value: str) -> str:
        return _validate_cpf(value)

    @field_validator("cep")
    @classmethod
    def _validate_cep(cls, value: str) -> str:
        return _validate_digits_only(value, field_name="cep", valid_lengths={CEP_LENGTH})

    @field_validator("phone_number")
    @classmethod
    def _validate_phone_number(cls, value: str) -> str:
        return _validate_digits_only(value, field_name="phone_number", valid_lengths=PHONE_LENGTHS)

    @field_validator("guardian_name")
    @classmethod
    def _validate_guardian_name(cls, value: str | None) -> str | None:
        if value is None:
            return value
        return _validate_name(value, field_name="guardian_name")

    @field_validator("guardian_phone")
    @classmethod
    def _validate_guardian_phone(cls, value: str | None) -> str | None:
        if value is None:
            return value
        return _validate_digits_only(value, field_name="guardian_phone", valid_lengths=PHONE_LENGTHS)

    @field_validator("session_frequency")
    @classmethod
    def _validate_session_frequency(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("session_frequency cannot be blank")
        return normalized

    @model_validator(mode="after")
    def _validate_business_rules(self):
        if self.first_session_date is not None and self.first_session_date < self.birth_date:
            raise ValueError("first_session_date cannot be before birth_date")

        if _is_minor(self.birth_date) and (self.guardian_name is None or self.guardian_phone is None):
            raise ValueError("guardian_name and guardian_phone are required for minors")

        return self


class PatientQuickCreateRequest(BaseModel):
    """Quick patient creation request for first consultation registration."""

    full_name: str = Field(..., min_length=NAME_MIN_LENGTH, max_length=255)

    @field_validator("full_name")
    @classmethod
    def _validate_full_name(cls, value: str) -> str:
        return _validate_name(value, field_name="full_name")


class PatientUpdateRequest(BaseModel):
    """Patient update request."""

    full_name: str | None = Field(default=None, min_length=NAME_MIN_LENGTH, max_length=255)
    birth_date: date | None = None
    cpf: str | None = Field(default=None, min_length=CPF_LENGTH, max_length=CPF_LENGTH)
    cep: str | None = Field(default=None, min_length=CEP_LENGTH, max_length=CEP_LENGTH)
    phone_number: str | None = Field(default=None, min_length=min(PHONE_LENGTHS), max_length=max(PHONE_LENGTHS))
    session_price: Decimal | None = Field(default=None, gt=0, max_digits=10, decimal_places=2)
    session_frequency: str | None = Field(default=None, min_length=1, max_length=50)
    first_session_date: date | None = None
    guardian_name: str | None = Field(default=None, min_length=NAME_MIN_LENGTH, max_length=255)
    guardian_phone: str | None = Field(default=None, min_length=min(PHONE_LENGTHS), max_length=max(PHONE_LENGTHS))
    profile_photo_url: HttpUrl | None = None
    initial_record: str | None = Field(default=None, max_length=5000)

    @field_validator("full_name")
    @classmethod
    def _validate_full_name(cls, value: str | None) -> str | None:
        if value is None:
            return value
        return _validate_name(value, field_name="full_name")

    @field_validator("birth_date")
    @classmethod
    def _validate_birth_date(cls, value: date | None) -> date | None:
        if value is None:
            return value
        return _validate_birth_date(value)

    @field_validator("cpf")
    @classmethod
    def _validate_cpf(cls, value: str | None) -> str | None:
        if value is None:
            return value
        return _validate_cpf(value)

    @field_validator("cep")
    @classmethod
    def _validate_cep(cls, value: str | None) -> str | None:
        if value is None:
            return value
        return _validate_digits_only(value, field_name="cep", valid_lengths={CEP_LENGTH})

    @field_validator("phone_number")
    @classmethod
    def _validate_phone_number(cls, value: str | None) -> str | None:
        if value is None:
            return value
        return _validate_digits_only(value, field_name="phone_number", valid_lengths=PHONE_LENGTHS)

    @field_validator("guardian_name")
    @classmethod
    def _validate_guardian_name(cls, value: str | None) -> str | None:
        if value is None:
            return value
        return _validate_name(value, field_name="guardian_name")

    @field_validator("guardian_phone")
    @classmethod
    def _validate_guardian_phone(cls, value: str | None) -> str | None:
        if value is None:
            return value
        return _validate_digits_only(value, field_name="guardian_phone", valid_lengths=PHONE_LENGTHS)

    @field_validator("session_frequency")
    @classmethod
    def _validate_session_frequency(cls, value: str | None) -> str | None:
        if value is None:
            return value
        normalized = value.strip()
        if not normalized:
            raise ValueError("session_frequency cannot be blank")
        return normalized


class PatientCompleteRegistrationRequest(PatientCreateRequest):
    """Complete registration for a previously quick-registered patient."""


class PatientResponse(BaseModel):
    """Patient response."""

    id: int
    full_name: str
    birth_date: date | None
    cpf: str | None
    cep: str | None
    phone_number: str | None
    session_price: Decimal | None
    session_frequency: str | None
    first_session_date: date | None
    guardian_name: str | None
    guardian_phone: str | None
    profile_photo_url: str | None
    initial_record: str | None
    is_registered: bool
    is_active: bool
    inactivated_at: datetime | None
    retention_expires_at: datetime | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class PatientListResponse(BaseModel):
    """Patient list response."""

    patients: list[PatientResponse]
    total: int
    page: int
    page_size: int

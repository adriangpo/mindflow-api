"""Finance schemas (DTOs)."""

from datetime import date, datetime
from decimal import Decimal
from enum import StrEnum

from pydantic import BaseModel, Field, field_validator

from src.shared.schema_utils import _normalize_text

MAX_DESCRIPTION_LENGTH = 255
MAX_NOTES_LENGTH = 5000
MAX_REVERSAL_REASON_LENGTH = 500


class FinancialEntryType(StrEnum):
    """Supported manual financial entry types."""

    INCOME = "income"
    EXPENSE = "expense"


class FinancialEntryClassification(StrEnum):
    """Supported manual entry classifications."""

    FIXED = "fixed"
    VARIABLE = "variable"


class FinanceReportView(StrEnum):
    """Supported finance report windows."""

    DAY = "day"
    WEEK = "week"
    MONTH = "month"
    YEAR = "year"
    TOTAL = "total"
    CUSTOM = "custom"


class FinancialEntryCreateRequest(BaseModel):
    """Manual financial entry creation request."""

    entry_type: FinancialEntryType
    classification: FinancialEntryClassification
    description: str = Field(..., min_length=1, max_length=MAX_DESCRIPTION_LENGTH)
    amount: Decimal = Field(..., gt=0, max_digits=10, decimal_places=2)
    occurred_on: date
    notes: str | None = Field(default=None, max_length=MAX_NOTES_LENGTH)

    @field_validator("description")
    @classmethod
    def _validate_description(cls, value: str) -> str:
        normalized = _normalize_text(value, field_name="description")
        if normalized is None:
            raise ValueError("description cannot be blank")
        return normalized

    @field_validator("notes")
    @classmethod
    def _validate_notes(cls, value: str | None) -> str | None:
        return _normalize_text(value, field_name="notes")


class FinancialEntryReverseRequest(BaseModel):
    """Financial entry reversal request."""

    reversal_reason: str = Field(..., min_length=3, max_length=MAX_REVERSAL_REASON_LENGTH)

    @field_validator("reversal_reason")
    @classmethod
    def _validate_reversal_reason(cls, value: str) -> str:
        normalized = _normalize_text(value, field_name="reversal_reason")
        if normalized is None:
            raise ValueError("reversal_reason cannot be blank")
        return normalized


class FinancialEntryResponse(BaseModel):
    """Manual financial entry response."""

    id: int
    created_by_user_id: int
    entry_type: FinancialEntryType
    classification: FinancialEntryClassification
    description: str
    amount: Decimal
    occurred_on: date
    notes: str | None
    is_reversed: bool
    reversed_at: datetime | None
    reversed_by_user_id: int | None
    reversal_reason: str | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class FinancialEntryListResponse(BaseModel):
    """Financial entry list response."""

    entries: list[FinancialEntryResponse]
    total: int
    page: int
    page_size: int


class FinanceReportResponse(BaseModel):
    """Finance report summary response."""

    view: FinanceReportView
    range_start: date | None
    range_end: date | None
    automatic_income_total: Decimal
    manual_income_total: Decimal
    manual_expense_total: Decimal
    total_income: Decimal
    total_expense: Decimal
    net_total: Decimal
    paid_appointments_count: int
    manual_income_count: int
    manual_expense_count: int

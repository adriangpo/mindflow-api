"""Export job schemas (DTOs)."""

from datetime import date, datetime
from enum import StrEnum
from uuid import UUID

from pydantic import BaseModel

from src.features.finance.schemas import FinanceReportView


class ExportJobKind(StrEnum):
    """Supported async export job types."""

    MEDICAL_RECORD_SINGLE_PDF = "medical_record_single_pdf"
    MEDICAL_RECORD_PATIENT_HISTORY_PDF = "medical_record_patient_history_pdf"
    MEDICAL_RECORD_ALL_PDF = "medical_record_all_pdf"
    PATIENT_COMPLETE_PDF = "patient_complete_pdf"
    FINANCE_REPORT_PDF = "finance_report_pdf"


class ExportJobStatus(StrEnum):
    """Supported export job lifecycle states."""

    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ExportJobResponse(BaseModel):
    """Public export job response."""

    id: str
    kind: ExportJobKind
    status: ExportJobStatus
    progress_current: int
    progress_total: int
    progress_message: str | None
    download_url: str | None
    error_detail: str | None
    created_at: datetime
    updated_at: datetime


class ExportProcessCallbackRequest(BaseModel):
    """Signed QStash callback payload for export processing."""

    job_id: str


class FinanceReportExportRequest(BaseModel):
    """Finance report export request payload."""

    view: FinanceReportView = FinanceReportView.DAY
    reference_date: date | None = None
    start_date: date | None = None
    end_date: date | None = None


class ExportJobSnapshot(BaseModel):
    """Internal Redis-backed export job snapshot."""

    id: str
    kind: ExportJobKind
    status: ExportJobStatus
    progress_current: int
    progress_total: int
    progress_message: str | None
    download_url: str | None
    error_detail: str | None
    created_at: datetime
    updated_at: datetime
    tenant_id: UUID
    created_by_user_id: int
    payload: dict[str, object]
    file_relative_path: str | None = None
    filename: str | None = None
    content_type: str | None = None

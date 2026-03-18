"""Medical record router (API endpoints)."""

from datetime import date

from fastapi import APIRouter, Depends, Query
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession

from src.database.dependencies import get_tenant_db_session
from src.features.auth.dependencies import require_role, require_tenant_membership
from src.features.user.models import User, UserRole
from src.shared.pagination.pagination import PaginationParams
from src.shared.storage import StoredFile

from .schemas import (
    MedicalRecordCreateRequest,
    MedicalRecordListResponse,
    MedicalRecordPatientHistoryResponse,
    MedicalRecordResponse,
    MedicalRecordUpdateRequest,
)
from .service import MedicalRecordService

router = APIRouter(
    prefix="/medical-records",
    tags=["Medical Record Management"],
    dependencies=[Depends(require_role(UserRole.TENANT_OWNER))],
)


def _pdf_response(stored_file: StoredFile) -> FileResponse:
    """Build a downloadable PDF response."""
    return FileResponse(
        path=stored_file.path,
        media_type=stored_file.content_type,
        filename=stored_file.filename,
    )


@router.post("", response_model=MedicalRecordResponse)
async def create_medical_record(
    data: MedicalRecordCreateRequest,
    current_user: User = Depends(require_tenant_membership),
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Create a medical record entry."""
    record = await MedicalRecordService.create_record(session, current_user.id, data)
    await session.commit()
    await session.refresh(record)
    return MedicalRecordResponse.model_validate(record)


@router.get("", response_model=MedicalRecordListResponse)
async def list_medical_records(
    pagination: PaginationParams = Depends(),
    patient_id: int | None = Query(default=None, gt=0),
    appointment_id: int | None = Query(default=None, gt=0),
    search: str | None = Query(default=None, min_length=1, max_length=255),
    start_date: date | None = Query(default=None),
    end_date: date | None = Query(default=None),
    _: User = Depends(require_tenant_membership),
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """List tenant medical records with optional filters."""
    records, total = await MedicalRecordService.list_records(
        session=session,
        pagination=pagination,
        patient_id=patient_id,
        appointment_id=appointment_id,
        search=search,
        start_date=start_date,
        end_date=end_date,
    )

    return MedicalRecordListResponse(
        records=[MedicalRecordResponse.model_validate(record) for record in records],
        total=total,
        page=pagination.page or 1,
        page_size=pagination.page_size or 50,
    )


@router.get("/patients/{patient_id}/history", response_model=MedicalRecordPatientHistoryResponse)
async def get_patient_medical_record_history(
    patient_id: int,
    pagination: PaginationParams = Depends(),
    _: User = Depends(require_tenant_membership),
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """List consultation history records for a patient."""
    records, total = await MedicalRecordService.get_patient_history(session, patient_id, pagination)
    return MedicalRecordPatientHistoryResponse(
        patient_id=patient_id,
        records=[MedicalRecordResponse.model_validate(record) for record in records],
        total=total,
        page=pagination.page or 1,
        page_size=pagination.page_size or 50,
    )


@router.get("/export/pdf")
async def export_all_medical_records_pdf(
    _: User = Depends(require_tenant_membership),
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Export all tenant medical records as a PDF file."""
    stored_file = await MedicalRecordService.export_all_records_pdf(session)
    return _pdf_response(stored_file)


@router.get("/patients/{patient_id}/export/pdf")
async def export_patient_medical_record_history_pdf(
    patient_id: int,
    _: User = Depends(require_tenant_membership),
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Export one patient's medical record history as a PDF file."""
    stored_file = await MedicalRecordService.export_patient_history_pdf(session, patient_id)
    return _pdf_response(stored_file)


@router.get("/{record_id}/export/pdf")
async def export_single_medical_record_pdf(
    record_id: int,
    _: User = Depends(require_tenant_membership),
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Export a single medical record entry as a PDF file."""
    stored_file = await MedicalRecordService.export_record_pdf(session, record_id)
    return _pdf_response(stored_file)


@router.get("/{record_id}", response_model=MedicalRecordResponse)
async def get_medical_record(
    record_id: int,
    _: User = Depends(require_tenant_membership),
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Get one medical record by id."""
    record = await MedicalRecordService.require_record(session, record_id)
    return MedicalRecordResponse.model_validate(record)


@router.put("/{record_id}", response_model=MedicalRecordResponse)
async def update_medical_record(
    record_id: int,
    data: MedicalRecordUpdateRequest,
    _: User = Depends(require_tenant_membership),
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Update a medical record entry."""
    record = await MedicalRecordService.require_record(session, record_id)
    updated = await MedicalRecordService.update_record(session, record, data)
    await session.commit()
    await session.refresh(updated)
    return MedicalRecordResponse.model_validate(updated)

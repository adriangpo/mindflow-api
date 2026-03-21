"""Medical record router (API endpoints)."""

from datetime import date

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from src.database.dependencies import get_tenant_db_session
from src.features.auth.dependencies import require_role, require_tenant_membership
from src.features.export.schemas import ExportJobKind, ExportJobResponse
from src.features.export.service import ExportService
from src.features.user.models import User, UserRole
from src.shared.pagination.pagination import PaginationParams

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


@router.post("/export/pdf", response_model=ExportJobResponse, status_code=status.HTTP_202_ACCEPTED)
async def export_all_medical_records_pdf(
    current_user: User = Depends(require_tenant_membership),
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Queue an async export job for all tenant medical records."""
    await MedicalRecordService.validate_all_records_export(session)
    return await ExportService.create_job(
        kind=ExportJobKind.MEDICAL_RECORD_ALL_PDF,
        tenant_id=session.info["tenant_id"],
        user_id=current_user.id,
        payload={},
    )


@router.post(
    "/patients/{patient_id}/export/pdf", response_model=ExportJobResponse, status_code=status.HTTP_202_ACCEPTED
)
async def export_patient_medical_record_history_pdf(
    patient_id: int,
    current_user: User = Depends(require_tenant_membership),
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Queue an async export job for one patient's medical record history."""
    await MedicalRecordService.validate_patient_history_export(session, patient_id)
    return await ExportService.create_job(
        kind=ExportJobKind.MEDICAL_RECORD_PATIENT_HISTORY_PDF,
        tenant_id=session.info["tenant_id"],
        user_id=current_user.id,
        payload={"patient_id": patient_id},
    )


@router.post("/{record_id}/export/pdf", response_model=ExportJobResponse, status_code=status.HTTP_202_ACCEPTED)
async def export_single_medical_record_pdf(
    record_id: int,
    current_user: User = Depends(require_tenant_membership),
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Queue an async export job for a single medical record entry."""
    await MedicalRecordService.validate_record_export(session, record_id)
    return await ExportService.create_job(
        kind=ExportJobKind.MEDICAL_RECORD_SINGLE_PDF,
        tenant_id=session.info["tenant_id"],
        user_id=current_user.id,
        payload={"record_id": record_id},
    )


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

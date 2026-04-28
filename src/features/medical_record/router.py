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

from .openapi import (
    CREATE_MEDICAL_RECORD_RESPONSES,
    DETAIL_MEDICAL_RECORD_RESPONSES,
    EXPORT_ALL_MEDICAL_RECORD_RESPONSES,
    EXPORT_PATIENT_HISTORY_RESPONSES,
    EXPORT_SINGLE_RESPONSES,
    HISTORY_MEDICAL_RECORDS_RESPONSES,
    LIST_MEDICAL_RECORDS_RESPONSES,
    MEDICAL_RECORD_CREATE_DESCRIPTION,
    MEDICAL_RECORD_DETAIL_DESCRIPTION,
    MEDICAL_RECORD_EXPORT_ALL_DESCRIPTION,
    MEDICAL_RECORD_EXPORT_PATIENT_DESCRIPTION,
    MEDICAL_RECORD_EXPORT_SINGLE_DESCRIPTION,
    MEDICAL_RECORD_HISTORY_DESCRIPTION,
    MEDICAL_RECORD_LIST_DESCRIPTION,
    MEDICAL_RECORD_UPDATE_DESCRIPTION,
    UPDATE_MEDICAL_RECORD_RESPONSES,
)
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
    dependencies=[Depends(require_role(UserRole.TENANT_OWNER)), Depends(require_tenant_membership)],
)


@router.post(
    "",
    response_model=MedicalRecordResponse,
    summary="Create a medical record",
    description=MEDICAL_RECORD_CREATE_DESCRIPTION,
    response_description="The newly created consultation note for the current tenant.",
    responses=CREATE_MEDICAL_RECORD_RESPONSES,
)
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


@router.get(
    "",
    response_model=MedicalRecordListResponse,
    summary="List medical records",
    description=MEDICAL_RECORD_LIST_DESCRIPTION,
    response_description="Paginated consultation notes for the current tenant.",
    responses=LIST_MEDICAL_RECORDS_RESPONSES,
)
async def list_medical_records(
    pagination: PaginationParams = Depends(),
    patient_id: int | None = Query(default=None, gt=0, description="Filter by a specific patient id."),
    appointment_id: int | None = Query(default=None, gt=0, description="Filter by a specific appointment id."),
    search: str | None = Query(
        default=None,
        min_length=1,
        max_length=255,
        description="Free-text search across title, content, clinical assessment, and treatment plan.",
    ),
    start_date: date | None = Query(
        default=None,
        description="Include records whose recorded date is on or after this value.",
    ),
    end_date: date | None = Query(
        default=None,
        description="Include records whose recorded date is on or before this value.",
    ),
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


@router.get(
    "/patients/{patient_id}/history",
    response_model=MedicalRecordPatientHistoryResponse,
    summary="Get patient medical record history",
    description=MEDICAL_RECORD_HISTORY_DESCRIPTION,
    response_description="Paginated consultation history for one patient in the current tenant.",
    responses=HISTORY_MEDICAL_RECORDS_RESPONSES,
)
async def get_patient_medical_record_history(
    patient_id: int,
    pagination: PaginationParams = Depends(),
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


@router.post(
    "/export/pdf",
    response_model=ExportJobResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Queue a PDF export for all medical records",
    description=MEDICAL_RECORD_EXPORT_ALL_DESCRIPTION,
    response_description="Generic export job metadata for the queued PDF export.",
    responses=EXPORT_ALL_MEDICAL_RECORD_RESPONSES,
)
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
    "/patients/{patient_id}/export/pdf",
    response_model=ExportJobResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Queue a PDF export for one patient history",
    description=MEDICAL_RECORD_EXPORT_PATIENT_DESCRIPTION,
    response_description="Generic export job metadata for the queued PDF export.",
    responses=EXPORT_PATIENT_HISTORY_RESPONSES,
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


@router.post(
    "/{record_id}/export/pdf",
    response_model=ExportJobResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Queue a PDF export for one medical record",
    description=MEDICAL_RECORD_EXPORT_SINGLE_DESCRIPTION,
    response_description="Generic export job metadata for the queued PDF export.",
    responses=EXPORT_SINGLE_RESPONSES,
)
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


@router.get(
    "/{record_id}",
    response_model=MedicalRecordResponse,
    summary="Get a medical record",
    description=MEDICAL_RECORD_DETAIL_DESCRIPTION,
    response_description="One consultation note from the current tenant.",
    responses=DETAIL_MEDICAL_RECORD_RESPONSES,
)
async def get_medical_record(
    record_id: int,
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Get one medical record by id."""
    record = await MedicalRecordService.require_record(session, record_id)
    return MedicalRecordResponse.model_validate(record)


@router.put(
    "/{record_id}",
    response_model=MedicalRecordResponse,
    summary="Update a medical record",
    description=MEDICAL_RECORD_UPDATE_DESCRIPTION,
    response_description="The updated consultation note for the current tenant.",
    responses=UPDATE_MEDICAL_RECORD_RESPONSES,
)
async def update_medical_record(
    record_id: int,
    data: MedicalRecordUpdateRequest,
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Update a medical record entry."""
    record = await MedicalRecordService.require_record(session, record_id)
    updated = await MedicalRecordService.update_record(session, record, data)
    await session.commit()
    await session.refresh(updated)
    return MedicalRecordResponse.model_validate(updated)

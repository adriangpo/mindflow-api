"""Medical record router (API endpoints)."""

import mimetypes
from datetime import date
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile, status
from fastapi.responses import FileResponse, RedirectResponse
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
from .storage import MedicalRecordStorage

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
    description=(
        MEDICAL_RECORD_UPDATE_DESCRIPTION + "\n\nThis endpoint accepts `multipart/form-data`. "
        "Send the JSON update payload as the `data` field and optional attachment files as `files`. "
        "When `files` are provided they replace all existing attachments. "
        "Omit `files` to leave existing attachments unchanged."
    ),
    response_description="The updated consultation note for the current tenant.",
    responses=UPDATE_MEDICAL_RECORD_RESPONSES,
)
async def update_medical_record(
    record_id: int,
    data: Annotated[
        str,
        Form(
            description=(
                "JSON object with the fields to update. "
                "Accepted keys: patient_id, appointment_id, recorded_at, title, content, "
                "clinical_assessment, treatment_plan. "
                "Omit a key to leave its value unchanged. "
                "Attachments are managed via the `files` field."
            )
        ),
    ] = "{}",
    files: Annotated[
        list[UploadFile] | None,
        File(description="Attachment files to store. When provided, replaces all existing attachments."),
    ] = None,
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Update a medical record entry with optional file attachment upload."""
    record = await MedicalRecordService.require_record(session, record_id)
    update_request = MedicalRecordUpdateRequest.model_validate_json(data)

    attachment_paths: list[str] | None = None
    if files is not None and len(files) > 0:
        tenant_id = session.info["tenant_id"]
        storage = MedicalRecordStorage()
        paths: list[str] = []
        for f in files:
            file_data = await f.read()
            stored = storage.store_attachment(
                tenant_id,
                record.id,
                f.filename or "attachment",
                file_data,
                f.content_type or "application/octet-stream",
            )
            paths.append(str(stored.relative_path))
        attachment_paths = paths

    updated = await MedicalRecordService.update_record(
        session, record, update_request, attachment_paths=attachment_paths
    )
    await session.commit()
    await session.refresh(updated)
    return MedicalRecordResponse.model_validate(updated)


@router.get(
    "/{record_id}/attachments/{index}",
    summary="Download a medical record attachment",
    description=(
        "Download or redirect to one attachment stored for a medical record. "
        "The index corresponds to the position of the attachment in the record's attachment list. "
        "For local storage the response is a direct binary download. "
        "For S3-compatible storage the API returns a 307 redirect to a presigned URL."
    ),
    response_description="Binary file download or temporary redirect to a presigned URL.",
    responses={
        200: {"description": "Binary file download."},
        307: {"description": "Temporary redirect to a presigned S3 URL."},
        404: {"description": "Attachment not found at the given index."},
    },
)
async def get_medical_record_attachment(
    record_id: int,
    index: int,
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Serve or redirect to a stored attachment for a medical record."""
    record = await MedicalRecordService.require_record(session, record_id)

    if index < 0 or index >= len(record.attachments):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Attachment at index {index} not found. Record has {len(record.attachments)} attachment(s).",
        )

    relative_path = record.attachments[index]
    path = Path(relative_path)
    content_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"

    try:
        download = MedicalRecordStorage().resolve_attachment_download(
            relative_path,
            filename=path.name,
            content_type=content_type,
        )
    except FileNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Attachment file not found.") from exc

    if download.path is not None:
        return FileResponse(path=download.path, media_type=content_type, filename=path.name)
    if download.url is not None:
        return RedirectResponse(download.url, status_code=307)
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Attachment could not be resolved.")

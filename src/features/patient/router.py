"""Patient router (API endpoints)."""

from typing import Annotated

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status
from fastapi.encoders import jsonable_encoder
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import ValidationError
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from src.database.dependencies import get_tenant_db_session
from src.features.auth.dependencies import require_role, require_tenant_membership
from src.features.export.schemas import ExportJobKind, ExportJobResponse
from src.features.export.service import ExportService
from src.features.user.models import User, UserRole
from src.shared.pagination.pagination import PaginationParams

from .exceptions import PatientCpfAlreadyExists
from .openapi import (
    COMPLETE_REGISTRATION_DESCRIPTION,
    CREATE_PATIENT_DESCRIPTION,
    EXPORT_PATIENT_DESCRIPTION,
    GET_PATIENT_DESCRIPTION,
    INACTIVATE_PATIENT_DESCRIPTION,
    LIST_PATIENTS_DESCRIPTION,
    PATIENT_COMPLETE_REGISTRATION_RESPONSES,
    PATIENT_CREATE_RESPONSES,
    PATIENT_DELETE_RESPONSE_DOC,
    PATIENT_DELETE_RESPONSES,
    PATIENT_EXPORT_RESPONSE_DOC,
    PATIENT_EXPORT_RESPONSES,
    PATIENT_GET_RESPONSES,
    PATIENT_LIST_RESPONSE_DOC,
    PATIENT_LIST_RESPONSES,
    PATIENT_PROFILE_PHOTO_RESPONSES,
    PATIENT_QUICK_REGISTER_RESPONSES,
    PATIENT_REACTIVATE_RESPONSES,
    PATIENT_RESPONSE_DOC,
    PATIENT_UPDATE_RESPONSES,
    PROFILE_PHOTO_DESCRIPTION,
    QUICK_REGISTER_DESCRIPTION,
    REACTIVATE_PATIENT_DESCRIPTION,
    UPDATE_PATIENT_DESCRIPTION,
    PatientMessageResponse,
)
from .schemas import (
    PatientCompleteRegistrationRequest,
    PatientCreateRequest,
    PatientListResponse,
    PatientQuickCreateRequest,
    PatientResponse,
    PatientUpdateRequest,
)
from .service import PatientService, is_patient_cpf_unique_violation
from .storage import PatientStorage

_ALLOWED_PHOTO_TYPES = {"image/jpeg", "image/png", "image/webp"}

router = APIRouter(
    prefix="/patients",
    tags=["Patient Management"],
    dependencies=[Depends(require_role(UserRole.TENANT_OWNER)), Depends(require_tenant_membership)],
)


def _merged_registered_payload(patient, data: PatientUpdateRequest) -> dict:
    """Build merged payload for re-validating full registered-patient state."""
    update_data = data.model_dump(exclude_unset=True)

    return {
        "full_name": update_data.get("full_name", patient.full_name),
        "birth_date": update_data.get("birth_date", patient.birth_date),
        "cpf": update_data.get("cpf", patient.cpf),
        "cep": update_data.get("cep", patient.cep),
        "phone_number": update_data.get("phone_number", patient.phone_number),
        "session_price": update_data.get("session_price", patient.session_price),
        "session_frequency": update_data.get("session_frequency", patient.session_frequency),
        "first_session_date": update_data.get("first_session_date", patient.first_session_date),
        "guardian_name": update_data.get("guardian_name", patient.guardian_name),
        "guardian_phone": update_data.get("guardian_phone", patient.guardian_phone),
        "initial_record": update_data.get("initial_record", patient.initial_record),
    }


@router.post(
    "",
    response_model=PatientResponse,
    summary="Create a fully registered patient",
    description=CREATE_PATIENT_DESCRIPTION,
    response_description="The created patient record for the current tenant.",
    responses={**PATIENT_RESPONSE_DOC, **PATIENT_CREATE_RESPONSES},
)
async def create_patient(
    data: PatientCreateRequest,
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Create a fully registered patient."""
    patient = await PatientService.create_patient(session, data)
    try:
        await session.commit()
    except IntegrityError as exc:
        await session.rollback()
        if is_patient_cpf_unique_violation(exc):
            raise PatientCpfAlreadyExists() from exc
        raise
    await session.refresh(patient)
    return PatientResponse.model_validate(patient)


@router.post(
    "/quick-register",
    response_model=PatientResponse,
    summary="Create a quick-registration patient",
    description=QUICK_REGISTER_DESCRIPTION,
    response_description="The newly created quick-registration patient.",
    responses={**PATIENT_RESPONSE_DOC, **PATIENT_QUICK_REGISTER_RESPONSES},
)
async def quick_register_patient(
    data: PatientQuickCreateRequest,
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Create patient with name only for first consultation registration."""
    patient = await PatientService.create_quick_patient(session, data)
    await session.commit()
    await session.refresh(patient)
    return PatientResponse.model_validate(patient)


@router.get(
    "",
    response_model=PatientListResponse,
    summary="List tenant patients",
    description=LIST_PATIENTS_DESCRIPTION,
    response_description="Paginated tenant patient collection.",
    responses={**PATIENT_LIST_RESPONSE_DOC, **PATIENT_LIST_RESPONSES},
)
async def list_patients(
    pagination: PaginationParams = Depends(),
    search: str | None = Query(
        default=None,
        min_length=1,
        max_length=255,
        description="Case-insensitive search over full name, CPF, or phone number.",
    ),
    active_only: bool = Query(
        default=True,
        description="When true, returns only active patients. Set false to include inactive rows.",
    ),
    is_registered: bool | None = Query(
        default=None,
        description="Filter by registration state when provided.",
    ),
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """List patients from tenant with search, activity, and registration filters."""
    items, total = await PatientService.list_patients(
        session=session,
        pagination=pagination,
        search=search,
        is_active=True if active_only else None,
        is_registered=is_registered,
    )
    return PatientListResponse(
        patients=[PatientResponse.model_validate(item) for item in items],
        total=total,
        page=pagination.page or 1,
        page_size=pagination.page_size or 50,
    )


@router.get(
    "/{patient_id}",
    response_model=PatientResponse,
    summary="Get one patient",
    description=GET_PATIENT_DESCRIPTION,
    response_description="The requested patient from the current tenant.",
    responses={**PATIENT_RESPONSE_DOC, **PATIENT_GET_RESPONSES},
)
async def get_patient(
    patient_id: int,
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Get patient by id."""
    patient = await PatientService.require_patient(session, patient_id)
    return PatientResponse.model_validate(patient)


@router.post(
    "/{patient_id}/export/pdf",
    response_model=ExportJobResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Queue a patient dossier export",
    description=EXPORT_PATIENT_DESCRIPTION,
    response_description="Queued export job for later polling or download.",
    responses={**PATIENT_EXPORT_RESPONSE_DOC, **PATIENT_EXPORT_RESPONSES},
)
async def export_patient_complete_pdf(
    patient_id: int,
    current_user: User = Depends(require_tenant_membership),
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Queue a complete patient dossier export."""
    await PatientService.require_patient(session, patient_id)
    return await ExportService.create_job(
        kind=ExportJobKind.PATIENT_COMPLETE_PDF,
        tenant_id=session.info["tenant_id"],
        user_id=current_user.id,
        payload={"patient_id": patient_id},
    )


@router.put(
    "/{patient_id}",
    response_model=PatientResponse,
    summary="Update a patient",
    description=UPDATE_PATIENT_DESCRIPTION,
    response_description="The updated patient record after the partial update is applied.",
    responses={**PATIENT_RESPONSE_DOC, **PATIENT_UPDATE_RESPONSES},
)
async def update_patient(
    patient_id: int,
    data: PatientUpdateRequest,
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Update patient data."""
    patient = await PatientService.require_patient(session, patient_id)

    if patient.is_registered:
        try:
            PatientCreateRequest.model_validate(_merged_registered_payload(patient, data))
        except ValidationError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=jsonable_encoder(exc.errors()),
            ) from exc

    updated = await PatientService.update_patient(session, patient, data)
    try:
        await session.commit()
    except IntegrityError as exc:
        await session.rollback()
        if is_patient_cpf_unique_violation(exc):
            raise PatientCpfAlreadyExists() from exc
        raise

    await session.refresh(updated)
    return PatientResponse.model_validate(updated)


@router.post(
    "/{patient_id}/complete-registration",
    response_model=PatientResponse,
    summary="Complete patient registration",
    description=COMPLETE_REGISTRATION_DESCRIPTION,
    response_description="The patient after full registration has been completed.",
    responses={**PATIENT_RESPONSE_DOC, **PATIENT_COMPLETE_REGISTRATION_RESPONSES},
)
async def complete_patient_registration(
    patient_id: int,
    data: PatientCompleteRegistrationRequest,
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Complete registration for a quick-registered patient."""
    patient = await PatientService.require_patient(session, patient_id)
    updated = await PatientService.complete_registration(session, patient, data)

    try:
        await session.commit()
    except IntegrityError as exc:
        await session.rollback()
        if is_patient_cpf_unique_violation(exc):
            raise PatientCpfAlreadyExists() from exc
        raise

    await session.refresh(updated)
    return PatientResponse.model_validate(updated)


@router.patch(
    "/{patient_id}/profile-photo",
    response_model=PatientResponse,
    summary="Upload patient profile photo",
    description=PROFILE_PHOTO_DESCRIPTION,
    response_description="The patient after the profile photo is stored and linked.",
    responses={**PATIENT_RESPONSE_DOC, **PATIENT_PROFILE_PHOTO_RESPONSES},
)
async def update_patient_profile_photo(
    patient_id: int,
    file: Annotated[
        UploadFile,
        File(description="Profile photo image file. Accepted formats: JPEG, PNG, WebP."),
    ],
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Upload and store a patient profile photo."""
    if file.content_type not in _ALLOWED_PHOTO_TYPES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Profile photo must be a JPEG, PNG, or WebP image.",
        )
    patient = await PatientService.require_patient(session, patient_id)
    file_data = await file.read()
    updated = await PatientService.update_profile_photo(session, patient, file_data, file.content_type or "image/jpeg")
    await session.commit()
    await session.refresh(updated)
    return PatientResponse.model_validate(updated)


@router.get(
    "/{patient_id}/profile-photo",
    summary="Download patient profile photo",
    description=(
        "Serve the stored profile photo for a patient as a direct binary download. "
        "Returns 404 when no photo has been uploaded."
    ),
    response_description="Binary image download.",
    responses={
        200: {"description": "Binary image file."},
        404: {"description": "No profile photo found for this patient."},
    },
)
async def get_patient_profile_photo(
    patient_id: int,
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Serve the patient profile photo."""
    patient = await PatientService.require_patient(session, patient_id)
    photo_ref = patient.profile_photo_url

    if not photo_ref:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No profile photo found for this patient.")

    try:
        download = PatientStorage().resolve_profile_photo_download(photo_ref)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Profile photo file not found.") from exc

    if download.path is not None:
        return FileResponse(path=download.path, media_type=download.content_type, filename=download.filename)
    if download.stream is not None:
        return StreamingResponse(
            download.stream,
            media_type=download.content_type,
            headers={"Content-Disposition": f'inline; filename="{download.filename}"'},
        )
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Profile photo could not be resolved.")


@router.delete(
    "/{patient_id}",
    response_model=PatientMessageResponse,
    summary="Inactivate a patient",
    description=INACTIVATE_PATIENT_DESCRIPTION,
    response_description="A confirmation message explaining that the patient was inactivated.",
    responses={**PATIENT_DELETE_RESPONSE_DOC, **PATIENT_DELETE_RESPONSES},
)
async def inactivate_patient(
    patient_id: int,
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Inactivate patient and keep retention metadata."""
    patient = await PatientService.require_patient(session, patient_id)
    await PatientService.inactivate_patient(session, patient)
    await session.commit()
    return {"message": "Patient inactivated successfully"}


@router.post(
    "/{patient_id}/reactivate",
    response_model=PatientResponse,
    summary="Reactivate a patient",
    description=REACTIVATE_PATIENT_DESCRIPTION,
    response_description="The patient after the reactivation is applied.",
    responses={**PATIENT_RESPONSE_DOC, **PATIENT_REACTIVATE_RESPONSES},
)
async def reactivate_patient(
    patient_id: int,
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Reactivate previously inactivated patient."""
    patient = await PatientService.require_patient(session, patient_id)
    updated = await PatientService.reactivate_patient(session, patient)
    await session.commit()
    await session.refresh(updated)
    return PatientResponse.model_validate(updated)

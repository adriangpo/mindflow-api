"""Patient router (API endpoints)."""

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.encoders import jsonable_encoder
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
from .schemas import (
    PatientCompleteRegistrationRequest,
    PatientCreateRequest,
    PatientListResponse,
    PatientProfilePhotoUpdateRequest,
    PatientQuickCreateRequest,
    PatientResponse,
    PatientUpdateRequest,
)
from .service import PatientService, is_patient_cpf_unique_violation

router = APIRouter(
    prefix="/patients",
    tags=["Patient Management"],
    dependencies=[Depends(require_role(UserRole.TENANT_OWNER))],
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
        "profile_photo_url": update_data.get("profile_photo_url", patient.profile_photo_url),
        "initial_record": update_data.get("initial_record", patient.initial_record),
    }


@router.post("", response_model=PatientResponse)
async def create_patient(
    data: PatientCreateRequest,
    _: User = Depends(require_tenant_membership),
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


@router.post("/quick-register", response_model=PatientResponse)
async def quick_register_patient(
    data: PatientQuickCreateRequest,
    _: User = Depends(require_tenant_membership),
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Create patient with name only for first consultation registration."""
    patient = await PatientService.create_quick_patient(session, data)
    await session.commit()
    await session.refresh(patient)
    return PatientResponse.model_validate(patient)


@router.get("", response_model=PatientListResponse)
async def list_patients(
    pagination: PaginationParams = Depends(),
    search: str | None = Query(default=None, min_length=1, max_length=255),
    active_only: bool = Query(default=True),
    is_registered: bool | None = Query(default=None),
    _: User = Depends(require_tenant_membership),
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """List patients from tenant with search and status filters."""
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


@router.get("/{patient_id}", response_model=PatientResponse)
async def get_patient(
    patient_id: int,
    _: User = Depends(require_tenant_membership),
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Get patient by id."""
    patient = await PatientService.require_patient(session, patient_id)
    return PatientResponse.model_validate(patient)


@router.post("/{patient_id}/export/pdf", response_model=ExportJobResponse, status_code=status.HTTP_202_ACCEPTED)
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


@router.put("/{patient_id}", response_model=PatientResponse)
async def update_patient(
    patient_id: int,
    data: PatientUpdateRequest,
    _: User = Depends(require_tenant_membership),
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


@router.post("/{patient_id}/complete-registration", response_model=PatientResponse)
async def complete_patient_registration(
    patient_id: int,
    data: PatientCompleteRegistrationRequest,
    _: User = Depends(require_tenant_membership),
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


@router.patch("/{patient_id}/profile-photo", response_model=PatientResponse)
async def update_patient_profile_photo(
    patient_id: int,
    data: PatientProfilePhotoUpdateRequest,
    _: User = Depends(require_tenant_membership),
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Update patient profile photo URL."""
    patient = await PatientService.require_patient(session, patient_id)
    updated = await PatientService.update_profile_photo(
        session,
        patient,
        str(data.profile_photo_url) if data.profile_photo_url is not None else None,
    )
    await session.commit()
    await session.refresh(updated)
    return PatientResponse.model_validate(updated)


@router.delete("/{patient_id}")
async def inactivate_patient(
    patient_id: int,
    _: User = Depends(require_tenant_membership),
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Inactivate patient and keep retention metadata."""
    patient = await PatientService.require_patient(session, patient_id)
    await PatientService.inactivate_patient(session, patient)
    await session.commit()
    return {"message": "Patient inactivated successfully"}


@router.post("/{patient_id}/reactivate", response_model=PatientResponse)
async def reactivate_patient(
    patient_id: int,
    _: User = Depends(require_tenant_membership),
    session: AsyncSession = Depends(get_tenant_db_session),
):
    """Reactivate previously inactivated patient."""
    patient = await PatientService.require_patient(session, patient_id)
    updated = await PatientService.reactivate_patient(session, patient)
    await session.commit()
    await session.refresh(updated)
    return PatientResponse.model_validate(updated)

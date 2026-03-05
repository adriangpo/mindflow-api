"""Patient service layer."""

from datetime import UTC, datetime

from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from src.shared.pagination.pagination import PaginationParams

from .exceptions import (
    PatientAlreadyActive,
    PatientAlreadyInactive,
    PatientAlreadyRegistered,
    PatientCpfAlreadyExists,
    PatientNotFound,
)
from .models import Patient
from .schemas import (
    PatientCompleteRegistrationRequest,
    PatientCreateRequest,
    PatientQuickCreateRequest,
    PatientUpdateRequest,
)

TENANT_CPF_UNIQUE_CONSTRAINT = "uq_patient_tenant_cpf"


def is_patient_cpf_unique_violation(exc: IntegrityError) -> bool:
    """Check whether IntegrityError came from tenant CPF unique constraint."""
    diag = getattr(getattr(exc, "orig", None), "diag", None)
    constraint_name = getattr(diag, "constraint_name", None)
    if constraint_name == TENANT_CPF_UNIQUE_CONSTRAINT:
        return True

    return TENANT_CPF_UNIQUE_CONSTRAINT in str(getattr(exc, "orig", exc))


class PatientService:
    """Service for patient operations."""

    @staticmethod
    def _require_tenant_id(session: AsyncSession):
        """Return tenant_id from session context or raise if missing."""
        tenant_id = session.info.get("tenant_id")
        if tenant_id is None:
            raise RuntimeError("Tenant context is required for patient operations")
        return tenant_id

    @staticmethod
    def _add_years(dt: datetime, years: int) -> datetime:
        """Safely add years to a datetime, handling leap-day edge cases."""
        try:
            return dt.replace(year=dt.year + years)
        except ValueError:
            return dt.replace(month=2, day=28, year=dt.year + years)

    @staticmethod
    async def _ensure_cpf_available(
        session: AsyncSession,
        cpf: str | None,
        *,
        exclude_patient_id: int | None = None,
    ) -> None:
        """Ensure CPF is unique for the current tenant."""
        if cpf is None:
            return

        tenant_id = PatientService._require_tenant_id(session)
        stmt = select(Patient).where(
            Patient.tenant_id == tenant_id,
            Patient.cpf == cpf,
        )
        if exclude_patient_id is not None:
            stmt = stmt.where(Patient.id != exclude_patient_id)

        result = await session.execute(stmt)
        if result.scalar_one_or_none() is not None:
            raise PatientCpfAlreadyExists()

    @staticmethod
    def _apply_filters(
        stmt,
        *,
        tenant_id,
        search: str | None,
        is_active: bool | None,
        is_registered: bool | None,
    ):
        """Apply tenant and list filters to a patient statement."""
        stmt = stmt.where(Patient.tenant_id == tenant_id)

        if is_active is not None:
            stmt = stmt.where(Patient.is_active == is_active)

        if is_registered is not None:
            stmt = stmt.where(Patient.is_registered == is_registered)

        if search:
            search_pattern = f"%{search.strip()}%"
            stmt = stmt.where(
                or_(
                    Patient.full_name.ilike(search_pattern),
                    Patient.cpf.ilike(search_pattern),
                    Patient.phone_number.ilike(search_pattern),
                )
            )

        return stmt

    @staticmethod
    async def create_patient(
        session: AsyncSession,
        data: PatientCreateRequest,
    ) -> Patient:
        """Create a fully registered patient."""
        tenant_id = PatientService._require_tenant_id(session)
        await PatientService._ensure_cpf_available(session, data.cpf)

        patient = Patient(
            tenant_id=tenant_id,
            full_name=data.full_name,
            birth_date=data.birth_date,
            cpf=data.cpf,
            cep=data.cep,
            phone_number=data.phone_number,
            session_price=data.session_price,
            session_frequency=data.session_frequency,
            first_session_date=data.first_session_date,
            guardian_name=data.guardian_name,
            guardian_phone=data.guardian_phone,
            profile_photo_url=str(data.profile_photo_url) if data.profile_photo_url is not None else None,
            initial_record=data.initial_record,
            is_registered=True,
            is_active=True,
        )
        session.add(patient)
        return patient

    @staticmethod
    async def create_quick_patient(
        session: AsyncSession,
        data: PatientQuickCreateRequest,
    ) -> Patient:
        """Create a quick-registration patient with minimum required data."""
        tenant_id = PatientService._require_tenant_id(session)
        patient = Patient(
            tenant_id=tenant_id,
            full_name=data.full_name,
            is_registered=False,
            is_active=True,
        )
        session.add(patient)
        return patient

    @staticmethod
    async def get_patient(session: AsyncSession, patient_id: int) -> Patient | None:
        """Get patient by id in current tenant."""
        tenant_id = PatientService._require_tenant_id(session)
        stmt = select(Patient).where(
            Patient.id == patient_id,
            Patient.tenant_id == tenant_id,
        )
        result = await session.execute(stmt)
        return result.scalar_one_or_none()

    @staticmethod
    async def require_patient(session: AsyncSession, patient_id: int) -> Patient:
        """Get patient by id or raise not found."""
        patient = await PatientService.get_patient(session, patient_id)
        if patient is None:
            raise PatientNotFound()
        return patient

    @staticmethod
    async def list_patients(
        session: AsyncSession,
        pagination: PaginationParams,
        *,
        search: str | None = None,
        is_active: bool | None = True,
        is_registered: bool | None = None,
    ) -> tuple[list[Patient], int]:
        """List patients from current tenant with optional filters."""
        tenant_id = PatientService._require_tenant_id(session)

        count_stmt = select(func.count()).select_from(Patient)
        count_stmt = PatientService._apply_filters(
            count_stmt,
            tenant_id=tenant_id,
            search=search,
            is_active=is_active,
            is_registered=is_registered,
        )

        stmt = select(Patient).order_by(Patient.created_at.desc(), Patient.id.desc())
        stmt = PatientService._apply_filters(
            stmt,
            tenant_id=tenant_id,
            search=search,
            is_active=is_active,
            is_registered=is_registered,
        )

        total_result = await session.execute(count_stmt)
        total = total_result.scalar_one()

        if pagination.is_paginated:
            stmt = stmt.offset(pagination.skip).limit(pagination.limit)

        result = await session.execute(stmt)
        items = list(result.scalars().all())
        return items, total

    @staticmethod
    async def update_patient(
        session: AsyncSession,
        patient: Patient,
        data: PatientUpdateRequest,
    ) -> Patient:
        """Update patient data."""
        updates = data.model_dump(exclude_unset=True)

        if "cpf" in updates and updates["cpf"] != patient.cpf:
            await PatientService._ensure_cpf_available(session, updates["cpf"], exclude_patient_id=patient.id)

        if "profile_photo_url" in updates and updates["profile_photo_url"] is not None:
            updates["profile_photo_url"] = str(updates["profile_photo_url"])

        for key, value in updates.items():
            setattr(patient, key, value)

        await session.flush()
        return patient

    @staticmethod
    async def complete_registration(
        session: AsyncSession,
        patient: Patient,
        data: PatientCompleteRegistrationRequest,
    ) -> Patient:
        """Complete quick-registration with all required patient data."""
        if patient.is_registered:
            raise PatientAlreadyRegistered()

        if data.cpf != patient.cpf:
            await PatientService._ensure_cpf_available(session, data.cpf, exclude_patient_id=patient.id)

        patient.full_name = data.full_name
        patient.birth_date = data.birth_date
        patient.cpf = data.cpf
        patient.cep = data.cep
        patient.phone_number = data.phone_number
        patient.session_price = data.session_price
        patient.session_frequency = data.session_frequency
        patient.first_session_date = data.first_session_date
        patient.guardian_name = data.guardian_name
        patient.guardian_phone = data.guardian_phone
        patient.profile_photo_url = str(data.profile_photo_url) if data.profile_photo_url is not None else None
        patient.initial_record = data.initial_record
        patient.is_registered = True
        patient.is_active = True

        await session.flush()
        return patient

    @staticmethod
    async def update_profile_photo(
        session: AsyncSession,
        patient: Patient,
        profile_photo_url: str | None,
    ) -> Patient:
        """Update patient profile photo URL."""
        patient.profile_photo_url = profile_photo_url
        await session.flush()
        return patient

    @staticmethod
    async def inactivate_patient(session: AsyncSession, patient: Patient) -> Patient:
        """Inactivate a patient and set retention deadline."""
        if not patient.is_active:
            raise PatientAlreadyInactive()

        now = datetime.now(UTC)
        patient.is_active = False
        patient.inactivated_at = now
        patient.retention_expires_at = PatientService._add_years(now, 5)
        await session.flush()
        return patient

    @staticmethod
    async def reactivate_patient(session: AsyncSession, patient: Patient) -> Patient:
        """Reactivate an inactive patient."""
        if patient.is_active:
            raise PatientAlreadyActive()

        patient.is_active = True
        patient.inactivated_at = None
        patient.retention_expires_at = None
        await session.flush()
        return patient

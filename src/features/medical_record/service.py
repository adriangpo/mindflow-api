"""Medical record service layer."""

from datetime import UTC, date, datetime

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.features.patient.models import Patient
from src.features.schedule.models import ScheduleAppointment
from src.shared.pagination.pagination import PaginationParams
from src.shared.pdf import build_pdf_from_template
from src.shared.storage import StoredFile

from .exceptions import (
    MedicalRecordAppointmentNotFound,
    MedicalRecordAppointmentPatientMismatch,
    MedicalRecordExportEmpty,
    MedicalRecordNotFound,
    MedicalRecordPatientNotFound,
)
from .models import MedicalRecord
from .schemas import MedicalRecordCreateRequest, MedicalRecordUpdateRequest
from .storage import MedicalRecordStorage


def _fmt_datetime(value: datetime | None) -> str:
    """Format a datetime for template rendering."""
    if value is None:
        return ""
    return value.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC")


def _record_context(record: MedicalRecord, patient_name: str) -> dict:
    """Build template context dict for one medical record."""
    return {
        "id": record.id,
        "patient_name": patient_name,
        "recorded_at_fmt": _fmt_datetime(record.recorded_at),
        "title": record.title or "",
        "content": record.content,
        "clinical_assessment": record.clinical_assessment or "",
        "treatment_plan": record.treatment_plan or "",
        "attachments": record.attachments or [],
    }


class MedicalRecordService:
    """Service for medical record operations."""

    @staticmethod
    def _require_tenant_id(session: AsyncSession):
        tenant_id = session.info.get("tenant_id")
        if tenant_id is None:
            raise RuntimeError("Tenant context is required for medical record operations")
        return tenant_id

    @staticmethod
    async def _require_patient(session: AsyncSession, patient_id: int) -> Patient:
        tenant_id = MedicalRecordService._require_tenant_id(session)
        stmt = select(Patient).where(
            Patient.id == patient_id,
            Patient.tenant_id == tenant_id,
        )
        result = await session.execute(stmt)
        patient = result.scalar_one_or_none()
        if patient is None:
            raise MedicalRecordPatientNotFound()
        return patient

    @staticmethod
    async def _require_appointment(session: AsyncSession, appointment_id: int) -> ScheduleAppointment:
        tenant_id = MedicalRecordService._require_tenant_id(session)
        stmt = select(ScheduleAppointment).where(
            ScheduleAppointment.id == appointment_id,
            ScheduleAppointment.tenant_id == tenant_id,
            ScheduleAppointment.is_deleted.is_(False),
        )
        result = await session.execute(stmt)
        appointment = result.scalar_one_or_none()
        if appointment is None:
            raise MedicalRecordAppointmentNotFound()
        return appointment

    @staticmethod
    async def _require_record(session: AsyncSession, record_id: int) -> MedicalRecord:
        record = await MedicalRecordService.get_record(session, record_id)
        if record is None:
            raise MedicalRecordNotFound()
        return record

    @staticmethod
    def _serialize_attachments(attachments) -> list[str]:
        if attachments is None:
            return []
        return [str(url) for url in attachments]

    @staticmethod
    async def create_record(
        session: AsyncSession,
        user_id: int,
        data: MedicalRecordCreateRequest,
    ) -> MedicalRecord:
        """Create a tenant-scoped medical record."""
        tenant_id = MedicalRecordService._require_tenant_id(session)
        await MedicalRecordService._require_patient(session, data.patient_id)

        if data.appointment_id is not None:
            appointment = await MedicalRecordService._require_appointment(session, data.appointment_id)
            if appointment.patient_id != data.patient_id:
                raise MedicalRecordAppointmentPatientMismatch()

        record = MedicalRecord(
            tenant_id=tenant_id,
            patient_id=data.patient_id,
            appointment_id=data.appointment_id,
            recorded_by_user_id=user_id,
            recorded_at=data.recorded_at or datetime.now(UTC),
            title=data.title,
            content=data.content,
            clinical_assessment=data.clinical_assessment,
            treatment_plan=data.treatment_plan,
            attachments=MedicalRecordService._serialize_attachments(data.attachments),
        )
        session.add(record)
        await session.flush()
        return record

    @staticmethod
    def _apply_filters(
        stmt,
        *,
        tenant_id,
        patient_id: int | None,
        appointment_id: int | None,
        search: str | None,
        start_date: date | None,
        end_date: date | None,
    ):
        """Apply list filters to a medical record statement."""
        stmt = stmt.where(MedicalRecord.tenant_id == tenant_id)

        if patient_id is not None:
            stmt = stmt.where(MedicalRecord.patient_id == patient_id)

        if appointment_id is not None:
            stmt = stmt.where(MedicalRecord.appointment_id == appointment_id)

        if search:
            search_pattern = f"%{search.strip()}%"
            stmt = stmt.where(
                or_(
                    MedicalRecord.title.ilike(search_pattern),
                    MedicalRecord.content.ilike(search_pattern),
                    MedicalRecord.clinical_assessment.ilike(search_pattern),
                    MedicalRecord.treatment_plan.ilike(search_pattern),
                )
            )

        if start_date is not None:
            stmt = stmt.where(func.date(MedicalRecord.recorded_at) >= start_date)

        if end_date is not None:
            stmt = stmt.where(func.date(MedicalRecord.recorded_at) <= end_date)

        return stmt

    @staticmethod
    async def list_records(
        session: AsyncSession,
        pagination: PaginationParams,
        *,
        patient_id: int | None = None,
        appointment_id: int | None = None,
        search: str | None = None,
        start_date: date | None = None,
        end_date: date | None = None,
    ) -> tuple[list[MedicalRecord], int]:
        """List medical records in the current tenant."""
        tenant_id = MedicalRecordService._require_tenant_id(session)

        count_stmt = select(func.count()).select_from(MedicalRecord)
        count_stmt = MedicalRecordService._apply_filters(
            count_stmt,
            tenant_id=tenant_id,
            patient_id=patient_id,
            appointment_id=appointment_id,
            search=search,
            start_date=start_date,
            end_date=end_date,
        )

        stmt = select(MedicalRecord).order_by(MedicalRecord.recorded_at.desc(), MedicalRecord.id.desc())
        stmt = MedicalRecordService._apply_filters(
            stmt,
            tenant_id=tenant_id,
            patient_id=patient_id,
            appointment_id=appointment_id,
            search=search,
            start_date=start_date,
            end_date=end_date,
        )

        total_result = await session.execute(count_stmt)
        total = total_result.scalar_one()

        if pagination.is_paginated:
            stmt = stmt.offset(pagination.skip).limit(pagination.limit)

        result = await session.execute(stmt)
        records = list(result.scalars().all())
        return records, total

    @staticmethod
    async def get_record(session: AsyncSession, record_id: int) -> MedicalRecord | None:
        """Get medical record by id in tenant scope."""
        tenant_id = MedicalRecordService._require_tenant_id(session)
        stmt = select(MedicalRecord).where(
            MedicalRecord.id == record_id,
            MedicalRecord.tenant_id == tenant_id,
        )
        result = await session.execute(stmt)
        return result.scalar_one_or_none()

    @staticmethod
    async def update_record(
        session: AsyncSession,
        record: MedicalRecord,
        data: MedicalRecordUpdateRequest,
        attachment_paths: list[str] | None = None,
    ) -> MedicalRecord:
        """Update an existing medical record.

        When attachment_paths is provided it replaces the attachments field entirely,
        ignoring any attachments value that may be present in the schema data.
        """
        updates = data.model_dump(exclude_unset=True)

        if attachment_paths is not None:
            updates["attachments"] = attachment_paths
        elif "attachments" in updates:
            updates["attachments"] = MedicalRecordService._serialize_attachments(updates["attachments"])

        target_patient_id = updates.get("patient_id", record.patient_id)

        if "patient_id" in updates and updates["patient_id"] != record.patient_id:
            await MedicalRecordService._require_patient(session, updates["patient_id"])

        if "appointment_id" in updates:
            if updates["appointment_id"] is not None:
                appointment = await MedicalRecordService._require_appointment(session, updates["appointment_id"])
                if appointment.patient_id != target_patient_id:
                    raise MedicalRecordAppointmentPatientMismatch()
        elif "patient_id" in updates and record.appointment_id is not None:
            appointment = await MedicalRecordService._require_appointment(session, record.appointment_id)
            if appointment.patient_id != target_patient_id:
                raise MedicalRecordAppointmentPatientMismatch()

        for key, value in updates.items():
            setattr(record, key, value)

        await session.flush()
        return record

    @staticmethod
    async def get_patient_history(
        session: AsyncSession,
        patient_id: int,
        pagination: PaginationParams,
    ) -> tuple[list[MedicalRecord], int]:
        """Get consultation record history for a single patient."""
        await MedicalRecordService._require_patient(session, patient_id)
        return await MedicalRecordService.list_records(
            session=session,
            pagination=pagination,
            patient_id=patient_id,
        )

    @staticmethod
    async def require_record(session: AsyncSession, record_id: int) -> MedicalRecord:
        """Get medical record by id or raise not found."""
        return await MedicalRecordService._require_record(session, record_id)

    @staticmethod
    async def validate_record_export(session: AsyncSession, record_id: int) -> None:
        """Validate that a single-record export can be queued."""
        await MedicalRecordService.require_record(session, record_id)

    @staticmethod
    async def validate_patient_history_export(session: AsyncSession, patient_id: int) -> None:
        """Validate that a patient-history export can be queued."""
        await MedicalRecordService._require_patient(session, patient_id)
        tenant_id = MedicalRecordService._require_tenant_id(session)
        result = await session.execute(
            select(MedicalRecord.id)
            .where(
                MedicalRecord.tenant_id == tenant_id,
                MedicalRecord.patient_id == patient_id,
            )
            .limit(1)
        )
        if result.scalar_one_or_none() is None:
            raise MedicalRecordExportEmpty()

    @staticmethod
    async def validate_all_records_export(session: AsyncSession) -> None:
        """Validate that an all-records export can be queued."""
        tenant_id = MedicalRecordService._require_tenant_id(session)
        result = await session.execute(select(MedicalRecord.id).where(MedicalRecord.tenant_id == tenant_id).limit(1))
        if result.scalar_one_or_none() is None:
            raise MedicalRecordExportEmpty()

    @staticmethod
    async def _patient_name_map(session: AsyncSession, patient_ids: set[int]) -> dict[int, str]:
        """Build a patient id -> full name map for export output."""
        if not patient_ids:
            return {}

        tenant_id = MedicalRecordService._require_tenant_id(session)
        stmt = select(Patient.id, Patient.full_name).where(
            Patient.tenant_id == tenant_id,
            Patient.id.in_(patient_ids),
        )
        result = await session.execute(stmt)
        return dict(result.tuples().all())

    @staticmethod
    async def export_record_pdf(session: AsyncSession, record_id: int) -> StoredFile:
        """Export a single medical record and store the generated PDF."""
        record = await MedicalRecordService.require_record(session, record_id)
        tenant_id = MedicalRecordService._require_tenant_id(session)
        names = await MedicalRecordService._patient_name_map(session, {record.patient_id})
        patient_name = names.get(record.patient_id, f"Paciente #{record.patient_id}")

        context = {
            "report_title": "Exportação de Prontuário",
            "header_subtitle": f"Consulta Individual — {patient_name}",
            "patient_name": patient_name,
            "records": [_record_context(record, patient_name)],
            "generated_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
        }
        pdf_bytes = build_pdf_from_template("medical_record_export.html", context)
        return MedicalRecordStorage().store_single_record_export(tenant_id, record.id, pdf_bytes)

    @staticmethod
    async def export_patient_history_pdf(session: AsyncSession, patient_id: int) -> StoredFile:
        """Export all records of one patient and store the generated PDF."""
        patient = await MedicalRecordService._require_patient(session, patient_id)
        tenant_id = MedicalRecordService._require_tenant_id(session)

        stmt = (
            select(MedicalRecord)
            .where(
                MedicalRecord.tenant_id == tenant_id,
                MedicalRecord.patient_id == patient_id,
            )
            .order_by(MedicalRecord.recorded_at.desc(), MedicalRecord.id.desc())
        )
        result = await session.execute(stmt)
        records = list(result.scalars().all())

        if not records:
            raise MedicalRecordExportEmpty()

        context = {
            "report_title": "Histórico de Prontuários",
            "header_subtitle": patient.full_name,
            "patient_name": patient.full_name,
            "records": [_record_context(r, patient.full_name) for r in records],
            "generated_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
        }
        pdf_bytes = build_pdf_from_template("medical_record_export.html", context)
        return MedicalRecordStorage().store_patient_history_export(tenant_id, patient_id, pdf_bytes)

    @staticmethod
    async def export_all_records_pdf(session: AsyncSession) -> StoredFile:
        """Export all tenant medical records and store the generated PDF."""
        tenant_id = MedicalRecordService._require_tenant_id(session)
        stmt = (
            select(MedicalRecord)
            .where(MedicalRecord.tenant_id == tenant_id)
            .order_by(MedicalRecord.recorded_at.desc(), MedicalRecord.id.desc())
        )
        result = await session.execute(stmt)
        records = list(result.scalars().all())

        if not records:
            raise MedicalRecordExportEmpty()

        names = await MedicalRecordService._patient_name_map(session, {r.patient_id for r in records})

        context = {
            "report_title": "Exportação de Prontuários — Todos os Pacientes",
            "header_subtitle": "Histórico Completo de Registros",
            "patient_name": None,
            "records": [_record_context(r, names.get(r.patient_id, f"Paciente #{r.patient_id}")) for r in records],
            "generated_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
        }
        pdf_bytes = build_pdf_from_template("medical_record_export.html", context)
        return MedicalRecordStorage().store_all_records_export(tenant_id, pdf_bytes)

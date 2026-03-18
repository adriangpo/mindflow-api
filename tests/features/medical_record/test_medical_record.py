"""Tests for medical record feature."""

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from uuid import UUID

import pytest
from fastapi import status

from src.features.auth.dependencies import get_current_active_user, get_current_user
from src.features.medical_record.exceptions import (
    MedicalRecordAppointmentNotFound,
    MedicalRecordAppointmentPatientMismatch,
    MedicalRecordExportEmpty,
    MedicalRecordNotFound,
    MedicalRecordPatientNotFound,
)
from src.features.medical_record.schemas import MedicalRecordCreateRequest, MedicalRecordUpdateRequest
from src.features.medical_record.service import MedicalRecordService
from src.features.patient.schemas import PatientCreateRequest
from src.features.patient.service import PatientService
from src.features.schedule.models import ScheduleAppointment
from src.features.user.models import UserRole
from src.main import app
from src.shared.pagination.pagination import PaginationParams


def _tenant_id_from_client(client) -> UUID:
    """Extract tenant UUID from test client default headers."""
    tenant_id_header = client.headers.get("X-Tenant-ID")
    assert tenant_id_header is not None
    return UUID(tenant_id_header)


async def _create_patient(session, *, cpf: str, full_name: str = "Paciente Prontuario"):
    """Create a tenant-scoped patient for tests."""
    patient = await PatientService.create_patient(
        session,
        PatientCreateRequest(
            full_name=full_name,
            birth_date=datetime(1992, 1, 10, tzinfo=UTC).date(),
            cpf=cpf,
            cep="19900000",
            phone_number="14999999999",
            session_price=Decimal("200.00"),
            session_frequency="weekly",
        ),
    )
    await session.flush()
    return patient


async def _create_appointment(session, *, user_id: int, patient_id: int):
    """Create a minimal appointment record for linkage tests."""
    tenant_id = session.info["tenant_id"]
    starts_at = datetime.now(UTC) + timedelta(days=1)
    appointment = ScheduleAppointment(
        tenant_id=tenant_id,
        patient_id=patient_id,
        schedule_configuration_id=None,
        created_by_user_id=user_id,
        starts_at=starts_at,
        ends_at=starts_at + timedelta(minutes=50),
        modality="online",
        status="scheduled",
        payment_status="pending",
        charge_amount=Decimal("200.00"),
    )
    session.add(appointment)
    await session.flush()
    return appointment


def _record_payload(*, patient_id: int, appointment_id: int | None = None, content: str = "Clinical notes"):
    payload = {
        "patient_id": patient_id,
        "content": content,
        "clinical_assessment": "Patient stable",
        "treatment_plan": "Weekly follow-up",
        "attachments": ["https://example.com/anamnese.pdf"],
    }
    if appointment_id is not None:
        payload["appointment_id"] = appointment_id
    return payload


class TestMedicalRecordService:
    """Service-layer tests for medical record operations."""

    async def test_create_record_success(self, session, make_user):
        user = await make_user()
        patient = await _create_patient(session, cpf="52998224725")

        record = await MedicalRecordService.create_record(
            session,
            user.id,
            MedicalRecordCreateRequest(
                patient_id=patient.id,
                content="Initial consultation notes",
                clinical_assessment="Mild anxiety",
                treatment_plan="Cognitive therapy",
                attachments=["https://example.com/record-1.pdf"],
            ),
        )
        await session.commit()
        await session.refresh(record)

        assert record.patient_id == patient.id
        assert record.recorded_by_user_id == user.id
        assert record.content == "Initial consultation notes"
        assert record.attachments == ["https://example.com/record-1.pdf"]

    async def test_create_record_with_mismatched_appointment_raises_conflict(self, session, make_user):
        user = await make_user()
        patient_1 = await _create_patient(session, cpf="11144477735", full_name="Paciente Um")
        patient_2 = await _create_patient(session, cpf="39053344705", full_name="Paciente Dois")
        appointment = await _create_appointment(session, user_id=user.id, patient_id=patient_2.id)

        with pytest.raises(MedicalRecordAppointmentPatientMismatch):
            await MedicalRecordService.create_record(
                session,
                user.id,
                MedicalRecordCreateRequest(
                    patient_id=patient_1.id,
                    appointment_id=appointment.id,
                    content="This should fail",
                ),
            )

    async def test_create_record_with_unknown_patient_raises_not_found(self, session, make_user):
        user = await make_user()

        with pytest.raises(MedicalRecordPatientNotFound):
            await MedicalRecordService.create_record(
                session,
                user.id,
                MedicalRecordCreateRequest(
                    patient_id=999999,
                    content="Unknown patient should fail",
                ),
            )

    async def test_create_record_with_deleted_appointment_raises_not_found(self, session, make_user):
        user = await make_user()
        patient = await _create_patient(session, cpf="69542144342", full_name="Paciente Agenda")
        appointment = await _create_appointment(session, user_id=user.id, patient_id=patient.id)
        appointment.is_deleted = True
        await session.flush()

        with pytest.raises(MedicalRecordAppointmentNotFound):
            await MedicalRecordService.create_record(
                session,
                user.id,
                MedicalRecordCreateRequest(
                    patient_id=patient.id,
                    appointment_id=appointment.id,
                    content="Deleted appointment should fail",
                ),
            )

    async def test_get_patient_history_returns_only_patient_records(self, session, make_user):
        user = await make_user()
        patient_1 = await _create_patient(session, cpf="41547287411", full_name="Paciente Historico")
        patient_2 = await _create_patient(session, cpf="16899535009", full_name="Paciente Outro")

        await MedicalRecordService.create_record(
            session,
            user.id,
            MedicalRecordCreateRequest(patient_id=patient_1.id, content="Record A"),
        )
        await MedicalRecordService.create_record(
            session,
            user.id,
            MedicalRecordCreateRequest(patient_id=patient_2.id, content="Record B"),
        )
        await session.commit()

        records, total = await MedicalRecordService.get_patient_history(
            session,
            patient_id=patient_1.id,
            pagination=PaginationParams(page=1, page_size=10),
        )

        assert total == 1
        assert len(records) == 1
        assert records[0].patient_id == patient_1.id

    async def test_list_records_with_search_date_and_appointment_filters(self, session, make_user):
        user = await make_user()
        patient = await _create_patient(session, cpf="52998224725", full_name="Paciente Filtro")
        other_patient = await _create_patient(session, cpf="39053344705", full_name="Paciente Outro")
        appointment = await _create_appointment(session, user_id=user.id, patient_id=patient.id)

        await MedicalRecordService.create_record(
            session,
            user.id,
            MedicalRecordCreateRequest(
                patient_id=patient.id,
                appointment_id=appointment.id,
                recorded_at=datetime.now(UTC) - timedelta(days=1),
                title="Consulta de ansiedade",
                content="Paciente relatou ansiedade social",
            ),
        )
        await MedicalRecordService.create_record(
            session,
            user.id,
            MedicalRecordCreateRequest(
                patient_id=other_patient.id,
                recorded_at=datetime.now(UTC) - timedelta(days=7),
                title="Consulta antiga",
                content="Sem relacao com filtro",
            ),
        )
        await session.commit()

        records, total = await MedicalRecordService.list_records(
            session,
            pagination=PaginationParams(page=1, page_size=10),
            patient_id=patient.id,
            appointment_id=appointment.id,
            search="ansiedade",
            start_date=(datetime.now(UTC) - timedelta(days=2)).date(),
            end_date=datetime.now(UTC).date(),
        )

        assert total == 1
        assert len(records) == 1
        assert records[0].patient_id == patient.id
        assert records[0].appointment_id == appointment.id

    async def test_update_record_patient_change_checks_existing_appointment_consistency(self, session, make_user):
        user = await make_user()
        patient_1 = await _create_patient(session, cpf="64351919051", full_name="Paciente Um")
        patient_2 = await _create_patient(session, cpf="41547287411", full_name="Paciente Dois")
        appointment = await _create_appointment(session, user_id=user.id, patient_id=patient_1.id)
        record = await MedicalRecordService.create_record(
            session,
            user.id,
            MedicalRecordCreateRequest(
                patient_id=patient_1.id,
                appointment_id=appointment.id,
                content="Registro inicial",
            ),
        )
        await session.flush()

        with pytest.raises(MedicalRecordAppointmentPatientMismatch):
            await MedicalRecordService.update_record(
                session,
                record,
                MedicalRecordUpdateRequest(patient_id=patient_2.id),
            )

    async def test_update_record_can_unlink_appointment(self, session, make_user):
        user = await make_user()
        patient = await _create_patient(session, cpf="52998224725", full_name="Paciente V")
        appointment = await _create_appointment(session, user_id=user.id, patient_id=patient.id)
        record = await MedicalRecordService.create_record(
            session,
            user.id,
            MedicalRecordCreateRequest(
                patient_id=patient.id,
                appointment_id=appointment.id,
                content="Registro para desvincular",
            ),
        )
        await session.flush()

        updated = await MedicalRecordService.update_record(
            session,
            record,
            MedicalRecordUpdateRequest(appointment_id=None),
        )
        await session.commit()

        assert updated.appointment_id is None

    async def test_update_record_with_mismatched_appointment_raises_conflict(self, session, make_user):
        user = await make_user()
        patient_1 = await _create_patient(session, cpf="11144477735", full_name="Paciente Um")
        patient_2 = await _create_patient(session, cpf="39053344705", full_name="Paciente Dois")
        appointment = await _create_appointment(session, user_id=user.id, patient_id=patient_2.id)
        record = await MedicalRecordService.create_record(
            session,
            user.id,
            MedicalRecordCreateRequest(
                patient_id=patient_1.id,
                content="Registro inicial",
            ),
        )
        await session.flush()

        with pytest.raises(MedicalRecordAppointmentPatientMismatch):
            await MedicalRecordService.update_record(
                session,
                record,
                MedicalRecordUpdateRequest(appointment_id=appointment.id),
            )

    async def test_update_record_with_null_attachments_clears_list(self, session, make_user):
        user = await make_user()
        patient = await _create_patient(session, cpf="41547287411", full_name="Paciente Anexo")
        record = await MedicalRecordService.create_record(
            session,
            user.id,
            MedicalRecordCreateRequest(
                patient_id=patient.id,
                content="Registro com anexo",
                attachments=["https://example.com/arquivo.pdf"],
            ),
        )
        await session.flush()

        updated = await MedicalRecordService.update_record(
            session,
            record,
            MedicalRecordUpdateRequest(attachments=None),
        )
        await session.commit()

        assert updated.attachments == []

    async def test_require_record_raises_not_found(self, session):
        with pytest.raises(MedicalRecordNotFound):
            await MedicalRecordService.require_record(session, record_id=999999)

    async def test_export_single_record_generates_pdf(self, session, make_user, isolated_storage_root):
        user = await make_user()
        patient = await _create_patient(session, cpf="69542144342")
        record = await MedicalRecordService.create_record(
            session,
            user.id,
            MedicalRecordCreateRequest(patient_id=patient.id, content="Record for export"),
        )
        await session.commit()

        assert not isolated_storage_root.exists()

        stored_file = await MedicalRecordService.export_record_pdf(session, record.id)

        assert stored_file.filename == f"medical-record-{record.id}.pdf"
        assert stored_file.path.exists()
        assert stored_file.path.read_bytes().startswith(b"%PDF-1.4")
        assert stored_file.relative_path.parts[:3] == ("medical-records", "exports", str(session.info["tenant_id"]))

    async def test_export_patient_history_pdf_with_records(self, session, make_user, isolated_storage_root):
        user = await make_user()
        patient = await _create_patient(session, cpf="11144477735")
        await MedicalRecordService.create_record(
            session,
            user.id,
            MedicalRecordCreateRequest(patient_id=patient.id, content="Historico para exportacao"),
        )
        await session.commit()

        assert not isolated_storage_root.exists()

        stored_file = await MedicalRecordService.export_patient_history_pdf(session, patient.id)

        assert stored_file.filename == f"medical-record-history-patient-{patient.id}.pdf"
        assert stored_file.path.exists()
        assert stored_file.path.read_bytes().startswith(b"%PDF-1.4")
        assert "patients" in stored_file.relative_path.parts

    async def test_export_patient_history_pdf_without_records_raises_not_found(self, session, make_user):
        await make_user()
        patient = await _create_patient(session, cpf="39053344705")

        with pytest.raises(MedicalRecordExportEmpty):
            await MedicalRecordService.export_patient_history_pdf(session, patient.id)

    async def test_export_all_records_pdf_with_records(self, session, make_user, isolated_storage_root):
        user = await make_user()
        patient = await _create_patient(session, cpf="16899535009")
        await MedicalRecordService.create_record(
            session,
            user.id,
            MedicalRecordCreateRequest(patient_id=patient.id, content="Historico global"),
        )
        await session.commit()

        assert not isolated_storage_root.exists()

        stored_file = await MedicalRecordService.export_all_records_pdf(session)

        assert stored_file.filename == "medical-record-history-all-patients.pdf"
        assert stored_file.path.exists()
        assert stored_file.path.read_bytes().startswith(b"%PDF-1.4")
        assert stored_file.relative_path.parts[-2:] == ("all", "medical-record-history-all-patients.pdf")


class TestMedicalRecordAPI:
    """API-layer tests for medical record operations."""

    async def test_owner_can_create_list_update_history_and_export(self, auth_client, session, isolated_storage_root):
        client, user = auth_client
        user.tenant_ids = [_tenant_id_from_client(client)]

        patient = await _create_patient(session, cpf="64351919051")
        await session.commit()

        create_response = await client.post("/api/medical-records", json=_record_payload(patient_id=patient.id))
        assert create_response.status_code == status.HTTP_200_OK
        record_id = create_response.json()["id"]

        list_response = await client.get(f"/api/medical-records?patient_id={patient.id}")
        assert list_response.status_code == status.HTTP_200_OK
        assert list_response.json()["total"] == 1

        history_response = await client.get(f"/api/medical-records/patients/{patient.id}/history")
        assert history_response.status_code == status.HTTP_200_OK
        assert history_response.json()["total"] == 1

        update_response = await client.put(
            f"/api/medical-records/{record_id}",
            json={
                "title": "Sessao 01",
                "content": "Updated consultation notes",
                "attachments": ["https://example.com/updated.pdf"],
            },
        )
        assert update_response.status_code == status.HTTP_200_OK
        assert update_response.json()["title"] == "Sessao 01"

        export_response = await client.get(f"/api/medical-records/{record_id}/export/pdf")
        assert export_response.status_code == status.HTTP_200_OK
        assert export_response.headers["content-type"].startswith("application/pdf")
        assert (
            export_response.headers["content-disposition"] == f'attachment; filename="medical-record-{record_id}.pdf"'
        )
        assert export_response.content.startswith(b"%PDF-1.4")
        stored_files = list(isolated_storage_root.rglob("*.pdf"))
        assert len(stored_files) == 1
        assert stored_files[0].name == f"medical-record-{record_id}.pdf"

    async def test_export_all_without_records_returns_404(self, auth_client):
        client, user = auth_client
        user.tenant_ids = [_tenant_id_from_client(client)]

        response = await client.get("/api/medical-records/export/pdf")

        assert response.status_code == status.HTTP_404_NOT_FOUND

    async def test_get_and_update_nonexistent_record_return_404(self, auth_client):
        client, user = auth_client
        user.tenant_ids = [_tenant_id_from_client(client)]

        get_response = await client.get("/api/medical-records/999999")
        update_response = await client.put(
            "/api/medical-records/999999",
            json={"content": "Atualizacao que deve falhar"},
        )

        assert get_response.status_code == status.HTTP_404_NOT_FOUND
        assert update_response.status_code == status.HTTP_404_NOT_FOUND

    async def test_get_record_and_export_scopes_success(self, auth_client, session, isolated_storage_root):
        client, user = auth_client
        user.tenant_ids = [_tenant_id_from_client(client)]
        patient = await _create_patient(session, cpf="16899535009")
        await session.commit()

        create_response = await client.post("/api/medical-records", json=_record_payload(patient_id=patient.id))
        record_id = create_response.json()["id"]

        get_response = await client.get(f"/api/medical-records/{record_id}")
        patient_export_response = await client.get(f"/api/medical-records/patients/{patient.id}/export/pdf")
        all_export_response = await client.get("/api/medical-records/export/pdf")

        assert get_response.status_code == status.HTTP_200_OK
        assert get_response.json()["id"] == record_id
        assert patient_export_response.status_code == status.HTTP_200_OK
        assert patient_export_response.headers["content-type"].startswith("application/pdf")
        assert patient_export_response.content.startswith(b"%PDF-1.4")
        assert all_export_response.status_code == status.HTTP_200_OK
        assert all_export_response.headers["content-type"].startswith("application/pdf")
        assert all_export_response.content.startswith(b"%PDF-1.4")
        stored_names = sorted(path.name for path in isolated_storage_root.rglob("*.pdf"))
        assert stored_names == [
            "medical-record-history-all-patients.pdf",
            f"medical-record-history-patient-{patient.id}.pdf",
        ]

    async def test_create_rejects_duplicate_attachments(self, auth_client, session):
        client, user = auth_client
        user.tenant_ids = [_tenant_id_from_client(client)]
        patient = await _create_patient(session, cpf="41547287411")
        await session.commit()

        response = await client.post(
            "/api/medical-records",
            json={
                "patient_id": patient.id,
                "content": "Registro com anexos duplicados",
                "attachments": [
                    "https://example.com/anexo.pdf",
                    "https://example.com/anexo.pdf",
                ],
            },
        )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT

    async def test_update_rejects_null_content(self, auth_client, session):
        client, user = auth_client
        user.tenant_ids = [_tenant_id_from_client(client)]
        patient = await _create_patient(session, cpf="16899535009")
        await session.commit()

        create_response = await client.post("/api/medical-records", json=_record_payload(patient_id=patient.id))
        record_id = create_response.json()["id"]

        response = await client.put(
            f"/api/medical-records/{record_id}",
            json={"content": None},
        )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT

    async def test_update_rejects_null_patient_and_recorded_at(self, auth_client, session):
        client, user = auth_client
        user.tenant_ids = [_tenant_id_from_client(client)]
        patient = await _create_patient(session, cpf="11144477735")
        await session.commit()

        create_response = await client.post("/api/medical-records", json=_record_payload(patient_id=patient.id))
        record_id = create_response.json()["id"]

        null_patient_response = await client.put(
            f"/api/medical-records/{record_id}",
            json={"patient_id": None},
        )
        null_recorded_at_response = await client.put(
            f"/api/medical-records/{record_id}",
            json={"recorded_at": None},
        )

        assert null_patient_response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT
        assert null_recorded_at_response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT

    async def test_export_patient_history_returns_404_when_empty(self, auth_client, session):
        client, user = auth_client
        user.tenant_ids = [_tenant_id_from_client(client)]
        patient = await _create_patient(session, cpf="69542144342")
        await session.commit()

        response = await client.get(f"/api/medical-records/patients/{patient.id}/export/pdf")

        assert response.status_code == status.HTTP_404_NOT_FOUND

    async def test_export_patient_history_returns_404_when_patient_missing(self, auth_client):
        client, user = auth_client
        user.tenant_ids = [_tenant_id_from_client(client)]

        response = await client.get("/api/medical-records/patients/999999/export/pdf")

        assert response.status_code == status.HTTP_404_NOT_FOUND

    async def test_create_with_deleted_appointment_returns_404(self, auth_client, session):
        client, user = auth_client
        user.tenant_ids = [_tenant_id_from_client(client)]
        patient = await _create_patient(session, cpf="64351919051")
        appointment = await _create_appointment(session, user_id=user.id, patient_id=patient.id)
        appointment.is_deleted = True
        await session.commit()

        response = await client.post(
            "/api/medical-records",
            json=_record_payload(
                patient_id=patient.id,
                appointment_id=appointment.id,
                content="Registro com consulta deletada",
            ),
        )

        assert response.status_code == status.HTTP_404_NOT_FOUND

    async def test_assistant_cannot_access_medical_record_endpoints(self, auth_client, make_user):
        client, _ = auth_client
        tenant_id = _tenant_id_from_client(client)
        assistant = await make_user(
            email="assistant_medical_record@example.com",
            username="assistant_medical_record",
            roles=[UserRole.ASSISTANT],
            tenant_ids=[tenant_id],
        )

        async def override_get_current_user():
            return assistant

        app.dependency_overrides[get_current_user] = override_get_current_user
        app.dependency_overrides[get_current_active_user] = override_get_current_user
        try:
            response = await client.get("/api/medical-records")
        finally:
            app.dependency_overrides.pop(get_current_user, None)
            app.dependency_overrides.pop(get_current_active_user, None)

        assert response.status_code == status.HTTP_403_FORBIDDEN

    async def test_user_not_assigned_to_tenant_gets_403(self, auth_client):
        client, user = auth_client
        user.tenant_ids = []

        response = await client.get("/api/medical-records")

        assert response.status_code == status.HTTP_403_FORBIDDEN

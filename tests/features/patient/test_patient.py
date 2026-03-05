"""Tests for patient feature."""

from datetime import date
from decimal import Decimal
from uuid import UUID

import pytest
from fastapi import status

from src.features.auth.dependencies import get_current_active_user, get_current_user
from src.features.patient.exceptions import PatientCpfAlreadyExists
from src.features.patient.schemas import (
    PatientCompleteRegistrationRequest,
    PatientCreateRequest,
    PatientQuickCreateRequest,
)
from src.features.patient.service import PatientService
from src.features.user.models import UserRole
from src.main import app
from src.shared.pagination.pagination import PaginationParams


def _tenant_id_from_client(client) -> UUID:
    """Extract tenant UUID from test client default headers."""
    tenant_id_header = client.headers.get("X-Tenant-ID")
    assert tenant_id_header is not None
    return UUID(tenant_id_header)


def _patient_payload(cpf: str = "52998224725", **overrides):
    payload = {
        "full_name": "Maria Oliveira",
        "birth_date": "1995-05-22",
        "cpf": cpf,
        "cep": "19900000",
        "phone_number": "14999999999",
        "session_price": "180.00",
        "session_frequency": "weekly",
        "first_session_date": "2026-03-20",
        "initial_record": "Initial history notes.",
    }
    payload.update(overrides)
    return payload


class TestPatientService:
    """Service-layer tests for patient operations."""

    async def test_create_patient_success(self, session, make_user):
        await make_user()
        request = PatientCreateRequest(
            full_name="Ana Souza",
            birth_date=date(1990, 1, 10),
            cpf="11144477735",
            cep="19900000",
            phone_number="14999998888",
            session_price=Decimal("200.00"),
            session_frequency="weekly",
            first_session_date=date(2026, 3, 20),
            initial_record="Initial notes",
        )

        patient = await PatientService.create_patient(session, request)
        await session.commit()
        await session.refresh(patient)

        assert patient.cpf == "11144477735"
        assert patient.is_registered is True
        assert patient.is_active is True

    async def test_quick_registration_and_completion(self, session, make_user):
        await make_user()

        quick = await PatientService.create_quick_patient(
            session,
            PatientQuickCreateRequest(full_name="Paciente Rápido"),
        )
        await session.flush()
        assert quick.is_registered is False

        completed = await PatientService.complete_registration(
            session,
            quick,
            PatientCompleteRegistrationRequest(
                full_name="Paciente Rápido",
                birth_date=date(2000, 2, 2),
                cpf="39053344705",
                cep="19911111",
                phone_number="14988887777",
                session_price=Decimal("150.00"),
                session_frequency="biweekly",
                first_session_date=date(2026, 3, 18),
            ),
        )
        await session.commit()

        assert completed.is_registered is True
        assert completed.cpf == "39053344705"

    async def test_duplicate_cpf_in_same_tenant_raises_conflict(self, session, make_user):
        await make_user()
        payload = PatientCreateRequest(
            full_name="Paciente Um",
            birth_date=date(1991, 3, 3),
            cpf="16899535009",
            cep="19922222",
            phone_number="14977776666",
            session_price=Decimal("120.00"),
            session_frequency="weekly",
        )
        await PatientService.create_patient(session, payload)
        await session.flush()

        with pytest.raises(PatientCpfAlreadyExists):
            await PatientService.create_patient(session, payload)

    async def test_inactivate_and_reactivate_patient(self, session, make_user):
        await make_user()
        patient = await PatientService.create_patient(
            session,
            PatientCreateRequest(
                full_name="Paciente Ativo",
                birth_date=date(1988, 8, 8),
                cpf="41547287411",
                cep="19933333",
                phone_number="14966665555",
                session_price=Decimal("190.00"),
                session_frequency="weekly",
            ),
        )
        await session.flush()

        inactive = await PatientService.inactivate_patient(session, patient)
        assert inactive.is_active is False
        assert inactive.retention_expires_at is not None
        assert inactive.inactivated_at is not None
        assert inactive.retention_expires_at.year == inactive.inactivated_at.year + 5

        reactivated = await PatientService.reactivate_patient(session, patient)
        await session.commit()

        assert reactivated.is_active is True
        assert reactivated.inactivated_at is None
        assert reactivated.retention_expires_at is None

    async def test_list_patients_with_active_filter(self, session, make_user):
        await make_user()
        active_patient = await PatientService.create_patient(
            session,
            PatientCreateRequest(
                full_name="Paciente Ativo",
                birth_date=date(1992, 9, 9),
                cpf="69542144342",
                cep="19944444",
                phone_number="14955554444",
                session_price=Decimal("175.00"),
                session_frequency="weekly",
            ),
        )
        inactive_patient = await PatientService.create_patient(
            session,
            PatientCreateRequest(
                full_name="Paciente Inativo",
                birth_date=date(1993, 10, 10),
                cpf="64351919051",
                cep="19955555",
                phone_number="14944443333",
                session_price=Decimal("165.00"),
                session_frequency="weekly",
            ),
        )
        await session.flush()
        await PatientService.inactivate_patient(session, inactive_patient)
        await session.commit()

        items, total = await PatientService.list_patients(
            session=session,
            pagination=PaginationParams(page=1, page_size=10),
            is_active=True,
        )

        assert total == 1
        assert len(items) == 1
        assert items[0].id == active_patient.id


class TestPatientAPI:
    """API-layer tests for patient operations."""

    async def test_tenant_owner_can_create_patient(self, auth_client):
        client, user = auth_client
        user.tenant_ids = [_tenant_id_from_client(client)]

        response = await client.post("/api/patients", json=_patient_payload())

        assert response.status_code == status.HTTP_200_OK
        body = response.json()
        assert body["full_name"] == "Maria Oliveira"
        assert body["is_registered"] is True

    async def test_minor_without_guardian_returns_422(self, auth_client):
        client, user = auth_client
        user.tenant_ids = [_tenant_id_from_client(client)]

        response = await client.post(
            "/api/patients",
            json=_patient_payload(
                cpf="16899535009",
                birth_date="2010-01-01",
            ),
        )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT

    async def test_assistant_cannot_access_patient_endpoints(self, auth_client, make_user):
        client, _ = auth_client
        tenant_id = _tenant_id_from_client(client)
        assistant = await make_user(
            email="assistant_patient@example.com",
            username="assistant_patient",
            roles=[UserRole.ASSISTANT],
            tenant_ids=[tenant_id],
        )

        async def override_get_current_user():
            return assistant

        app.dependency_overrides[get_current_user] = override_get_current_user
        app.dependency_overrides[get_current_active_user] = override_get_current_user
        try:
            response = await client.get("/api/patients")
        finally:
            app.dependency_overrides.pop(get_current_user, None)
            app.dependency_overrides.pop(get_current_active_user, None)

        assert response.status_code == status.HTTP_403_FORBIDDEN

    async def test_list_active_only_excludes_inactive_patients(self, auth_client):
        client, user = auth_client
        user.tenant_ids = [_tenant_id_from_client(client)]

        create_response = await client.post("/api/patients", json=_patient_payload())
        patient_id = create_response.json()["id"]

        second_response = await client.post(
            "/api/patients",
            json=_patient_payload(cpf="11144477735", full_name="Paciente Dois"),
        )
        second_id = second_response.json()["id"]
        assert second_id != patient_id

        inactivate_response = await client.delete(f"/api/patients/{second_id}")
        assert inactivate_response.status_code == status.HTTP_200_OK

        response = await client.get("/api/patients")
        assert response.status_code == status.HTTP_200_OK
        body = response.json()
        assert body["total"] == 1
        assert len(body["patients"]) == 1
        assert body["patients"][0]["id"] == patient_id

    async def test_duplicate_cpf_returns_409(self, auth_client):
        client, user = auth_client
        user.tenant_ids = [_tenant_id_from_client(client)]

        first = await client.post("/api/patients", json=_patient_payload())
        assert first.status_code == status.HTTP_200_OK

        second = await client.post(
            "/api/patients",
            json=_patient_payload(full_name="Paciente Duplicado"),
        )
        assert second.status_code == status.HTTP_409_CONFLICT

    async def test_quick_register_and_complete_registration(self, auth_client):
        client, user = auth_client
        user.tenant_ids = [_tenant_id_from_client(client)]

        quick_response = await client.post(
            "/api/patients/quick-register",
            json={"full_name": "Paciente sem cadastro"},
        )
        assert quick_response.status_code == status.HTTP_200_OK
        patient_id = quick_response.json()["id"]
        assert quick_response.json()["is_registered"] is False

        complete_response = await client.post(
            f"/api/patients/{patient_id}/complete-registration",
            json=_patient_payload(
                cpf="39053344705",
                full_name="Paciente sem cadastro",
            ),
        )
        assert complete_response.status_code == status.HTTP_200_OK
        assert complete_response.json()["is_registered"] is True

    async def test_update_registered_minor_without_guardian_returns_422(self, auth_client):
        client, user = auth_client
        user.tenant_ids = [_tenant_id_from_client(client)]

        create_response = await client.post(
            "/api/patients",
            json=_patient_payload(
                cpf="22028656247",
                birth_date="2010-05-20",
                guardian_name="Mae Responsavel",
                guardian_phone="14912345678",
            ),
        )
        patient_id = create_response.json()["id"]

        response = await client.put(
            f"/api/patients/{patient_id}",
            json={"guardian_name": None},
        )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT

    async def test_user_not_assigned_to_tenant_gets_403(self, auth_client):
        client, user = auth_client
        user.tenant_ids = []

        response = await client.get("/api/patients")

        assert response.status_code == status.HTTP_403_FORBIDDEN

    async def test_update_profile_photo_success(self, auth_client):
        client, user = auth_client
        user.tenant_ids = [_tenant_id_from_client(client)]

        create_response = await client.post(
            "/api/patients",
            json=_patient_payload(cpf="39360534803"),
        )
        patient_id = create_response.json()["id"]

        response = await client.patch(
            f"/api/patients/{patient_id}/profile-photo",
            json={"profile_photo_url": "https://example.com/patient-photo.jpg"},
        )

        assert response.status_code == status.HTTP_200_OK
        assert response.json()["profile_photo_url"] == "https://example.com/patient-photo.jpg"

    async def test_reactivate_patient_success(self, auth_client):
        client, user = auth_client
        user.tenant_ids = [_tenant_id_from_client(client)]

        create_response = await client.post(
            "/api/patients",
            json=_patient_payload(cpf="16514569927"),
        )
        patient_id = create_response.json()["id"]

        deactivate_response = await client.delete(f"/api/patients/{patient_id}")
        assert deactivate_response.status_code == status.HTTP_200_OK

        response = await client.post(f"/api/patients/{patient_id}/reactivate")

        assert response.status_code == status.HTTP_200_OK
        assert response.json()["is_active"] is True

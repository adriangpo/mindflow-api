"""Tests for the async export feature."""

import asyncio
import json
from uuid import UUID

from fastapi import status

from src.features.auth.dependencies import get_current_active_user, get_current_user
from src.features.export.router import _event_stream
from src.features.export.service import ExportService
from src.features.user.models import UserRole
from src.main import app


def _tenant_id_from_client(client) -> UUID:
    tenant_id_header = client.headers.get("X-Tenant-ID")
    assert tenant_id_header is not None
    return UUID(tenant_id_header)


async def _create_record_via_api(client) -> int:
    patient_response = await client.post(
        "/api/patients",
        json={
            "full_name": "Paciente Exportacao",
            "birth_date": "1995-05-22",
            "cpf": "52998224725",
            "cep": "19900000",
            "phone_number": "14999999999",
            "session_price": "180.00",
            "session_frequency": "weekly",
            "first_session_date": "2026-03-20",
            "initial_record": "Initial history notes.",
        },
    )
    assert patient_response.status_code == status.HTTP_200_OK
    patient_id = patient_response.json()["id"]

    record_response = await client.post(
        "/api/medical-records",
        json={
            "patient_id": patient_id,
            "content": "Registro para exportar",
        },
    )
    assert record_response.status_code == status.HTTP_200_OK
    return record_response.json()["id"]


async def _read_first_export_event(tenant_id: UUID, user_id: int) -> dict[str, object]:
    stream = _event_stream(tenant_id, user_id)
    try:
        while True:
            chunk = await anext(stream)
            for line in chunk.splitlines():
                if line.startswith("data: "):
                    return json.loads(line.removeprefix("data: "))
    finally:
        await stream.aclose()


class TestExportAPI:
    """API-level tests for generic export status, download, and SSE behavior."""

    async def test_status_download_and_creator_scope(self, auth_client, session, make_user):
        client, user = auth_client
        tenant_id = _tenant_id_from_client(client)
        user.tenant_ids = [tenant_id]

        record_id = await _create_record_via_api(client)

        create_job_response = await client.post(f"/api/medical-records/{record_id}/export/pdf")
        assert create_job_response.status_code == status.HTTP_202_ACCEPTED
        job_id = create_job_response.json()["id"]

        queued_status_response = await client.get(f"/api/exports/{job_id}")
        assert queued_status_response.status_code == status.HTTP_200_OK
        assert queued_status_response.json()["status"] == "queued"

        await ExportService.process_job(job_id, session=session)

        completed_status_response = await client.get(f"/api/exports/{job_id}")
        assert completed_status_response.status_code == status.HTTP_200_OK
        assert completed_status_response.json()["status"] == "completed"
        assert completed_status_response.json()["download_url"] == f"/api/exports/{job_id}/download"

        download_response = await client.get(f"/api/exports/{job_id}/download")
        assert download_response.status_code == status.HTTP_200_OK
        assert download_response.content.startswith(b"%PDF-1.4")

        same_tenant_other_user = await make_user(
            email="other_export@example.com",
            username="other_export",
            roles=[UserRole.TENANT_OWNER],
            tenant_ids=[tenant_id],
        )

        async def override_get_current_user():
            return same_tenant_other_user

        app.dependency_overrides[get_current_user] = override_get_current_user
        app.dependency_overrides[get_current_active_user] = override_get_current_user
        try:
            forbidden_status_response = await client.get(f"/api/exports/{job_id}")
            forbidden_download_response = await client.get(f"/api/exports/{job_id}/download")
        finally:
            app.dependency_overrides.pop(get_current_user, None)
            app.dependency_overrides.pop(get_current_active_user, None)

        assert forbidden_status_response.status_code == status.HTTP_404_NOT_FOUND
        assert forbidden_download_response.status_code == status.HTTP_404_NOT_FOUND

    async def test_sse_stream_receives_export_updates(self, auth_client):
        client, user = auth_client
        tenant_id = _tenant_id_from_client(client)
        user.tenant_ids = [tenant_id]

        record_id = await _create_record_via_api(client)
        event_task = asyncio.create_task(_read_first_export_event(tenant_id, user.id))
        await asyncio.sleep(0.05)

        create_job_response = await client.post(f"/api/medical-records/{record_id}/export/pdf")
        assert create_job_response.status_code == status.HTTP_202_ACCEPTED
        job_id = create_job_response.json()["id"]

        event_payload = await asyncio.wait_for(event_task, timeout=5)
        assert event_payload["id"] == job_id
        assert event_payload["status"] in {"queued", "running", "completed"}

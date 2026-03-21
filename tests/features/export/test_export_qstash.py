"""Tests for the QStash-backed export flow."""

import json
from pathlib import Path
from uuid import UUID

from fastapi import status
from httpx import ASGITransport, AsyncClient

from src.features.export.service import ExportService
from src.main import app
from src.shared.storage import StoredFile


def _tenant_id_from_client(client) -> UUID:
    tenant_id_header = client.headers.get("X-Tenant-ID")
    assert tenant_id_header is not None
    return UUID(tenant_id_header)


async def _create_record_via_api(client) -> int:
    patient_response = await client.post(
        "/api/patients",
        json={
            "full_name": "Paciente Exportacao QStash",
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


class TestExportQStash:
    """Export tests covering the production QStash callback path."""

    async def test_create_job_publishes_qstash_callback_and_processes_successfully(
        self,
        auth_client,
        fake_qstash,
        sign_qstash_request,
    ):
        client, user = auth_client
        tenant_id = _tenant_id_from_client(client)
        user.tenant_ids = [tenant_id]

        record_id = await _create_record_via_api(client)

        create_job_response = await client.post(f"/api/medical-records/{record_id}/export/pdf")
        assert create_job_response.status_code == status.HTTP_202_ACCEPTED
        job_id = create_job_response.json()["id"]

        assert len(fake_qstash.message.published) == 1
        published = fake_qstash.message.published[0]
        assert published["url"] == "http://test/api/internal/qstash/exports/process"
        assert published["body"] == {"job_id": job_id}
        assert published["method"] == "POST"

        body = json.dumps({"job_id": job_id}, separators=(",", ":"))
        callback_response = await client.post(
            "/api/internal/qstash/exports/process",
            content=body,
            headers=sign_qstash_request(
                body=body,
                path="/api/internal/qstash/exports/process",
            ),
        )
        assert callback_response.status_code == status.HTTP_200_OK
        assert callback_response.json()["status"] == "completed"

        completed_status_response = await client.get(f"/api/exports/{job_id}")
        assert completed_status_response.status_code == status.HTTP_200_OK
        assert completed_status_response.json()["status"] == "completed"

    async def test_callback_marks_job_failed_when_processing_raises(
        self,
        auth_client,
        fake_qstash,
        monkeypatch,
        sign_qstash_request,
    ):
        _ = fake_qstash
        client, user = auth_client
        tenant_id = _tenant_id_from_client(client)
        user.tenant_ids = [tenant_id]
        record_id = await _create_record_via_api(client)

        create_job_response = await client.post(f"/api/medical-records/{record_id}/export/pdf")
        assert create_job_response.status_code == status.HTTP_202_ACCEPTED
        job_id = create_job_response.json()["id"]

        async def _raise_processing_error(*_args, **_kwargs):
            raise RuntimeError("qstash processing failure")

        monkeypatch.setattr(ExportService, "_build_export_file", staticmethod(_raise_processing_error))

        body = json.dumps({"job_id": job_id}, separators=(",", ":"))
        callback_response = await client.post(
            "/api/internal/qstash/exports/process",
            content=body,
            headers=sign_qstash_request(
                body=body,
                path="/api/internal/qstash/exports/process",
            ),
        )
        assert callback_response.status_code == status.HTTP_200_OK

        failed_status_response = await client.get(f"/api/exports/{job_id}")
        assert failed_status_response.status_code == status.HTTP_200_OK
        assert failed_status_response.json()["status"] == "failed"
        assert "qstash processing failure" in failed_status_response.json()["error_detail"]

    async def test_callback_is_idempotent_after_completion(
        self,
        auth_client,
        fake_qstash,
        monkeypatch,
        sign_qstash_request,
        tmp_path,
    ):
        _ = fake_qstash
        client, user = auth_client
        tenant_id = _tenant_id_from_client(client)
        user.tenant_ids = [tenant_id]
        record_id = await _create_record_via_api(client)

        create_job_response = await client.post(f"/api/medical-records/{record_id}/export/pdf")
        assert create_job_response.status_code == status.HTTP_202_ACCEPTED
        job_id = create_job_response.json()["id"]

        call_count = {"count": 0}
        output_path = tmp_path / "export-idempotent.pdf"
        output_path.write_bytes(b"%PDF-1.4 test")

        async def _fake_build(*_args, **_kwargs):
            call_count["count"] += 1
            return StoredFile(
                path=output_path,
                relative_path=Path("exports/export-idempotent.pdf"),
                filename="export-idempotent.pdf",
                content_type="application/pdf",
            )

        monkeypatch.setattr(ExportService, "_build_export_file", staticmethod(_fake_build))

        body = json.dumps({"job_id": job_id}, separators=(",", ":"))
        headers = sign_qstash_request(
            body=body,
            path="/api/internal/qstash/exports/process",
        )

        first_callback = await client.post(
            "/api/internal/qstash/exports/process",
            content=body,
            headers=headers,
        )
        second_callback = await client.post(
            "/api/internal/qstash/exports/process",
            content=body,
            headers=headers,
        )

        assert first_callback.status_code == status.HTTP_200_OK
        assert second_callback.status_code == status.HTTP_200_OK
        assert call_count["count"] == 1

    async def test_internal_callback_rejects_missing_or_invalid_signature(
        self,
        auth_client,
        fake_qstash,
    ):
        _ = fake_qstash
        client, user = auth_client
        tenant_id = _tenant_id_from_client(client)
        user.tenant_ids = [tenant_id]

        body = json.dumps({"job_id": "job-123"}, separators=(",", ":"))

        missing_signature_response = await client.post(
            "/api/internal/qstash/exports/process",
            content=body,
            headers={"Content-Type": "application/json"},
        )
        invalid_signature_response = await client.post(
            "/api/internal/qstash/exports/process",
            content=body,
            headers={
                "Content-Type": "application/json",
                "Upstash-Signature": "invalid-signature",
            },
        )

        assert missing_signature_response.status_code == status.HTTP_401_UNAUTHORIZED
        assert invalid_signature_response.status_code == status.HTTP_401_UNAUTHORIZED

    async def test_internal_callback_does_not_require_tenant_header(
        self,
        auth_client,
        fake_qstash,
        sign_qstash_request,
    ):
        _ = fake_qstash
        client, user = auth_client
        tenant_id = _tenant_id_from_client(client)
        user.tenant_ids = [tenant_id]

        record_id = await _create_record_via_api(client)
        create_job_response = await client.post(f"/api/medical-records/{record_id}/export/pdf")
        assert create_job_response.status_code == status.HTTP_202_ACCEPTED
        job_id = create_job_response.json()["id"]

        body = json.dumps({"job_id": job_id}, separators=(",", ":"))
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as public_client:
            callback_response = await public_client.post(
                "/api/internal/qstash/exports/process",
                content=body,
                headers=sign_qstash_request(
                    body=body,
                    path="/api/internal/qstash/exports/process",
                ),
            )

        assert callback_response.status_code == status.HTTP_200_OK
        assert callback_response.json()["status"] == "completed"

    async def test_download_redirects_to_presigned_url_when_storage_backend_is_s3(
        self,
        auth_client,
        session,
        fake_s3_client,
        monkeypatch,
    ):
        from src.config.settings import settings

        monkeypatch.setattr(settings, "storage_backend", "s3")
        monkeypatch.setattr(settings, "s3_endpoint_url", "https://r2.example.test")
        monkeypatch.setattr(settings, "s3_bucket_name", "mindflow-exports")
        monkeypatch.setattr(settings, "aws_access_key_id", "access-key")
        monkeypatch.setattr(settings, "aws_secret_access_key", "secret-key")
        monkeypatch.setattr(settings, "aws_region", "auto")

        client, user = auth_client
        tenant_id = _tenant_id_from_client(client)
        user.tenant_ids = [tenant_id]

        record_id = await _create_record_via_api(client)
        create_job_response = await client.post(f"/api/medical-records/{record_id}/export/pdf")
        assert create_job_response.status_code == status.HTTP_202_ACCEPTED
        job_id = create_job_response.json()["id"]

        await ExportService.process_job(job_id, session=session)

        download_response = await client.get(f"/api/exports/{job_id}/download", follow_redirects=False)
        assert download_response.status_code == status.HTTP_307_TEMPORARY_REDIRECT
        assert download_response.headers["location"].startswith("https://r2.example.test/")
        assert fake_s3_client.objects

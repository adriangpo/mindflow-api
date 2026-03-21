"""Redis-backed async export service."""

import asyncio
import logging
from datetime import UTC, datetime
from uuid import UUID, uuid7

from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from src.config.settings import settings
from src.database.client import get_session, set_tenant_context
from src.features.finance.service import FinanceService
from src.features.medical_record.service import MedicalRecordService
from src.features.patient.service import PatientService
from src.shared.redis import dumps_json, ensure_stream_group, get_redis, loads_json
from src.shared.storage import StoredFile, get_local_storage_backend

from .schemas import ExportJobKind, ExportJobResponse, ExportJobSnapshot, ExportJobStatus

logger = logging.getLogger(__name__)

EXPORT_JOBS_STREAM = "exports:jobs"
EXPORT_JOBS_GROUP = "exports:workers"


class ExportService:
    """Manage async export job creation, state, and event publication."""

    @staticmethod
    def _job_key(job_id: str) -> str:
        return f"exports:job:{job_id}"

    @staticmethod
    def _user_channel(tenant_id: UUID, user_id: int) -> str:
        return f"exports:user:{tenant_id}:{user_id}:events"

    @staticmethod
    def _download_url(job_id: str) -> str:
        return f"{settings.api_prefix}/exports/{job_id}/download"

    @staticmethod
    def _payload_int(snapshot: ExportJobSnapshot, key: str) -> int:
        value = snapshot.payload.get(key)
        if not isinstance(value, int | str):
            raise ValueError(f"Export payload field '{key}' is invalid")
        return int(value)

    @staticmethod
    def _payload_str(snapshot: ExportJobSnapshot, key: str) -> str:
        value = snapshot.payload.get(key)
        if not isinstance(value, str):
            raise ValueError(f"Export payload field '{key}' is invalid")
        return value

    @staticmethod
    def _payload_optional_str(snapshot: ExportJobSnapshot, key: str) -> str | None:
        value = snapshot.payload.get(key)
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValueError(f"Export payload field '{key}' is invalid")
        return value

    @staticmethod
    def _public_snapshot(snapshot: ExportJobSnapshot) -> ExportJobResponse:
        return ExportJobResponse.model_validate(
            {
                "id": snapshot.id,
                "kind": snapshot.kind,
                "status": snapshot.status,
                "progress_current": snapshot.progress_current,
                "progress_total": snapshot.progress_total,
                "progress_message": snapshot.progress_message,
                "download_url": snapshot.download_url,
                "error_detail": snapshot.error_detail,
                "created_at": snapshot.created_at,
                "updated_at": snapshot.updated_at,
            }
        )

    @staticmethod
    async def ensure_runtime() -> None:
        """Ensure Redis consumer-group prerequisites exist."""
        await ensure_stream_group(EXPORT_JOBS_STREAM, EXPORT_JOBS_GROUP)

    @staticmethod
    async def create_job(
        *,
        kind: ExportJobKind,
        tenant_id: UUID,
        user_id: int,
        payload: dict[str, object],
    ) -> ExportJobResponse:
        """Create and enqueue an export job."""
        await ExportService.ensure_runtime()

        now = datetime.now(UTC)
        snapshot = ExportJobSnapshot(
            id=str(uuid7()),
            kind=kind,
            status=ExportJobStatus.QUEUED,
            progress_current=0,
            progress_total=3,
            progress_message="Queued",
            download_url=None,
            error_detail=None,
            created_at=now,
            updated_at=now,
            tenant_id=tenant_id,
            created_by_user_id=user_id,
            payload=payload,
        )

        redis = get_redis()
        pipeline = redis.pipeline(transaction=False)
        pipeline.set(ExportService._job_key(snapshot.id), dumps_json(snapshot.model_dump(mode="json")))
        pipeline.xadd(EXPORT_JOBS_STREAM, {"job_id": snapshot.id})
        await pipeline.execute()

        await ExportService.publish_snapshot(snapshot)
        return ExportService._public_snapshot(snapshot)

    @staticmethod
    async def get_snapshot(job_id: str) -> ExportJobSnapshot:
        """Load a job snapshot from Redis."""
        redis = get_redis()
        raw = await redis.get(ExportService._job_key(job_id))
        if raw is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Export job not found")
        return ExportJobSnapshot.model_validate(loads_json(raw))

    @staticmethod
    async def get_job_for_user(job_id: str, *, tenant_id: UUID, user_id: int) -> ExportJobResponse:
        """Load one export job scoped to its creator and tenant."""
        snapshot = await ExportService.get_snapshot(job_id)
        if snapshot.tenant_id != tenant_id or snapshot.created_by_user_id != user_id:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Export job not found")
        return ExportService._public_snapshot(snapshot)

    @staticmethod
    async def get_download_file(job_id: str, *, tenant_id: UUID, user_id: int) -> StoredFile:
        """Resolve a completed export file for its creator."""
        snapshot = await ExportService.get_snapshot(job_id)
        if snapshot.tenant_id != tenant_id or snapshot.created_by_user_id != user_id:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Export job not found")
        if snapshot.status != ExportJobStatus.COMPLETED or snapshot.file_relative_path is None:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Export job is not completed yet")
        if snapshot.filename is None or snapshot.content_type is None:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Export file metadata is incomplete")

        backend = get_local_storage_backend()
        path = backend.root / snapshot.file_relative_path
        if not path.exists():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Export file not found")

        return StoredFile(
            path=path,
            relative_path=path.relative_to(backend.root),
            filename=snapshot.filename,
            content_type=snapshot.content_type,
        )

    @staticmethod
    async def publish_snapshot(snapshot: ExportJobSnapshot) -> None:
        """Persist and publish a snapshot update."""
        redis = get_redis()
        public_snapshot = ExportService._public_snapshot(snapshot)
        pipeline = redis.pipeline(transaction=False)
        pipeline.set(ExportService._job_key(snapshot.id), dumps_json(snapshot.model_dump(mode="json")))
        pipeline.xadd(
            ExportService._user_channel(snapshot.tenant_id, snapshot.created_by_user_id),
            {"data": dumps_json(public_snapshot.model_dump(mode="json"))},
        )
        await pipeline.execute()

    @staticmethod
    async def update_snapshot(
        job_id: str,
        *,
        status_value: ExportJobStatus | None = None,
        progress_current: int | None = None,
        progress_total: int | None = None,
        progress_message: str | None = None,
        error_detail: str | None = None,
        stored_file: StoredFile | None = None,
    ) -> ExportJobSnapshot:
        """Update, persist, and publish one export job snapshot."""
        snapshot = await ExportService.get_snapshot(job_id)
        if status_value is not None:
            snapshot.status = status_value
        if progress_current is not None:
            snapshot.progress_current = progress_current
        if progress_total is not None:
            snapshot.progress_total = progress_total
        snapshot.progress_message = progress_message
        snapshot.error_detail = error_detail
        snapshot.updated_at = datetime.now(UTC)

        if stored_file is not None:
            snapshot.file_relative_path = str(stored_file.relative_path)
            snapshot.filename = stored_file.filename
            snapshot.content_type = stored_file.content_type
            snapshot.download_url = ExportService._download_url(snapshot.id)

        await ExportService.publish_snapshot(snapshot)
        return snapshot

    @staticmethod
    async def _build_export_file(snapshot: ExportJobSnapshot, session: AsyncSession) -> StoredFile:
        if session.info.get("tenant_id") != snapshot.tenant_id:
            await set_tenant_context(session, snapshot.tenant_id)

        if snapshot.kind == ExportJobKind.MEDICAL_RECORD_SINGLE_PDF:
            record_id = ExportService._payload_int(snapshot, "record_id")
            return await MedicalRecordService.export_record_pdf(session, record_id)

        if snapshot.kind == ExportJobKind.MEDICAL_RECORD_PATIENT_HISTORY_PDF:
            patient_id = ExportService._payload_int(snapshot, "patient_id")
            return await MedicalRecordService.export_patient_history_pdf(session, patient_id)

        if snapshot.kind == ExportJobKind.MEDICAL_RECORD_ALL_PDF:
            return await MedicalRecordService.export_all_records_pdf(session)

        if snapshot.kind == ExportJobKind.PATIENT_COMPLETE_PDF:
            patient_id = ExportService._payload_int(snapshot, "patient_id")
            return await PatientService.export_complete_patient_pdf(session, patient_id)

        view = ExportService._payload_str(snapshot, "view")
        reference_date = ExportService._payload_optional_str(snapshot, "reference_date")
        start_date = ExportService._payload_optional_str(snapshot, "start_date")
        end_date = ExportService._payload_optional_str(snapshot, "end_date")
        return await FinanceService.export_report_pdf(
            session,
            view=view,
            reference_date=reference_date,
            start_date=start_date,
            end_date=end_date,
        )

    @staticmethod
    async def process_job(job_id: str, *, session: AsyncSession | None = None) -> None:
        """Execute an export job and persist progress updates."""
        await ExportService.update_snapshot(
            job_id,
            status_value=ExportJobStatus.RUNNING,
            progress_current=1,
            progress_message="Preparing export data",
        )

        try:
            snapshot = await ExportService.get_snapshot(job_id)
            if session is None:
                async with get_session() as worker_session:
                    stored_file = await ExportService._build_export_file(snapshot, worker_session)
            else:
                stored_file = await ExportService._build_export_file(snapshot, session)
        except Exception as exc:
            logger.exception("Export job %s failed", job_id)
            await ExportService.update_snapshot(
                job_id,
                status_value=ExportJobStatus.FAILED,
                progress_current=3,
                progress_message="Export failed",
                error_detail=str(exc),
            )
            return

        await ExportService.update_snapshot(
            job_id,
            status_value=ExportJobStatus.COMPLETED,
            progress_current=3,
            progress_message="Export completed",
            stored_file=stored_file,
        )

    @staticmethod
    async def _collect_autoclaimed_messages(consumer_name: str) -> list[tuple[str, dict[str, str]]]:
        redis = get_redis()
        result = await redis.xautoclaim(
            EXPORT_JOBS_STREAM,
            EXPORT_JOBS_GROUP,
            consumer_name,
            min_idle_time=settings.export_worker_claim_idle_ms,
            start_id="0-0",
            count=10,
        )
        if not result:
            return []
        if len(result) == 3:
            _, messages, _ = result
        else:
            _, messages = result
        return list(messages)

    @staticmethod
    async def consume_one_batch(consumer_name: str, *, block_ms: int | None = None) -> int:
        """Consume one export worker batch."""
        await ExportService.ensure_runtime()
        redis = get_redis()
        entries = await ExportService._collect_autoclaimed_messages(consumer_name)
        if not entries:
            read_result = await redis.xreadgroup(
                EXPORT_JOBS_GROUP,
                consumer_name,
                {EXPORT_JOBS_STREAM: ">"},
                count=10,
                block=block_ms if block_ms is not None else settings.export_worker_block_ms,
            )
            if not read_result:
                return 0
            _, entries = read_result[0]

        processed_count = 0
        for message_id, payload in entries:
            job_id = payload["job_id"]
            await ExportService.process_job(job_id)
            await redis.xack(EXPORT_JOBS_STREAM, EXPORT_JOBS_GROUP, message_id)
            await redis.xdel(EXPORT_JOBS_STREAM, message_id)
            processed_count += 1

        return processed_count

    @staticmethod
    async def run_worker_loop() -> None:
        """Run the export worker forever until canceled."""
        consumer_name = f"worker-{uuid7()}"
        while True:
            try:
                await ExportService.consume_one_batch(consumer_name)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("Export worker iteration failed")

    @staticmethod
    def get_user_event_stream_key(tenant_id: UUID, user_id: int) -> str:
        """Return the Redis stream key used for creator-scoped export events."""
        return ExportService._user_channel(tenant_id, user_id)

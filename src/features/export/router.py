"""Async export job router."""

from collections.abc import AsyncGenerator
from uuid import UUID

from fastapi import APIRouter, Depends, Request
from fastapi.responses import FileResponse, StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession

from src.config.settings import settings
from src.database.dependencies import get_db_session
from src.features.auth.dependencies import require_tenant_membership
from src.features.user.models import User
from src.shared.qstash import verify_qstash_request
from src.shared.redis import get_redis

from .openapi import (
    EXPORT_DOWNLOAD_RESPONSES,
    EXPORT_EVENTS_RESPONSES,
    EXPORT_JOB_NOT_FOUND_RESPONSE,
    EXPORT_PROCESS_CALLBACK_OPENAPI_EXTRA,
    EXPORT_PROCESS_CALLBACK_RESPONSES,
    ExportProcessCallbackResponse,
)
from .schemas import ExportJobResponse, ExportProcessCallbackRequest
from .service import ExportService

router = APIRouter(
    prefix="/exports",
    tags=["Exports"],
    dependencies=[Depends(require_tenant_membership)],
)

internal_router = APIRouter(
    prefix="/internal/qstash/exports",
    tags=["Internal Exports"],
)


async def _event_stream(tenant_id, user_id) -> AsyncGenerator[str]:
    redis = get_redis()
    stream_key = ExportService.get_user_event_stream_key(tenant_id, user_id)
    last_entry = await redis.xrevrange(stream_key, count=1)
    last_id = last_entry[0][0] if last_entry else "0-0"

    yield ": connected\n\n"

    while True:
        messages = await redis.xread(
            {stream_key: last_id},
            count=10,
            block=settings.export_sse_keepalive_seconds * 1000,
        )
        if not messages:
            yield ": keepalive\n\n"
            continue

        _, entries = messages[0]
        for entry_id, fields in entries:
            last_id = entry_id
            yield f"event: export.updated\ndata: {fields['data']}\n\n"


@router.get(
    "/events",
    summary="Stream export job updates",
    description=(
        "Open a server-sent events stream for the authenticated user in the current tenant. "
        "The stream is creator-scoped: it only delivers jobs created by the current user and never replays "
        "other users' events. The first frame is a connection marker, followed by `export.updated` events "
        "whose `data` payload is the JSON-serialized export job snapshot. When no updates are available, the "
        "endpoint emits keepalive comments at the configured SSE interval."
    ),
    response_description="Server-sent events stream with creator-scoped export job updates.",
    responses=EXPORT_EVENTS_RESPONSES,
)
async def export_events(
    request: Request,
    current_user: User = Depends(require_tenant_membership),
):
    """Open an SSE stream for export status updates."""
    tenant_id = UUID(str(request.state.tenant_id))
    return StreamingResponse(
        _event_stream(tenant_id, current_user.id),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
        },
    )


@router.get(
    "/{job_id}",
    response_model=ExportJobResponse,
    summary="Get export job status",
    description=(
        "Return the latest public snapshot for one export job. The job must belong to the authenticated user "
        "and the active tenant; otherwise the API intentionally responds with `404` to avoid leaking job "
        "existence across tenants or creators. The response includes the current state, progress counters, "
        "error detail when applicable, and the download URL once the export completes."
    ),
    response_description="Current export job snapshot.",
    responses={404: EXPORT_JOB_NOT_FOUND_RESPONSE},
)
async def get_export_job(
    job_id: str,
    request: Request,
    current_user: User = Depends(require_tenant_membership),
):
    """Get the latest status for one export job."""
    tenant_id = UUID(str(request.state.tenant_id))
    return await ExportService.get_job_for_user(job_id, tenant_id=tenant_id, user_id=current_user.id)


@router.get(
    "/{job_id}/download",
    summary="Download an export file",
    description=(
        "Download a completed export file for the authenticated user in the current tenant. The route is "
        "creator-scoped and tenant-scoped, and it only succeeds after the job reaches `completed`. "
        "The file is always returned as a direct binary download regardless of the configured storage backend."
    ),
    response_description="Binary file download.",
    responses=EXPORT_DOWNLOAD_RESPONSES,
)
async def download_export_file(
    job_id: str,
    request: Request,
    current_user: User = Depends(require_tenant_membership),
):
    """Download a completed export file."""
    tenant_id = UUID(str(request.state.tenant_id))
    download = await ExportService.get_download_target(job_id, tenant_id=tenant_id, user_id=current_user.id)
    if download.path is not None:
        return FileResponse(
            path=download.path,
            media_type=download.content_type,
            filename=download.filename,
        )
    if download.stream is not None:
        return StreamingResponse(
            download.stream,
            media_type=download.content_type,
            headers={"Content-Disposition": f'attachment; filename="{download.filename}"'},
        )
    raise RuntimeError("Export download target is incomplete")


@internal_router.post(
    "/process",
    summary="Process an internal export callback",
    description=(
        "Process a signed QStash callback for one queued export job. This endpoint is only available when "
        "QStash callbacks are enabled. It requires the `Upstash-Signature` header, validates the raw JSON "
        "payload, and executes the export idempotently. Repeated callbacks after a job has already completed "
        "or failed are ignored."
    ),
    response_model=ExportProcessCallbackResponse,
    response_description="Processed job identifier and final status.",
    responses=EXPORT_PROCESS_CALLBACK_RESPONSES,
    openapi_extra=EXPORT_PROCESS_CALLBACK_OPENAPI_EXTRA,
)
async def process_export_job_callback(
    request: Request,
    session: AsyncSession = Depends(get_db_session),
):
    """Process one export job through a signed QStash callback."""
    raw_body = await verify_qstash_request(
        request,
        path=f"{settings.api_prefix}/internal/qstash/exports/process",
    )
    payload = ExportProcessCallbackRequest.model_validate_json(raw_body)
    await ExportService.process_job(payload.job_id, session=session)
    snapshot = await ExportService.get_snapshot(payload.job_id)
    return {"job_id": snapshot.id, "status": snapshot.status}

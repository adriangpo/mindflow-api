"""Async export job router."""

from collections.abc import AsyncGenerator
from uuid import UUID

from fastapi import APIRouter, Depends, Request
from fastapi.responses import FileResponse, RedirectResponse, StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession

from src.config.settings import settings
from src.database.dependencies import get_db_session
from src.features.auth.dependencies import require_tenant_membership
from src.features.user.models import User
from src.shared.qstash import verify_qstash_request
from src.shared.redis import get_redis

from .schemas import ExportProcessCallbackRequest
from .service import ExportService

router = APIRouter(
    prefix="/exports",
    tags=["Exports"],
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


@router.get("/events")
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


@router.get("/{job_id}")
async def get_export_job(
    job_id: str,
    request: Request,
    current_user: User = Depends(require_tenant_membership),
):
    """Get the latest status for one export job."""
    tenant_id = UUID(str(request.state.tenant_id))
    return await ExportService.get_job_for_user(job_id, tenant_id=tenant_id, user_id=current_user.id)


@router.get("/{job_id}/download")
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
    if download.url is None:
        raise RuntimeError("Export download target is incomplete")
    return RedirectResponse(download.url, status_code=307)


@internal_router.post("/process")
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

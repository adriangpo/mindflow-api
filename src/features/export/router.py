"""Async export job router."""

from collections.abc import AsyncGenerator
from uuid import UUID

from fastapi import APIRouter, Depends, Request
from fastapi.responses import FileResponse, StreamingResponse

from src.config.settings import settings
from src.features.auth.dependencies import require_tenant_membership
from src.features.user.models import User
from src.shared.redis import get_redis

from .service import ExportService

router = APIRouter(
    prefix="/exports",
    tags=["Exports"],
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
    stored_file = await ExportService.get_download_file(job_id, tenant_id=tenant_id, user_id=current_user.id)
    return FileResponse(
        path=stored_file.path,
        media_type=stored_file.content_type,
        filename=stored_file.filename,
    )

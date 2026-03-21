"""Export runtime entrypoint."""

from .service import ExportService


async def run_export_worker_loop() -> None:
    """Run the Redis-backed export worker loop."""
    await ExportService.run_worker_loop()

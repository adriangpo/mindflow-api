"""Finance export storage helpers."""

from pathlib import Path
from uuid import UUID

from src.shared.storage import StorageBackend, StoredFile, get_local_storage_backend


class FinanceStorage:
    """Feature-level finance export storage adapter."""

    def __init__(self, backend: StorageBackend | None = None):
        self.backend = backend or get_local_storage_backend()

    @staticmethod
    def _tenant_prefix(tenant_id: UUID) -> Path:
        return Path("finance") / "exports" / str(tenant_id)

    def store_report_export(self, tenant_id: UUID, filename: str, payload: bytes) -> StoredFile:
        """Store a finance report PDF export."""
        relative_path = self._tenant_prefix(tenant_id) / filename
        return self.backend.store_bytes(relative_path, payload, content_type="application/pdf")

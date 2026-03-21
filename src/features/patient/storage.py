"""Patient export storage helpers."""

from pathlib import Path
from uuid import UUID

from src.shared.storage import StorageBackend, StoredFile, get_local_storage_backend


class PatientStorage:
    """Feature-level patient export storage adapter."""

    def __init__(self, backend: StorageBackend | None = None):
        self.backend = backend or get_local_storage_backend()

    @staticmethod
    def _tenant_prefix(tenant_id: UUID) -> Path:
        return Path("patients") / "exports" / str(tenant_id)

    def store_complete_patient_export(self, tenant_id: UUID, patient_id: int, payload: bytes) -> StoredFile:
        """Store a full patient dossier PDF export."""
        filename = f"patient-{patient_id}-complete.pdf"
        relative_path = self._tenant_prefix(tenant_id) / filename
        return self.backend.store_bytes(relative_path, payload, content_type="application/pdf")

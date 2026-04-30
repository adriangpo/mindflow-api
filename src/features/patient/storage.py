"""Patient export and photo storage helpers."""

from pathlib import Path
from uuid import UUID

from src.shared.storage import StorageBackend, StorageDownload, StoredFile, get_storage_backend


class PatientStorage:
    """Feature-level patient storage adapter."""

    def __init__(self, backend: StorageBackend | None = None):
        self.backend = backend or get_storage_backend()

    @staticmethod
    def _export_prefix(tenant_id: UUID) -> Path:
        return Path("patients") / "exports" / str(tenant_id)

    @staticmethod
    def _photo_prefix(tenant_id: UUID, patient_id: int) -> Path:
        return Path("patients") / "photos" / str(tenant_id) / str(patient_id)

    def store_complete_patient_export(self, tenant_id: UUID, patient_id: int, payload: bytes) -> StoredFile:
        """Store a full patient dossier PDF export."""
        filename = f"patient-{patient_id}-complete.pdf"
        relative_path = self._export_prefix(tenant_id) / filename
        return self.backend.store_bytes(relative_path, payload, content_type="application/pdf")

    def store_profile_photo(self, tenant_id: UUID, patient_id: int, data: bytes, content_type: str) -> StoredFile:
        """Store a patient profile photo."""
        ext = content_type.split("/")[-1] if "/" in content_type else "bin"
        filename = f"profile-photo.{ext}"
        relative_path = self._photo_prefix(tenant_id, patient_id) / filename
        return self.backend.store_bytes(relative_path, data, content_type=content_type)

    def resolve_profile_photo_download(self, relative_path: str | Path) -> StorageDownload:
        """Resolve a patient profile photo for download or redirect."""
        path = Path(relative_path)
        return self.backend.resolve_download(path, filename=path.name, content_type="image/jpeg")

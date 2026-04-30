"""Medical record export and attachment storage helpers."""

from pathlib import Path
from uuid import UUID, uuid4

from src.shared.storage import (
    StorageBackend,
    StorageDownload,
    StoredFile,
    get_storage_backend,
)


class MedicalRecordStorage:
    """Feature-level storage adapter for medical records."""

    def __init__(self, backend: StorageBackend | None = None):
        self.backend = backend or get_storage_backend()

    @staticmethod
    def _tenant_prefix(tenant_id: UUID) -> Path:
        return Path("medical-records") / "exports" / str(tenant_id)

    @staticmethod
    def _attachment_prefix(tenant_id: UUID, record_id: int) -> Path:
        return Path("medical-records") / "attachments" / str(tenant_id) / str(record_id)

    def store_single_record_export(self, tenant_id: UUID, record_id: int, payload: bytes) -> StoredFile:
        """Store a single-record PDF export."""
        filename = f"medical-record-{record_id}.pdf"
        relative_path = self._tenant_prefix(tenant_id) / "single" / filename
        return self.backend.store_bytes(relative_path, payload, content_type="application/pdf")

    def store_patient_history_export(self, tenant_id: UUID, patient_id: int, payload: bytes) -> StoredFile:
        """Store a patient history PDF export."""
        filename = f"medical-record-history-patient-{patient_id}.pdf"
        relative_path = self._tenant_prefix(tenant_id) / "patients" / str(patient_id) / "history" / filename
        return self.backend.store_bytes(relative_path, payload, content_type="application/pdf")

    def store_all_records_export(self, tenant_id: UUID, payload: bytes) -> StoredFile:
        """Store an all-patients PDF export."""
        filename = "medical-record-history-all-patients.pdf"
        relative_path = self._tenant_prefix(tenant_id) / "all" / filename
        return self.backend.store_bytes(relative_path, payload, content_type="application/pdf")

    def store_attachment(
        self,
        tenant_id: UUID,
        record_id: int,
        original_filename: str,
        data: bytes,
        content_type: str,
    ) -> StoredFile:
        """Store a medical record attachment file."""
        safe_name = f"{uuid4().hex[:8]}_{original_filename}"
        relative_path = self._attachment_prefix(tenant_id, record_id) / safe_name
        return self.backend.store_bytes(relative_path, data, content_type=content_type)

    def resolve_attachment_download(
        self,
        relative_path: str | Path,
        *,
        filename: str,
        content_type: str,
    ) -> StorageDownload:
        """Resolve a stored attachment for download or redirect."""
        return self.backend.resolve_download(Path(relative_path), filename=filename, content_type=content_type)

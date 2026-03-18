"""Medical record export storage helpers."""

from pathlib import Path
from uuid import UUID

from src.shared.storage import (
    StorageBackend,
    StoredFile,
    get_local_storage_backend,
)


class MedicalRecordStorage:
    """Feature-level export storage adapter."""

    def __init__(self, backend: StorageBackend | None = None):
        self.backend = backend or get_local_storage_backend()

    @staticmethod
    def _tenant_prefix(tenant_id: UUID) -> Path:
        return Path("medical-records") / "exports" / str(tenant_id)

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

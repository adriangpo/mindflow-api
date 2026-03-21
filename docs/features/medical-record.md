# Medical Record Feature

## Purpose

`src/features/medical_record` manages tenant-scoped digital medical records, including consultation note registration, patient history visualization, and async PDF export initiation for a single consultation, one patient history, or all patients in the tenant.

## Scope

Documented feature files:

- `src/features/medical_record/router.py`
- `src/features/medical_record/service.py`
- `src/features/medical_record/schemas.py`
- `src/features/medical_record/models.py`
- `src/features/medical_record/exceptions.py`

Direct dependencies used by this feature:

- `src/features/auth/dependencies.py` (`require_role`, `require_tenant_membership`)
- `src/database/dependencies.py` (`get_tenant_db_session`)
- `src/features/export/service.py` (async export job creation)
- `src/features/export/schemas.py` (`ExportJobKind`, `ExportJobResponse`)
- `src/features/patient/models.py` (`Patient` tenant validation)
- `src/features/schedule/models.py` (`ScheduleAppointment` optional linkage)
- `src/features/medical_record/storage.py` (feature-specific export storage paths)
- `src/shared/storage/backends.py` (local storage backend abstraction)
- `src/shared/pagination/pagination.py` (`PaginationParams`)

## Request Flow

```mermaid
sequenceDiagram
    participant Client
    participant Router as /api/medical-records
    participant Guard as require_role(owner) + require_tenant_membership
    participant TenantDB as get_tenant_db_session
    participant Service as MedicalRecordService
    participant DB as medical_records
    participant Export as ExportService

    Client->>Router: create/list/get/update/history/export-init
    Router->>Guard: role + tenant membership
    Guard-->>Router: authorized tenant owner
    Router->>TenantDB: tenant-scoped session
    TenantDB-->>Router: session.info.tenant_id
    Router->>Service: business operation
    Service->>DB: tenant-scoped read/write
    Router->>Export: create async export job for validated export requests
    Service-->>Router: model or export validation result
    Router-->>Client: DTO or 202 ExportJobResponse
```

## Data Model

```mermaid
erDiagram
    MedicalRecord {
        int id PK
        uuid tenant_id FK
        int patient_id FK
        int appointment_id FK
        int recorded_by_user_id FK
        datetime recorded_at
        string title
        text content
        text clinical_assessment
        text treatment_plan
        jsonb attachments
        datetime created_at
        datetime updated_at
    }
```

`medical_records` is tenant-scoped (`TenantMixin`) and auditable (`AuditableMixin`).

## Schemas And Validation

### `MedicalRecordCreateRequest`

Required:

- `patient_id > 0`
- `content` (trimmed, non-blank, max 20000)

Optional:

- `appointment_id > 0`
- `recorded_at` (timezone-aware datetime)
- `title` (trimmed non-blank if provided, max 255)
- `clinical_assessment` (trimmed non-blank if provided, max 20000)
- `treatment_plan` (trimmed non-blank if provided, max 20000)
- `attachments` (list of URLs, max 20, no duplicates)

### `MedicalRecordUpdateRequest`

All mutable fields are optional. Additional rules:

- if `recorded_at` is sent, it cannot be `null` and must be timezone-aware
- if `patient_id` is sent, it cannot be `null`
- if `content` is sent, it cannot be `null` and must be non-blank
- `attachments: null` clears attachments to an empty list

### Response DTOs

- `MedicalRecordResponse`: full medical record state
- `MedicalRecordListResponse`: paginated list envelope
- `MedicalRecordPatientHistoryResponse`: paginated patient history envelope

## Endpoints

Base path is `/api/medical-records`.

### `POST /api/medical-records`

Creates one medical record.

Behavior:

- validates patient exists in current tenant
- if `appointment_id` is provided, validates appointment exists in current tenant and belongs to the same patient
- sets `recorded_by_user_id` from current authenticated user

### `GET /api/medical-records`

Lists tenant medical records.

Query params:

- `page`, `page_size`
- `patient_id`
- `appointment_id`
- `search`
- `start_date`, `end_date` (applied to `recorded_at::date`)

Ordering: `recorded_at DESC, id DESC`.

### `GET /api/medical-records/patients/{patient_id}/history`

Returns paginated history of records for one patient.

Behavior:

- validates patient exists in tenant before listing

### `GET /api/medical-records/{record_id}`

Returns one medical record by id.

### `PUT /api/medical-records/{record_id}`

Updates one medical record.

Behavior:

- validates patient and appointment consistency on update
- if patient changes while appointment remains, appointment must still belong to the new patient

### `POST /api/medical-records/{record_id}/export/pdf`

Queues a single-record PDF export.

Behavior:

- validates the medical record exists in the current tenant
- creates an async export job with kind `medical_record_single_pdf`
- returns generic export job metadata instead of the file bytes

Success:

- `202` `ExportJobResponse`

Errors:

- `404` record not found
- `400`/`401`/`403` access, tenant, or auth failures

### `POST /api/medical-records/patients/{patient_id}/export/pdf`

Queues a patient-history PDF export.

Behavior:

- validates the patient exists in the current tenant
- validates at least one medical record exists for that patient
- creates an async export job with kind `medical_record_patient_history_pdf`

Success:

- `202` `ExportJobResponse`

Errors:

- `404` patient not found
- `404` no medical records exist for that patient
- `400`/`401`/`403` access, tenant, or auth failures

### `POST /api/medical-records/export/pdf`

Queues an all-records PDF export.

Behavior:

- validates at least one medical record exists in the tenant
- creates an async export job with kind `medical_record_all_pdf`

Success:

- `202` `ExportJobResponse`

Errors:

- `404` no medical records exist in the tenant
- `400`/`401`/`403` access, tenant, or auth failures

## Service Logic

`MedicalRecordService` centralizes:

- tenant context validation (`session.info["tenant_id"]`)
- patient existence checks in tenant scope
- appointment existence checks in tenant scope (`is_deleted=false`)
- patient/appointment consistency rules
- listing filters (patient, appointment, search, date range)
- export pre-validation for single, patient-history, and all-record queue requests
- in-memory PDF generation without external libraries (single and multi-page)
- export persistence through a segregated storage adapter (`MedicalRecordStorage` -> shared storage backend)

## Error Handling

Feature exceptions:

- `MedicalRecordNotFound` -> `404`
- `MedicalRecordPatientNotFound` -> `404`
- `MedicalRecordAppointmentNotFound` -> `404`
- `MedicalRecordAppointmentPatientMismatch` -> `409`
- `MedicalRecordExportEmpty` -> `404`

Access and tenancy errors come from shared dependencies (`400/401/403`), and schema validation errors return `422`.

## Side Effects

- Write endpoints (`POST`, `PUT`) commit at router boundary.
- `MedicalRecord` inherits `AuditableMixin`, so create/update operations emit entries into `audit_logs` automatically.
- Export initiation endpoints are read-only from the database perspective, validate exportability, and enqueue a generic export job.
- Completed files are stored under `storage/medical-records/exports/<tenant-id>/...` by the shared export worker.

## Frontend Integration Notes

- Send `X-Tenant-ID` header and Bearer token for every endpoint.
- Only `tenant_owner` role is allowed; `assistant` users receive `403`.
- `attachments` should be URL strings; the backend does not upload files.
- Export initiation endpoints return `202 ExportJobResponse`; use `/api/exports/{job_id}`, `/api/exports/events`, and `/api/exports/{job_id}/download` for progress and file retrieval.

# Export Feature

## Purpose

`src/features/export` manages creator-scoped async export jobs for medical records, patients, and finance reports. It stores job state in Redis, exposes generic progress/download endpoints, and streams status changes to the frontend with SSE. Execution is dual-mode: local and test environments use the resident Redis worker, while production can publish a signed QStash callback that processes the export inside a normal HTTP request.

## Scope

Documented feature files:

- `src/features/export/router.py`
- `src/features/export/service.py`
- `src/features/export/schemas.py`
- `src/features/export/runtime.py`

Direct dependencies used by this feature:

- `src/features/auth/dependencies.py` (`require_tenant_membership`)
- `src/features/medical_record/service.py` (medical record PDF generation)
- `src/features/patient/service.py` (patient dossier PDF generation)
- `src/features/finance/service.py` (finance report PDF generation)
- `src/shared/redis/client.py` (Redis client, streams, JSON helpers)
- `src/shared/storage/backends.py` (local or S3-compatible stored file resolution)
- `src/shared/qstash/client.py` (signed callback publishing and verification)
- `src/config/settings.py` (dispatch mode, worker, TTL, and SSE settings)

## Request Flow

```mermaid
sequenceDiagram
    participant Client
    participant FeatureRouter as feature POST .../export/pdf
    participant ExportService
    participant Redis as snapshots + creator events
    participant Dispatcher as Redis worker or QStash
    participant Internal as /api/internal/qstash/exports/process
    participant FeatureService as medical/patient/finance service
    participant Storage as local or S3 storage

    Client->>FeatureRouter: queue export request
    FeatureRouter->>ExportService: create_job(...)
    ExportService->>Redis: SET job snapshot + XADD user event stream
    ExportService->>Dispatcher: enqueue Redis work item or publish signed callback
    FeatureRouter-->>Client: 202 ExportJobResponse
    Dispatcher->>ExportService: process_job(job_id)
    QStash->>Internal: signed POST callback
    Internal->>ExportService: process_job(job_id)
    ExportService->>FeatureService: build PDF for job kind
    FeatureService->>Storage: store generated file
    ExportService->>Redis: update snapshot + publish creator event
    Client->>ExportService: GET /api/exports/{job_id}
    Client->>ExportService: GET /api/exports/{job_id}/download
```

## Data Model

```mermaid
stateDiagram-v2
    [*] --> queued
    queued --> running
    running --> completed
    running --> failed
```

Runtime state is Redis-backed, not database-backed.

Keys and structures:

- `exports:jobs`: Redis stream used as the worker queue in `redis_worker` mode
- `exports:workers`: consumer group used by background workers in `redis_worker` mode
- `exports:job:{job_id}`: JSON snapshot for one job
- `exports:user:{tenant_id}:{user_id}:events`: Redis stream used by the SSE endpoint for creator-scoped updates

Stored file bytes are persisted by the configured storage backend. In development that is usually local disk under `storage/`; in production it can be an S3-compatible backend such as Cloudflare R2. Redis stores only metadata such as `file_relative_path`, `filename`, and `content_type`.

## Schemas And Validation

### `ExportJobKind`

- `medical_record_single_pdf`
- `medical_record_patient_history_pdf`
- `medical_record_all_pdf`
- `patient_complete_pdf`
- `finance_report_pdf`

### `ExportJobStatus`

- `queued`
- `running`
- `completed`
- `failed`

### `ExportJobResponse`

Public response fields:

- `id`
- `kind`
- `status`
- `progress_current`
- `progress_total`
- `progress_message`
- `download_url`
- `error_detail`
- `created_at`
- `updated_at`

### `FinanceReportExportRequest`

Used by `POST /api/finance/report/export/pdf`:

- `view`: `day|week|month|year|total|custom`, default `day`
- `reference_date`: optional date for non-custom windows
- `start_date`, `end_date`: optional dates validated by the finance service for `custom`

Validation behavior:

- generic export endpoints are creator-scoped and tenant-scoped; a job created by another user is returned as `404`
- download is allowed only when job status is `completed`
- feature-specific initiation endpoints perform synchronous existence/range checks before queueing

## Endpoints

Base path is `/api/exports`.

### `GET /api/exports/events`

Opens a server-sent events stream for the authenticated user in the current tenant.

Behavior:

- media type is `text/event-stream`
- emits `event: export.updated`
- `data:` contains the JSON-serialized `ExportJobResponse`
- sends keepalive comments when no export update is available
- only receives events for jobs created by the current user in the current tenant

Success:

- `200` streaming SSE response

Errors:

- `400`/`401`/`403` tenant or auth failures

### `GET /api/exports/{job_id}`

Returns the latest snapshot for one export job.

Success:

- `200` `ExportJobResponse`

Errors:

- `404` job does not exist or does not belong to the current user in the current tenant

### `GET /api/exports/{job_id}/download`

Downloads the finished export file.

Behavior:

- local storage mode resolves the file from the stored relative path under `storage/`
- S3-compatible storage mode returns a short-lived redirect to a presigned object URL
- always enforces creator and tenant scoping before resolving the asset

Success:

- `200` file response in local mode
- `307` redirect to a presigned object URL in S3 mode

Errors:

- `404` job does not exist, is not creator-scoped to the current user, or file metadata/path is missing
- `409` job has not completed yet

### `POST /api/internal/qstash/exports/process`

Internal-only endpoint used in `qstash` mode.

Behavior:

- requires a valid `Upstash-Signature` header over the raw request body
- accepts `{ "job_id": "<id>" }`
- processes the queued job idempotently

Success:

- `200` with the latest `job_id` and `status`

Errors:

- `401` missing or invalid QStash signature
- `404` when `JOB_DISPATCH_MODE` is not `qstash`

## Service Logic

`ExportService` centralizes:

- `create_job(...)`: creates the initial `queued` snapshot and dispatches the job through Redis workers or QStash
- `get_job_for_user(...)`: enforces tenant + creator scoping for status reads
- `get_download_target(...)`: enforces tenant + creator scoping for downloads and resolves a local file or presigned redirect
- `update_snapshot(...)`: persists progress/status updates and appends creator-scoped SSE events
- `_build_export_file(...)`: dispatches the job to the correct feature service based on `ExportJobKind`
- `process_job(...)`: moves one job through `running` to `completed` or `failed` and ignores duplicate callback delivery after completion/failure
- `consume_one_batch(...)`: claims stale jobs with `XAUTOCLAIM`, reads new jobs with `XREADGROUP`, processes them, and acknowledges stream entries
- `run_worker_loop()`: long-running worker loop started from app lifespan

Worker/runtime behavior:

- dispatch mode is selected by `JOB_DISPATCH_MODE=redis_worker|qstash`
- export worker startup is controlled by `EXPORT_WORKER_ENABLED`
- worker blocking is controlled by `EXPORT_WORKER_BLOCK_MS`
- stale pending messages are reclaimed with `EXPORT_WORKER_CLAIM_IDLE_MS`
- SSE keepalive interval is controlled by `EXPORT_SSE_KEEPALIVE_SECONDS`
- job snapshot TTL is controlled by `EXPORT_JOB_TTL_SECONDS`
- creator event stream trimming and expiry are controlled by `EXPORT_EVENT_STREAM_MAXLEN` and `EXPORT_EVENT_STREAM_TTL_SECONDS`

## Error Handling

Feature-level HTTP errors:

- `404` `Export job not found`
- `404` `Export file not found`
- `409` `Export job is not completed yet`
- `409` `Export file metadata is incomplete`

Runtime behavior:

- job execution failures do not remove the job snapshot
- failed jobs remain queryable with `status=failed` and `error_detail`
- feature-specific validation errors raised during job execution are surfaced as failed-job details

## Side Effects

- job state is written to Redis snapshots and streams
- completed files are persisted under the owning feature path in the configured storage backend:
  - `storage/medical-records/exports/<tenant-id>/...`
  - `storage/patients/exports/<tenant-id>/...`
  - `storage/finance/exports/<tenant-id>/...`
- app lifespan starts the resident export worker only when `JOB_DISPATCH_MODE=redis_worker`, `EXPORT_WORKER_ENABLED=true`, and `TESTING=false`
- in `qstash` mode the internal callback verifies `Upstash-Signature` before processing the job

## Frontend Integration Notes

- Export creation does not happen under `/api/exports`; it starts from feature-specific `POST .../export/pdf` routes.
- Store the returned `job_id` and subscribe to `/api/exports/events` for live status changes.
- Polling `/api/exports/{job_id}` remains the most reliable integration pattern when `qstash` mode is enabled.
- Use `download_url` only after the job reaches `completed`.

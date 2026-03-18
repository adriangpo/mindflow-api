# Finance Feature

## Purpose

`src/features/finance` manages tenant-scoped financial reporting and manual financial entries. It combines automatic consultation revenue derived from paid appointments with manually entered income and expense records.

## Scope

Documented feature files:

- `src/features/finance/router.py`
- `src/features/finance/service.py`
- `src/features/finance/schemas.py`
- `src/features/finance/models.py`
- `src/features/finance/exceptions.py`

Direct dependencies used by this feature:

- `src/features/auth/dependencies.py` (`require_role`, `require_tenant_membership`)
- `src/database/dependencies.py` (`get_tenant_db_session`)
- `src/features/schedule/models.py` (`ScheduleAppointment` for automatic consultation revenue)
- `src/features/schedule/schemas.py` (`PaymentStatus`)
- `src/shared/pagination/pagination.py` (`PaginationParams`)
- `src/shared/audit/audit.py` (`AuditableMixin`)

## Request Flow

```mermaid
sequenceDiagram
    participant Client
    participant Router as /api/finance/*
    participant Guard as require_role(owner|assistant) + require_tenant_membership
    participant TenantDB as get_tenant_db_session
    participant Service as FinanceService
    participant DB as financial_entries + schedule_appointments

    Client->>Router: create/list/get/reverse/report
    Router->>Guard: RBAC + tenant assignment
    Guard-->>Router: authorized tenant user
    Router->>TenantDB: tenant-scoped session
    TenantDB-->>Router: session.info.tenant_id
    Router->>Service: business operation
    Service->>DB: manual entries and report aggregates
    Service-->>Router: model or summary payload
    Router-->>Client: DTO or report response
```

## Data Model

```mermaid
erDiagram
    FinancialEntry {
        int id PK
        uuid tenant_id FK
        int created_by_user_id FK
        string entry_type
        string classification
        string description
        decimal amount
        date occurred_on
        text notes
        bool is_reversed
        datetime reversed_at
        int reversed_by_user_id FK
        text reversal_reason
        datetime created_at
        datetime updated_at
    }
```

`financial_entries` is tenant-scoped (`TenantMixin`) and auditable (`AuditableMixin`).

Automatic consultation revenue is not stored in this table. It is computed from `schedule_appointments` rows where:

- `payment_status = paid`
- `is_deleted = false`
- `paid_at IS NOT NULL`

## Schemas And Validation

### Enums

- `FinancialEntryType`: `income`, `expense`
- `FinancialEntryClassification`: `fixed`, `variable`
- `FinanceReportView`: `day`, `week`, `month`, `year`, `total`, `custom`

### `FinancialEntryCreateRequest`

- `entry_type`: required enum
- `classification`: required enum
- `description`: required trimmed non-blank string, max 255
- `amount`: required decimal `> 0`, max digits 10, scale 2
- `occurred_on`: required date
- `notes`: optional trimmed non-blank string when provided, max 5000

### `FinancialEntryReverseRequest`

- `reversal_reason`: required trimmed non-blank string, min 3, max 500

### Response DTOs

- `FinancialEntryResponse`: full manual entry state including reversal metadata
- `FinancialEntryListResponse`: paginated list envelope
- `FinanceReportResponse`: aggregated totals and counts for the selected report window

## Endpoints

Base path is `/api/finance`.

### `POST /api/finance/entries`

Creates one manual financial entry.

Behavior:

- stores `created_by_user_id` from current authenticated user
- entries are append-only in v1

### `GET /api/finance/entries`

Lists manual financial entries.

Query params:

- `page`, `page_size`
- `entry_type`
- `classification`
- `start_date`, `end_date`
- `include_reversed` (default `false`)

Ordering:

- `occurred_on DESC, id DESC`

Behavior:

- when `include_reversed=false`, reversed entries are excluded
- when both dates are provided, `end_date` must be greater than or equal to `start_date`

### `GET /api/finance/entries/{entry_id}`

Returns one manual financial entry by id.

### `POST /api/finance/entries/{entry_id}/reverse`

Reverses one manual financial entry.

Behavior:

- sets `is_reversed=true`
- stores `reversed_at`, `reversed_by_user_id`, and `reversal_reason`
- rejects already reversed rows with `409`

### `GET /api/finance/report`

Returns an aggregated finance summary.

Query params:

- `view`: `day|week|month|year|total|custom` (default `day`)
- `reference_date`: optional date used for `day|week|month|year`
- `start_date`, `end_date`: required only when `view=custom`

Report semantics:

- automatic income uses `schedule_appointments.paid_at`
- manual entries use `financial_entries.occurred_on`
- `custom` is inclusive on both dates
- `total` ignores date filters and returns `range_start=null`, `range_end=null`

Response totals:

- `automatic_income_total`
- `manual_income_total`
- `manual_expense_total`
- `total_income`
- `total_expense`
- `net_total`
- `paid_appointments_count`
- `manual_income_count`
- `manual_expense_count`

## Service Logic

`FinanceService` centralizes:

- tenant context validation (`session.info["tenant_id"]`)
- manual entry creation, lookup, listing, and reversal
- date-range resolution for `day|week|month|year|total|custom`
- aggregate report computation across:
  - `financial_entries` for manual income/expenses
  - `schedule_appointments` for automatic paid consultation revenue

Reporting rules:

- reversed manual entries are excluded from all report totals
- deleted appointments are excluded from automatic revenue
- appointment status does not affect revenue once payment status is `paid`
- automatic revenue amount uses the persisted appointment `charge_amount` snapshot

## Error Handling

Feature exceptions:

- `FinancialEntryNotFound` -> `404`
- `FinancialEntryAlreadyReversed` -> `409`
- `FinanceCustomRangeRequired` -> `400`
- `FinanceInvalidCustomRange` -> `400`

Access and tenancy errors come from shared dependencies (`400/401/403`), and schema validation errors return `422`.

## Side Effects

- `POST /entries` and `POST /entries/{id}/reverse` commit at router boundary.
- `FinancialEntry` inherits `AuditableMixin`, so creation and reversal emit entries into `audit_logs`.
- Finance reports are read-only and do not materialize derived appointment revenue rows.

## Frontend Integration Notes

- Send `X-Tenant-ID` header and Bearer token for every finance endpoint.
- Both `tenant_owner` and `assistant` roles are allowed.
- Manual entry corrections in v1 require reversal plus a new replacement entry.
- Report windows use UTC calendar boundaries for appointment `paid_at` aggregation.

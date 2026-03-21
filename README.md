# Mindflow API

FastAPI backend for multi-tenant clinical scheduling and patient management.

The API now uses Redis for two runtime concerns:

- async export jobs and live export progress events
- notification scheduling and delivery queues

## Quick Start

### 1. Install dependencies

```bash
make install
# or
uv sync --all-extras
```

### 2. Configure environment

```bash
cp .env.example .env
```

Set at least:

- `SECRET_KEY`

Database configuration options:

- `POSTGRES_URL` (full connection string override)
- or `POSTGRES_USER` + `POSTGRES_PASSWORD` + `POSTGRES_DB` + `POSTGRES_HOST` + `POSTGRES_PORT`
- `REDIS_URL`
- `NOTIFICATION_PROVIDER` (`auto`, `stub`, or `twilio`)
- `NOTIFICATION_BACKGROUND_DISPATCH_ENABLED` (default `true`)
- `NOTIFICATION_DISPATCH_INTERVAL_SECONDS` (default `60`)
- `EXPORT_WORKER_ENABLED` (default `true`)
- `EXPORT_SSE_KEEPALIVE_SECONDS` (default `15`)
- `NOTIFICATION_DEFAULT_COUNTRY_CODE` (default `+55`, used to format stored local phone numbers)
- `TWILIO_ACCOUNT_SID`
- `TWILIO_AUTH_TOKEN`
- `TWILIO_WHATSAPP_FROM_NUMBER`

For Docker runs, API container uses `POSTGRES_URL` when provided; otherwise it builds one from `POSTGRES_USER/PASSWORD/HOST/DB` using internal PostgreSQL port `5432`.
Default `.env.example` sets `POSTGRES_HOST=postgres` for Docker networking.
If you run API locally (outside Docker), set `POSTGRES_HOST=localhost`.
Default `.env.example` also sets `REDIS_URL=redis://redis:6379/0` for Docker networking.

### 3. Start services (Docker)

```bash
make docker-start ENVIRONMENT=development
```

`make docker-start` starts API + PostgreSQL + Redis containers for the selected profile.

If you want to run API locally with `uv run`, start PostgreSQL and Redis separately (for example: `docker compose up -d postgres redis`).

### 4. Run migrations

```bash
make db-upgrade
# or
uv run alembic upgrade head
```

### 5. Run API (local only)

```bash
uv run uvicorn src.main:app --reload
```

Skip this step when using `make docker-start` because API is already running in Docker.

- API root: `http://localhost:8000/`
- Health check: `http://localhost:8000/health`
- Docs routes (`/docs`, `/redoc`, `/openapi.json`):
  - `development`: public
  - non-development environments: admin-only

### Twilio WhatsApp

Notification delivery defaults to `auto` mode:

- if `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, and `TWILIO_WHATSAPP_FROM_NUMBER` are set, outbound WhatsApp uses Twilio
- otherwise the API stays on the internal stub backend and only logs notifications

Stored patient/profile phone numbers are local digits in this project, so outbound delivery prefixes them with `NOTIFICATION_DEFAULT_COUNTRY_CODE` before sending to Twilio.
For Twilio sandbox testing, use the Twilio sandbox sender number and join the sandbox from the recipient device first.

## Architecture Summary

- App entrypoint: `src/main.py`
- Feature modules: `src/features/{auth,user,tenant,export,schedule_config,patient,schedule,finance,medical_record,notification}`
- Shared modules: `src/shared/*`
- Database migrations: `alembic/versions/*`
- Redis runtime state:
  - export jobs and creator-scoped export event streams
  - notification schedule ZSET and per-tenant delivery streams

Tenant-protected endpoints require:

1. `Authorization: Bearer <access_token>`
2. `X-Tenant-ID: <tenant_uuid>`
3. Tenant membership validation

Tenant-scoped tables use PostgreSQL RLS policies keyed by `app.current_tenant`.

Export flows are async:

- feature-specific `POST .../export/pdf` endpoints return `202 Accepted` with an export job payload
- generic `/api/exports/{job_id}` returns progress
- generic `/api/exports/events` streams SSE updates for the authenticated user in the current tenant
- generic `/api/exports/{job_id}/download` serves the finished file

## Authentication

- JWT access token (default 30 minutes)
- JWT refresh token (7 days, persisted in `refresh_tokens`)
- Account lock protection:
  - after 5 failed login attempts, account is locked for 30 minutes
  - when lock expiry is reached, account is automatically restored to `active`

Roles (`src/features/user/models.py`):

- `admin`
- `tenant_owner`
- `assistant`

## CORS

CORS config lives in `src/config/cors_config.py`.

Development defaults (when `CORS_ALLOW_ORIGINS` is not set):

- `http://localhost:3000`
- `http://localhost:8000`
- `http://127.0.0.1:3000`
- `http://127.0.0.1:8000`

Production/staging require explicit origin configuration (no wildcard policy in those environments).

## Testing And Quality

Tests run against PostgreSQL (not SQLite) and apply Alembic migrations before test execution.
Tests also require Redis for export and notification queue/runtime coverage.

Create test env file before running test DB commands:

```bash
cp .env.test.example .env.test
```

Test DB variables in `.env.test` use `TEST_POSTGRES_*`:

- `TEST_POSTGRES_USER`
- `TEST_POSTGRES_PASSWORD`
- `TEST_POSTGRES_DB`
- `TEST_POSTGRES_HOST`
- `TEST_POSTGRES_PORT`
- optional `TEST_POSTGRES_URL` override

Test Redis variables in `.env.test`:

- `TEST_REDIS_URL`
- `REDIS_URL` (used by the app runtime during tests)

```bash
make check-all
make test
```

Useful targets:

- `make lint`
- `make type-check`
- `make test-cov`
- `make docker-test-up`
- `make docker-test-down`

`make docker-test-up` starts both `postgres_test` and `redis_test`.

## Feature Docs

Implementation-focused docs are under `docs/features/`:

- `docs/features/auth.md`
- `docs/features/user.md`
- `docs/features/tenant.md`
- `docs/features/schedule-config.md`
- `docs/features/patient.md`
- `docs/features/schedule.md`
- `docs/features/finance.md`
- `docs/features/medical-record.md`
- `docs/features/notification.md`
- `docs/features/export.md`

# AGENTS.md

## Purpose
This file is the source of truth for autonomous/code-assistant agents working in this repository.
Follow it to extend the API without duplicating logic or breaking existing architecture.

## System Architecture (Current)
Mindflow API is a FastAPI backend with feature-based modules and SQLAlchemy async persistence.

Request flow:
1. `src/main.py` bootstraps app, middleware, and router registration.
2. Middleware runs in this order (added order):
   - `SlowAPIMiddleware` (rate limiting)
   - `admin_docs_middleware`
   - `CORSMiddleware`
   - `TenantMiddleware` (extracts `X-Tenant-ID` to `request.state.tenant_id`)
   - `AuditContextMiddleware`
3. Router dependencies enforce auth/tenant requirements.
4. DB sessions are provided by:
   - `get_db_session()` for global (non-tenant) tables
   - `get_tenant_db_session()` for tenant-scoped tables with RLS context set via `SET LOCAL app.current_tenant`
5. Services implement business logic; routers orchestrate I/O and commits.

## Folder Ownership
- `src/features/<feature>/models.py`: SQLAlchemy entities (domain data)
- `src/features/<feature>/schemas.py`: Pydantic DTOs (request/response contracts)
- `src/features/<feature>/service.py`: business rules + persistence queries
- `src/features/<feature>/router.py`: HTTP layer and dependency wiring
- `src/features/<feature>/exceptions.py`: feature-specific HTTP exceptions
- `src/features/auth/dependencies.py`: auth/role/permission dependencies (shared by all features)
- `src/shared/*`: cross-feature building blocks (tenancy, audit, pagination, validators, middleware)
- `alembic/versions/*`: schema migrations
- `tests/features/<feature>/*`: feature behavior tests

## How to Add a New Feature (Canonical Sequence)
1. Create `src/features/<feature>/` with files:
   - `models.py`, `schemas.py`, `service.py`, `router.py`, `exceptions.py`, `__init__.py`
2. Decide scope:
   - Global table: inherit from `Base` (+ optional `TimestampMixin`, `AuditableMixin`)
   - Tenant table: include tenant strategy (`TenantMixin`) and use tenant DB dependency (`get_tenant_db_session`)
   - Tenant table migrations must include explicit tenant isolation enforcement (RLS policy or project-approved equivalent)
3. Put pure validation and data shape in `schemas.py`.
4. Put all DB queries and business decisions in `service.py`.
5. Keep `router.py` thin:
   - Dependency injection
   - Input/output conversion
   - `await session.commit()` on write endpoints
6. Register router in `src/main.py`:
   - `public_routers` if no tenant header required
   - `tenant_routers` if `X-Tenant-ID` is required
7. Create migration in `alembic/versions/` for schema changes.
8. Ensure Alembic model import coverage in `alembic/env.py` (so autogenerate/metadata sees models).
9. Add tests under `tests/features/<feature>/` for service and API behavior.
10. Add/update docs under `docs/` (feature docs + affected architecture/API/testing docs).

## Anti-Duplication Rules (Mandatory)
Before adding any helper, dependency, validator, or util:
1. Search existing code first:
   - `src/shared/`
   - `src/features/auth/dependencies.py`
   - sibling feature `service.py` and `schemas.py`
2. Reuse existing primitives instead of re-implementing:
   - Password strength: `src/shared/validators/password.py`
   - Pagination: `src/shared/pagination/pagination.py`
   - Auth user extraction / role checks: `get_current_user`, `require_role`, `require_permission`
   - Tenant enforcement: `require_tenant`, `get_tenant_db_session`, `set_tenant_context`
   - Audit tracking: `AuditableMixin` + audit middleware/context
3. Never copy-paste query logic across features. Extract to a shared helper only when used in 2+ places.
4. Never duplicate DTO fields with different names for the same concept unless compatibility requires it.
5. Never add a second implementation of JWT/token/role logic outside `src/features/auth` unless explicitly required.

## File Creation Standards
- Keep one domain concept per feature package.
- Keep model names singular (`User`, `RefreshToken`), table names plural.
- Add docstrings for modules/classes/functions that encode domain intent.
- Use timezone-aware timestamps (`datetime.now(UTC)`) consistently.
- For request/response endpoints using dependency-injected DB sessions, commit at router boundary (not deep utility layers).
- Do not open independent `get_session()` context managers inside service methods used by routers.
- Standalone scripts/CLI jobs that use `get_session()` may rely on context-manager commit behavior.
- All docs live in `docs/`. Every `docs/*.md` file created or changed must include at least one Mermaid diagram.

## Consistency Checks Before Finishing
1. Router is registered in `src/main.py` under the correct router list.
2. DB session dependency matches model scope (global vs tenant).
3. Migration file exists and down/up revisions are correct.
4. `alembic/env.py` imports the new feature models.
5. Tests added or updated.
6. No duplicated helper introduced where a shared one already exists.
7. Relevant docs in `docs/` are updated and include Mermaid diagrams.
8. Quality gates pass:
   - `make lint`
   - `make type-check`
   - relevant `pytest` scope (or full suite when touching shared/core layers)

## Current Known Mismatch to Resolve When Touching Migrations
- `src/features/schedule_config` exists, but `alembic/env.py` does not import `src.features.schedule_config.models`.
- If you work on migrations/features, add/fix model imports in `alembic/env.py` so Alembic autogenerate sees all metadata.

## Definition of Done for Agent Changes
A change is complete only if:
1. Architecture rules above are followed.
2. No duplication was introduced.
3. New/changed behavior is covered by tests.
4. App startup + migration path remain coherent.
5. Required docs under `docs/` are updated (with Mermaid diagrams).
6. Quality checks pass (`make lint`, `make type-check`, and appropriate tests).

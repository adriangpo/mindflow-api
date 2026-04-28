# Inconsistencies Audit

This file records cross-cutting inconsistencies found during the April 2026 codebase audit. Each item describes the pattern, where it occurs, and the agreed resolution.

---

## 1. Duplicated Helper Functions Across Schema Files

**Pattern**: Identical utility functions defined independently in multiple schema files.

| Function | Files |
|---|---|
| `_normalize_text` | `finance/schemas.py`, `medical_record/schemas.py` |
| `_ensure_timezone_aware` | `medical_record/schemas.py`, `schedule/schemas.py` |
| `default_reference_date` | `finance/schemas.py`, `schedule/schemas.py` |

**Resolution**: Extract each function into a shared utility module (e.g. `src/shared/schema_utils.py`) and import from there.

---

## 2. Portuguese Error Messages in Notification Feature

**Pattern**: `notification/exceptions.py` uses Portuguese strings for exception messages; all other feature `exceptions.py` files use English.

**Resolution**: Translate all notification exception messages to English to match the project-wide standard.

---

## 3. Inconsistent Validator Naming Convention

**Pattern**: Pydantic validators in `auth/schemas.py`, `user/schemas.py`, and `schedule_config/schemas.py` are named without the `_` prefix (e.g. `validate_password`). All other schema files use the `_`-prefix convention (e.g. `_validate_password`).

**Resolution**: Prefix all validator method names with `_` to match the project standard.

---

## 4. Missing Type Annotations and Docstrings on Validators

**Pattern**: Validators in `auth/schemas.py` and `user/schemas.py` lack return type annotations and have multi-line docstrings. Project standard is full type annotations and no docstrings on validators.

**Resolution**: Add return type annotations; remove docstrings from validator methods.

---

## 5. Missing `model_config` on Notification Response Schemas

**Pattern**: `NotificationPatientPreferenceResponse` and `NotificationUserProfileResponse` in `notification/schemas.py` are missing `model_config = {"from_attributes": True}`, but are populated via `model_validate(orm_object)` in the service layer.

**Resolution**: Add `model_config = {"from_attributes": True}` to both schemas.

---

## 6. Inline Comments Inside Schema Field Definitions

**Pattern**: `tenant/schemas.py` has `# For inactivating a tenant, use the delete route.` inline after a field; `schedule_config/schemas.py` has `# user_id is the creator/owner reference; configuration semantics are tenant-wide.` on the `user_id` field.

**Resolution**: Remove inline comments from schema field declarations. Explanatory context belongs in OpenAPI `description` strings or router-level `description` fields.

---

## 7. Section-Header Comments in Model Files

**Pattern**: `auth/models.py` and `user/models.py` use inline comments as section headers (e.g. `# --- Identity ---`, `# --- Status ---`). Other model files have no such comments.

**Resolution**: Remove section-header comments from model files. Model fields should be self-documenting via their names and types.

---

## 8. Multi-Line Docstrings on ORM Model Classes

**Pattern**: `RefreshToken`, `User`, and `Tenant` models have multi-line docstrings with `Args`/`Example` blocks. All other model classes use single-line docstrings.

**Resolution**: Reduce to single-line docstrings. Detailed documentation belongs in `AGENTS.md` or feature docs.

---

## 9. Missing `description` on `include_deleted` Query Parameter

**Pattern**: `get_appointment_detail` in `schedule/router.py` has `include_deleted: bool = Query(default=False)` without a `description`. All other `Query(...)` parameters in the project include one (per Section 16.3 of `AGENTS.md`).

**Resolution**: Add `description="When true, returns the appointment even if it has been soft-deleted."` (or equivalent) to the `include_deleted` parameter.

---

## 10. Inline Comments in `main.py`

**Pattern**: `main.py` uses inline section-label comments (e.g. `# --- Middleware ---`, `# --- Routers ---`) and has `_ = request, exc` discards in the `rate_limit_handler`. Section-label comments are not used elsewhere in the codebase.

**Resolution**: Remove section-label comments; replace discard pattern with named variables or explicit `# noqa` markers if needed for linter compliance.

---

## 11. Manual `updated_at` Assignments in Service Methods

**Pattern**: `user/service.py` (7 occurrences) and `tenant/service.py` (3 occurrences) manually assign `model.updated_at = datetime.now(UTC)` after mutating ORM-model attributes. `TimestampMixin` already declares `onupdate=lambda: datetime.now(UTC)`, so SQLAlchemy handles this automatically for every ORM-generated `UPDATE`.

**Resolution** (applied): Removed all manual `updated_at` assignments and the now-unused `from datetime import UTC, datetime` imports from both service files. The only legitimate manual `updated_at` assignment is in `export/service.py` for the Redis-backed `ExportJobSnapshot` Pydantic model, which is not an ORM entity. See `AGENTS.md` Section 17.1.

# Notification Feature

## Purpose

`src/features/notification` manages tenant-scoped notification settings, patient and user delivery configuration, notification message history/outbox, due dispatch, and schedule-driven appointment notifications for confirmation, update, cancellation, and reminder events.

## Scope

Documented feature files:

- `src/features/notification/router.py`
- `src/features/notification/service.py`
- `src/features/notification/schemas.py`
- `src/features/notification/models.py`
- `src/features/notification/exceptions.py`
- `src/features/notification/delivery.py`
- `src/features/notification/runtime.py`

Direct dependencies used by this feature:

- `src/features/auth/dependencies.py` (`require_role`, `require_tenant_membership`)
- `src/database/dependencies.py` (`get_tenant_db_session`)
- `src/database/client.py` (`get_session`, `set_tenant_context`)
- `src/features/patient/models.py` (`Patient` lookups and default contact phone)
- `src/features/schedule/models.py` (`ScheduleAppointment` notification source)
- `src/features/schedule/schemas.py` (`AppointmentStatus` active reminder states)
- `src/features/user/models.py` (`User` tenant assignment and active status)
- `src/features/tenant/models.py` (`Tenant` iteration for background dispatch)
- `src/shared/pagination/pagination.py` (`PaginationParams`)
- `src/config/settings.py` (background dispatch and provider settings)

## Request Flow

```mermaid
sequenceDiagram
    participant Client
    participant Router as /api/notifications/*
    participant Guard as require_role(owner|assistant) + require_tenant_membership
    participant TenantDB as get_tenant_db_session
    participant Service as NotificationService
    participant DB as settings + profiles + messages
    participant Backend as delivery backend

    Client->>Router: get/update settings or profiles, list messages, dispatch due
    Router->>Guard: RBAC + tenant assignment
    Guard-->>Router: authorized tenant user
    Router->>TenantDB: tenant-scoped session
    TenantDB-->>Router: session.info.tenant_id
    Router->>Service: business operation
    Service->>DB: read/write tenant-scoped records
    Service->>Backend: send due WhatsApp messages
    Backend-->>Service: delivery result
    Service-->>Router: DTO/result
    Router-->>Client: response
```

## Data Model

```mermaid
erDiagram
    NotificationSettings ||--o{ NotificationMessage : "controls defaults"
    NotificationPatientPreference }o--|| Patient : "overrides"
    NotificationUserProfile }o--|| User : "configures"
    NotificationMessage }o--|| ScheduleAppointment : "tracks"
    NotificationMessage }o--o| Patient : "patient recipient"
    NotificationMessage }o--o| User : "user recipient"

    NotificationSettings {
        int id PK
        uuid tenant_id FK
        bool patient_notifications_enabled
        bool user_notifications_enabled
        bool reminders_enabled
        bool notify_on_create
        bool notify_on_update
        bool notify_on_cancel
        int default_reminder_minutes_before
        datetime created_at
        datetime updated_at
    }

    NotificationPatientPreference {
        int id PK
        uuid tenant_id FK
        int patient_id FK
        bool is_enabled
        string contact_phone
        int reminder_minutes_before
        datetime created_at
        datetime updated_at
    }

    NotificationUserProfile {
        int id PK
        uuid tenant_id FK
        int user_id FK
        bool is_enabled
        string contact_phone
        bool receive_appointment_notifications
        bool receive_reminders
        datetime created_at
        datetime updated_at
    }

    NotificationMessage {
        int id PK
        uuid tenant_id FK
        int appointment_id FK
        int patient_id FK
        int recipient_user_id FK
        string recipient_type
        string event_type
        string channel
        string status
        string destination
        text content
        datetime scheduled_for
        datetime sent_at
        datetime failed_at
        datetime canceled_at
        int attempt_count
        string failure_reason
        string provider_message_id
        datetime created_at
        datetime updated_at
    }
```

## Schemas And Validation

### Enums

- `NotificationChannel`: `whatsapp`
- `NotificationRecipientType`: `patient`, `user`
- `NotificationEventType`: `appointment_created`, `appointment_updated`, `appointment_canceled`, `appointment_reminder`
- `NotificationMessageStatus`: `pending`, `sent`, `failed`, `canceled`

### `NotificationSettingsUpdateRequest`

- `patient_notifications_enabled`: bool, default `true`
- `user_notifications_enabled`: bool, default `true`
- `reminders_enabled`: bool, default `true`
- `notify_on_create`: bool, default `true`
- `notify_on_update`: bool, default `true`
- `notify_on_cancel`: bool, default `true`
- `default_reminder_minutes_before`: integer `1..10080`, default `30`

### `NotificationPatientPreferenceUpsertRequest`

- `is_enabled`: bool, default `true`
- `contact_phone`: optional string with only digits and length `10` or `11`
- `reminder_minutes_before`: optional integer `1..10080`

Behavior:

- `contact_phone=null` clears the override and falls back to `patients.phone_number`
- `reminder_minutes_before=null` falls back to tenant default reminder timing

### `NotificationUserProfileUpsertRequest`

- `is_enabled`: bool, default `true`
- `contact_phone`: optional digits-only string with length `10` or `11`
- `receive_appointment_notifications`: bool, default `true`
- `receive_reminders`: bool, default `true`

Validation:

- when profile delivery is enabled for any message type, `contact_phone` is required

### Response DTOs

- `NotificationSettingsResponse`: effective tenant settings with optional persisted `id`
- `NotificationPatientPreferenceResponse`: effective patient delivery target + resolved reminder timing
- `NotificationUserProfileResponse`: effective per-user delivery profile
- `NotificationMessageResponse`: outbox/history record with delivery metadata
- `NotificationMessageListResponse`: paginated messages envelope
- `NotificationDispatchResponse`: counts for one dispatch run

Delivery backend configuration:

- `NOTIFICATION_PROVIDER=auto|stub|twilio`
- `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_WHATSAPP_FROM_NUMBER`
- `NOTIFICATION_DEFAULT_COUNTRY_CODE` is prepended to stored local phone digits before Twilio delivery

## Access Rules

All `/api/notifications/*` endpoints require:

- authenticated user with role `tenant_owner` OR `assistant`
- valid `X-Tenant-ID` tenant context
- authenticated user assigned to requested tenant

## Endpoints

Base path is `/api/notifications`.

### `GET /api/notifications/settings`

Returns effective tenant notification settings.

Behavior:

- if tenant has no persisted row yet, response still returns defaults

Success:

- `200` `NotificationSettingsResponse`

Errors:

- `400`/`401`/`403` access, tenant, or auth failures

### `PUT /api/notifications/settings`

Creates or updates tenant notification settings.

Behavior:

- upserts the single tenant settings row
- rebuilds reminder outbox entries for future appointments in the tenant
- dispatches any reminder that becomes due immediately after the update

Success:

- `200` `NotificationSettingsResponse`

Errors:

- `400`/`401`/`403` access, tenant, or auth failures
- `422` request validation

### `GET /api/notifications/patients/{patient_id}`

Returns effective notification settings for one patient.

Behavior:

- resolves contact phone from patient preference override first, otherwise `patients.phone_number`
- resolves reminder timing from patient override first, otherwise tenant default

Success:

- `200` `NotificationPatientPreferenceResponse`

Errors:

- `404` patient not found in tenant scope
- `400`/`401`/`403` access, tenant, or auth failures

### `PUT /api/notifications/patients/{patient_id}`

Creates or updates one patient's notification preference.

Behavior:

- upserts the preference row
- rebuilds reminder outbox entries for that patient's future appointments
- dispatches any reminder that becomes due immediately after the update

Success:

- `200` `NotificationPatientPreferenceResponse`

Errors:

- `404` patient not found in tenant scope
- `400`/`401`/`403` access, tenant, or auth failures
- `422` request validation

### `GET /api/notifications/users/{user_id}`

Returns effective notification profile for one tenant user.

Behavior:

- validates the user exists and belongs to the current tenant
- returns defaults when no profile row exists yet

Success:

- `200` `NotificationUserProfileResponse`

Errors:

- `404` user not found
- `409` user exists but is not assigned to tenant
- `400`/`401`/`403` access, tenant, or auth failures

### `PUT /api/notifications/users/{user_id}`

Creates or updates one tenant user's notification delivery profile.

Behavior:

- upserts the profile row
- rebuilds reminder outbox entries for future appointments in the tenant
- dispatches any reminder that becomes due immediately after the update

Success:

- `200` `NotificationUserProfileResponse`

Errors:

- `404` user not found
- `409` user exists but is not assigned to tenant
- `400`/`401`/`403` access, tenant, or auth failures
- `422` request validation

### `GET /api/notifications/messages`

Lists notification messages and delivery attempts.

Query params:

- pagination: `page`, `page_size`
- `message_status`: optional `pending|sent|failed|canceled`
- `event_type`: optional event enum
- `recipient_type`: optional `patient|user`
- `appointment_id`: optional `> 0`
- `patient_id`: optional `> 0`
- `recipient_user_id`: optional `> 0`

Success:

- `200` `NotificationMessageListResponse`

Errors:

- `400`/`401`/`403` access, tenant, or auth failures
- `422` query validation

### `POST /api/notifications/dispatch`

Dispatches due pending notifications for the current tenant.

Request body:

- `limit`: integer `1..1000`, default `100`

Behavior:

- selects pending records with `scheduled_for <= now`
- uses the configured delivery backend
- marks each record as `sent` or `failed`

Success:

- `200` `NotificationDispatchResponse`

Errors:

- `400`/`401`/`403` access, tenant, or auth failures
- `422` request validation

## Service Logic

### `upsert_settings(session, data)`

- creates or updates the tenant settings row
- applies defaults when the row does not exist yet
- resynchronizes reminder messages for all future appointments in the tenant
- dispatches any newly due message immediately

### `upsert_patient_preference(session, patient_id, data)`

- validates patient existence in tenant scope
- upserts the patient override row
- rebuilds future reminders for that patient's appointments
- dispatches newly due reminders immediately

### `upsert_user_profile(session, user_id, data)`

- validates the user exists and is assigned to the current tenant
- upserts the user delivery profile
- rebuilds future reminder messages in the tenant
- dispatches newly due reminders immediately

### `handle_appointment_created(session, appointment)`

- queues immediate confirmation messages for eligible patient and user recipients
- queues reminder messages using tenant defaults and patient overrides
- dispatches due messages for that appointment immediately

### `handle_appointment_updated(session, appointment)`

- queues immediate update messages for eligible recipients
- cancels and rebuilds pending reminder messages for that appointment
- dispatches due messages for that appointment immediately

### `handle_appointment_canceled(session, appointment)`

- cancels pending reminder messages for that appointment
- queues immediate cancellation messages for eligible recipients
- dispatches due messages for that appointment immediately

### `dispatch_due_messages(session, limit, appointment_id=None)`

- selects pending records in tenant scope ordered by `scheduled_for asc, id asc`
- locks rows with `FOR UPDATE SKIP LOCKED`
- resolves the delivery backend from settings (`auto`, `stub`, or `twilio`)
- uses Twilio `messages.create(...)` when Twilio is configured
- builds patient-facing and user-facing WhatsApp text in Brazilian Portuguese using `DD/MM/YYYY às HH:MM UTC`
- stores `sent_at`, `failed_at`, `failure_reason`, `attempt_count`, and `provider_message_id`

### `run_notification_dispatch_loop()`

- runs in app lifespan when `notification_background_dispatch_enabled=true` and `testing=false`
- iterates active tenants, sets tenant RLS context, and dispatches due messages per tenant
- sleeps for `notification_dispatch_interval_seconds` between iterations

## Error Handling

Feature exceptions (`src/features/notification/exceptions.py`):

- `NotificationPatientNotFound` -> `404`
- `NotificationUserNotFound` -> `404`
- `NotificationUserNotAssignedToTenant` -> `409`

Dependency-originated errors:

- `400` tenant header missing or invalid
- `401` authentication failures
- `403` role, tenant membership, inactive user, or locked user failures

Backend-originated delivery failures:

- do not fail the API request that triggered queueing
- affected outbox rows are marked `failed` with `failure_reason`

## Side Effects

- schedule create, update, cancel, no-show, completed, and delete flows now also maintain notification outbox state.
- future reminder rows are rebuilt whenever tenant settings, patient overrides, user profiles, or appointment timing change.
- delivery backend supports Twilio WhatsApp in `src/features/notification/delivery.py`.
- `NOTIFICATION_PROVIDER=auto` falls back to the internal stub backend until the required Twilio env vars are present.
- Twilio delivery formats outbound numbers as `whatsapp:+E164`; stored local digits are prefixed with `NOTIFICATION_DEFAULT_COUNTRY_CODE`.
- background dispatch is disabled automatically in test mode (`TESTING=true`) to keep tests deterministic.

## Frontend Integration Notes

- Configure `/users/{user_id}` before expecting user notifications; there is no notification phone field on the base user entity.
- Patient notifications use `patients.phone_number` by default. Use `/patients/{patient_id}` when a separate notification phone is needed or when reminder timing differs for one patient.
- Use `/messages` to render notification history, troubleshoot failed deliveries, or inspect pending reminders.
- `pending` means queued but not yet due or not yet dispatched; `canceled` means the reminder was invalidated by appointment/state changes.

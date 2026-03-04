# User Feature

## Purpose

`src/features/user` manages user lifecycle, profile operations, RBAC assignment, permissions, and tenant assignments.

```mermaid
flowchart TD
    A[Admin Request] --> B[User Router]
    B --> C[Role guard require_role(ADMIN)]
    C --> D[UserService]
    D --> E[users table]

    F[Authenticated User] --> G[/users/me endpoints]
    G --> D
```

## Files

- `models.py`: `User`, `UserRole`, `UserStatus`, password helpers.
- `schemas.py`: register/update/password and assignment DTOs.
- `service.py`: register, update, delete, password change, role/permission/tenant assignment.
- `router.py`: self-service and admin management endpoints.
- `exceptions.py`: user domain exceptions.

## Core Rules

- New users default to `TENANT_OWNER`, `ACTIVE`, and `is_logged_in=False`.
- Passwords are hashed via Argon2 (`pwdlib`).
- Only `full_name` and `email` are editable in update flows.
- Admin endpoints require `require_role(UserRole.ADMIN)`.
- Users cannot delete their own account via admin delete endpoint.

## Endpoints

Self:

- `GET /api/users/me`
- `PUT /api/users/me`
- `POST /api/users/me/change-password`

Admin:

- `POST /api/users`
- `GET /api/users`
- `GET /api/users/{user_id}`
- `PUT /api/users/{user_id}`
- `POST /api/users/{user_id}/roles`
- `POST /api/users/{user_id}/permissions`
- `POST /api/users/{user_id}/tenants`
- `DELETE /api/users/{user_id}`

## Test Coverage

- large service + API test suite covering CRUD, RBAC, and edge cases
- password and `is_logged_in` state behavior coverage

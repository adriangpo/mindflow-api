"""OpenAPI metadata for authentication routes."""

from typing import Any

from pydantic import BaseModel, Field

from .schemas import TokenResponse

OpenAPIResponse = dict[str, Any]
OpenAPIResponses = dict[int | str, OpenAPIResponse]


class AuthErrorResponse(BaseModel):
    """Standard error response shape used by auth endpoints."""

    detail: str = Field(..., description="Human-readable error message returned by the API.")


class AuthMessageResponse(BaseModel):
    """Standard message response shape used by auth logout."""

    message: str = Field(..., description="Human-readable status message returned by the API.")


LOGIN_REQUEST_DESCRIPTION = (
    "Authenticate a user with either `username` or `email` and a password. "
    "At least one credential must be present. If both are provided, the router uses `username` as the login "
    "credential. Passwords must already satisfy the shared password-strength policy. "
    "On success the server creates a new access token and persists a refresh token row for later renewal."
)

REFRESH_REQUEST_DESCRIPTION = (
    "Exchange a refresh token for a new access/refresh token pair. The refresh token must decode correctly, "
    "must be a `type=refresh` token, must exist in the database, must not be revoked, and must not be expired. "
    "The existing refresh token is not revoked automatically, so multiple active refresh tokens can coexist until "
    "they are individually revoked or expire."
)

LOGOUT_REQUEST_DESCRIPTION = (
    "Revoke one refresh token while the request is authenticated with a valid bearer access token. "
    "If the refresh token exists and is not already revoked, the server marks it revoked and clears the current "
    "user's `is_logged_in` flag. If the token is already revoked or was never stored, the request still returns "
    "a 200 response with a different message."
)

TOKEN_RESPONSE_EXAMPLE = {
    "summary": "Successful token pair",
    "value": {
        "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.access",
        "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.refresh",
        "token_type": "bearer",
        "expires_in": 3600,
    },
}

AUTH_ERROR_EXAMPLES = {
    "Invalid credentials": {
        "summary": "Authentication failed",
        "value": {"detail": "Incorrect username or password"},
    },
    "Invalid token": {
        "summary": "Token rejected",
        "value": {"detail": "Invalid or expired refresh token"},
    },
    "Inactive user": {
        "summary": "Account inactive",
        "value": {"detail": "User account is inactive"},
    },
    "Locked user": {
        "summary": "Account locked",
        "value": {"detail": "User account is locked"},
    },
}

LOGIN_RESPONSES: OpenAPIResponses = {
    200: {
        "model": TokenResponse,
        "description": "Access and refresh tokens were issued after successful authentication.",
        "content": {
            "application/json": {
                "examples": {"default": TOKEN_RESPONSE_EXAMPLE},
            }
        },
    },
    401: {
        "model": AuthErrorResponse,
        "description": "Authentication failed for an unknown, inactive, or locked account, or for a wrong password.",
        "content": {
            "application/json": {
                "examples": {"invalid_credentials": AUTH_ERROR_EXAMPLES["Invalid credentials"]},
            }
        },
    },
}

REFRESH_RESPONSES: OpenAPIResponses = {
    200: {
        "model": TokenResponse,
        "description": "A new access/refresh token pair was created from the supplied refresh token.",
        "content": {
            "application/json": {
                "examples": {"default": TOKEN_RESPONSE_EXAMPLE},
            }
        },
    },
    401: {
        "model": AuthErrorResponse,
        "description": (
            "The supplied refresh token could not be decoded, was revoked, expired, malformed, or belonged to "
            "an inactive user."
        ),
        "content": {
            "application/json": {
                "examples": {
                    "invalid_refresh_token": AUTH_ERROR_EXAMPLES["Invalid token"],
                    "inactive_user": {
                        "summary": "Inactive user",
                        "value": {"detail": "User not found or inactive"},
                    },
                }
            }
        },
    },
}

LOGOUT_RESPONSES: OpenAPIResponses = {
    200: {
        "model": AuthMessageResponse,
        "description": "The refresh token was revoked, or the token was already revoked or missing.",
        "content": {
            "application/json": {
                "examples": {
                    "revoked": {"summary": "Token revoked", "value": {"message": "Successfully logged out"}},
                    "noop": {
                        "summary": "Nothing to revoke",
                        "value": {"message": "Token already revoked or not found"},
                    },
                }
            }
        },
    },
    401: {
        "model": AuthErrorResponse,
        "description": "The request is missing a valid bearer token or the access token is invalid.",
        "content": {
            "application/json": {
                "examples": {"invalid_token": AUTH_ERROR_EXAMPLES["Invalid token"]},
            }
        },
    },
    403: {
        "model": AuthErrorResponse,
        "description": "The authenticated user is inactive or locked.",
        "content": {
            "application/json": {
                "examples": {
                    "inactive_user": AUTH_ERROR_EXAMPLES["Inactive user"],
                    "locked_user": AUTH_ERROR_EXAMPLES["Locked user"],
                }
            }
        },
    },
}

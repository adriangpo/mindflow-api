"""Authentication schemas (DTOs)."""

from pydantic import BaseModel, EmailStr, Field, field_validator

from src.shared.validators.password import validate_password_strength

AUTH_SCHEME_BEARER = "bearer"


# Request schemas
class UserLoginRequest(BaseModel):
    """Login request with separated username/email for validation purposes.

    Note: Uses email-validator library via Pydantic's EmailStr for RFC 5322 compliant email validation.
    """

    username: str | None = Field(
        None,
        min_length=3,
        max_length=50,
        pattern=r"^[a-zA-Z0-9._-]+$",
        description="Username (alphanumeric, hyphens, underscores, dots only)",
    )

    email: EmailStr | None = Field(None, description="Email address (validated via email-validator)")

    password: str = Field(
        ..., min_length=8, description="Password (minimum 8 characters, must include uppercase, lowercase, and digit)"
    )

    @field_validator("password")
    @classmethod
    def _check_password_strength(cls, value: str) -> str:
        return validate_password_strength(value)

    @field_validator("email", mode="after")
    @classmethod
    def _at_least_one_credential(cls, value: str | None, info) -> str | None:
        username = info.data.get("username")

        if not username and not value:
            raise ValueError("Either username or email must be provided")

        return value

    @property
    def credential(self) -> str:
        """Return the credential (username or email) for service layer."""
        if self.username:
            return self.username
        if self.email:
            return self.email
        raise ValueError("No credential available")


class RefreshTokenRequest(BaseModel):
    """Refresh token request."""

    refresh_token: str


# Response schemas
class TokenResponse(BaseModel):
    """JWT token response."""

    access_token: str
    refresh_token: str
    token_type: str = AUTH_SCHEME_BEARER
    expires_in: int  # seconds

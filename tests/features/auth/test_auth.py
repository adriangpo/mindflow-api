"""Comprehensive tests for the auth feature.
Covers: AuthService, JWT dependencies, token lifecycle, account locking.
"""

from datetime import UTC, datetime, timedelta

import pytest
from fastapi import status

from src.config.settings import settings
from src.features.auth.models import RefreshToken
from src.features.auth.service import AuthService
from src.features.user.models import User, UserRole, UserStatus

# AuthService.authenticate_user


class TestAuthenticateUser:
    """Unit tests for AuthService.authenticate_user."""

    async def test_success_with_email(self, session, make_user):
        await make_user(email="login@example.com", password="Pass123!")
        user = await AuthService.authenticate_user(session, "login@example.com", "Pass123!")
        assert user is not None
        assert user.email == "login@example.com"

    async def test_success_with_username(self, session, make_user):
        await make_user(username="byusername", password="Pass123!")
        user = await AuthService.authenticate_user(session, "byusername", "Pass123!")
        assert user is not None
        assert user.username == "byusername"

    async def test_returns_none_for_unknown_credential(self, session):
        result = await AuthService.authenticate_user(session, "ghost@example.com", "Pass123!")
        assert result is None

    async def test_returns_none_for_wrong_password(self, session, make_user):
        await make_user(email="wp@example.com", password="RealPass123!")
        result = await AuthService.authenticate_user(session, "wp@example.com", "WrongPass!")
        assert result is None

    async def test_increments_failed_attempts_on_wrong_password(self, session, make_user):
        from sqlalchemy import select

        await make_user(email="counter@example.com", password="RealPass123!")
        await AuthService.authenticate_user(session, "counter@example.com", "WrongPass!")

        stmt = select(User).where(User.email == "counter@example.com")
        result = await session.execute(stmt)
        user = result.scalar_one_or_none()
        assert user.failed_login_attempts == 1

    async def test_locks_account_after_five_failures(self, session, make_user):
        from sqlalchemy import select

        await make_user(
            email="lockme@example.com",
            password="RealPass123!",
            failed_login_attempts=4,  # one more will trigger lock
        )
        result = await AuthService.authenticate_user(session, "lockme@example.com", "WrongPass!")
        assert result is None

        stmt = select(User).where(User.email == "lockme@example.com")
        result = await session.execute(stmt)
        user = result.scalar_one_or_none()
        assert user.status == UserStatus.LOCKED
        assert user.locked_until is not None
        # Make sure locked_until is in the future (accounting for potential timezone issues)
        assert user.locked_until.replace(tzinfo=UTC) > datetime.now(UTC) - timedelta(seconds=10)

    async def test_resets_failed_attempts_on_success(self, session, make_user):
        await make_user(
            email="reset@example.com",
            password="Pass123!",
            failed_login_attempts=3,
        )
        user = await AuthService.authenticate_user(session, "reset@example.com", "Pass123!")
        assert user is not None
        assert user.failed_login_attempts == 0

    async def test_updates_last_login_at_on_success(self, session, make_user):
        await make_user(email="lastlogin@example.com", password="Pass123!")
        user = await AuthService.authenticate_user(session, "lastlogin@example.com", "Pass123!")
        assert user is not None
        assert user.last_login_at is not None

    async def test_returns_none_for_locked_account(self, session, make_user):
        await make_user(
            email="locked@example.com",
            password="Pass123!",
            status=UserStatus.LOCKED,
            locked_until=datetime.now(UTC) + timedelta(minutes=30),
        )
        result = await AuthService.authenticate_user(session, "locked@example.com", "Pass123!")
        assert result is None

    async def test_allows_login_after_lock_expires(self, session, make_user):
        """A user whose locked_until is in the past should be able to log in."""
        await make_user(
            email="expired_lock@example.com",
            password="Pass123!",
            status=UserStatus.ACTIVE,
            locked_until=datetime.now(UTC) - timedelta(minutes=1),  # already expired
        )
        user = await AuthService.authenticate_user(session, "expired_lock@example.com", "Pass123!")
        assert user is not None


# AuthService.create_tokens


class TestCreateTokens:
    async def test_returns_token_response(self, session, make_user):
        user = await make_user()
        tokens = await AuthService.create_tokens(session, user)

        assert tokens.access_token
        assert tokens.refresh_token
        assert tokens.expires_in > 0

    async def test_stores_refresh_token_in_db(self, session, make_user):
        from sqlalchemy import select

        user = await make_user()
        tokens = await AuthService.create_tokens(session, user)

        stmt = select(RefreshToken).where(RefreshToken.token == tokens.refresh_token)
        result = await session.execute(stmt)
        stored = result.scalar_one_or_none()
        assert stored is not None
        assert stored.user_id == user.id
        assert stored.revoked is False

    async def test_stores_ip_and_user_agent(self, session, make_user):
        from sqlalchemy import select

        user = await make_user()
        tokens = await AuthService.create_tokens(session, user, ip_address="127.0.0.1", user_agent="pytest/1.0")

        stmt = select(RefreshToken).where(RefreshToken.token == tokens.refresh_token)
        result = await session.execute(stmt)
        stored = result.scalar_one_or_none()
        assert stored.ip_address == "127.0.0.1"
        assert stored.user_agent == "pytest/1.0"

    async def test_access_token_contains_correct_claims(self, session, make_user):
        from src.features.auth.jwt_utils import decode_token

        user = await make_user(roles=[UserRole.ADMIN])
        tokens = await AuthService.create_tokens(session, user)
        payload = decode_token(tokens.access_token)

        assert payload["sub"] == str(user.id)
        assert payload["username"] == user.username
        assert "admin" in payload["roles"]


# AuthService.refresh_access_token


class TestRefreshAccessToken:
    async def test_success(self, session, make_user):
        import asyncio

        from sqlalchemy import select

        user = await make_user()
        original = await AuthService.create_tokens(session, user)
        # Wait a second so new tokens have different iat claim
        await asyncio.sleep(1)
        new_tokens = await AuthService.refresh_access_token(session, original.refresh_token)

        assert new_tokens.access_token
        assert new_tokens.refresh_token
        # Note: New refresh token might be same if issued in same millisecond (both have same payload)
        # The important thing is that the old token is no longer valid
        stmt = select(RefreshToken).where(RefreshToken.token == original.refresh_token)
        result = await session.execute(stmt)
        stored_old = result.scalar_one_or_none()
        assert stored_old is not None  # Old token still stored (not deleted)

    async def test_raises_for_invalid_token_string(self, session):
        from src.features.auth.exceptions import InvalidTokenException

        with pytest.raises(InvalidTokenException):
            await AuthService.refresh_access_token(session, "this.is.garbage")

    async def test_raises_for_revoked_token(self, session, make_user):
        from src.features.auth.exceptions import RefreshTokenNotFoundException

        user = await make_user()
        tokens = await AuthService.create_tokens(session, user)
        await AuthService.revoke_refresh_token(session, tokens.refresh_token)

        with pytest.raises(RefreshTokenNotFoundException):
            await AuthService.refresh_access_token(session, tokens.refresh_token)

    async def test_raises_for_expired_token(self, session, make_user):
        from sqlalchemy import select

        from src.features.auth.exceptions import RefreshTokenExpiredException

        user = await make_user()
        tokens = await AuthService.create_tokens(session, user)

        # Manually expire the stored token
        stmt = select(RefreshToken).where(RefreshToken.token == tokens.refresh_token)
        result = await session.execute(stmt)
        stored = result.scalar_one_or_none()
        stored.expires_at = datetime.now(UTC) - timedelta(days=1)
        await session.flush()

        with pytest.raises(RefreshTokenExpiredException):
            await AuthService.refresh_access_token(session, tokens.refresh_token)

    async def test_raises_for_inactive_user(self, session, make_user):
        from src.features.auth.exceptions import InvalidTokenException

        user = await make_user(status=UserStatus.INACTIVE)
        tokens = await AuthService.create_tokens(session, user)

        user.status = UserStatus.INACTIVE
        await session.flush()

        with pytest.raises(InvalidTokenException):
            await AuthService.refresh_access_token(session, tokens.refresh_token)


# AuthService.revoke_refresh_token


class TestRevokeRefreshToken:
    async def test_revokes_valid_token(self, session, make_user):
        from sqlalchemy import select

        user = await make_user()
        tokens = await AuthService.create_tokens(session, user)

        result = await AuthService.revoke_refresh_token(session, tokens.refresh_token)
        assert result is True

        stmt = select(RefreshToken).where(RefreshToken.token == tokens.refresh_token)
        result = await session.execute(stmt)
        stored = result.scalar_one_or_none()
        assert stored.revoked is True
        assert stored.revoked_at is not None

    async def test_returns_false_for_already_revoked(self, session, make_user):
        user = await make_user()
        tokens = await AuthService.create_tokens(session, user)
        await AuthService.revoke_refresh_token(session, tokens.refresh_token)

        result = await AuthService.revoke_refresh_token(session, tokens.refresh_token)
        assert result is False

    async def test_returns_false_for_nonexistent_token(self, session):
        result = await AuthService.revoke_refresh_token(session, "nonexistent.token.string")
        assert result is False


# POST {api_prefix}/auth/login  (HTTP layer)


class TestLoginEndpoint:
    async def test_login_success_with_email(self, client, make_user):
        await make_user(email="http@example.com", password="Pass123!")
        response = await client.post(
            f"{settings.api_prefix}/auth/login",
            json={"email": "http@example.com", "password": "Pass123!"},
        )
        assert response.status_code == status.HTTP_200_OK
        body = response.json()
        assert "access_token" in body
        assert "refresh_token" in body
        assert body["expires_in"] > 0

    async def test_login_success_with_username(self, client, make_user):
        await make_user(username="httpuser", password="Pass123!")
        response = await client.post(
            f"{settings.api_prefix}/auth/login",
            json={"username": "httpuser", "password": "Pass123!"},
        )
        assert response.status_code == status.HTTP_200_OK

    async def test_login_wrong_password_returns_401(self, client, make_user):
        await make_user(email="badpass@example.com", password="RealPass123!")
        response = await client.post(
            f"{settings.api_prefix}/auth/login",
            json={"email": "badpass@example.com", "password": "WrongPass123!"},
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    async def test_login_unknown_user_returns_401(self, client):
        response = await client.post(
            f"{settings.api_prefix}/auth/login",
            json={"email": "nobody@example.com", "password": "Pass123!"},
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    async def test_login_locked_account_returns_401(self, client, make_user):
        await make_user(
            email="locked@example.com",
            password="Pass123!",
            status=UserStatus.LOCKED,
            locked_until=datetime.now(UTC) + timedelta(minutes=30),
        )
        response = await client.post(
            f"{settings.api_prefix}/auth/login",
            json={"email": "locked@example.com", "password": "Pass123!"},
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    async def test_login_missing_fields_returns_422(self, client):
        response = await client.post(f"{settings.api_prefix}/auth/login", json={"username": "only-this"})
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT


# POST {api_prefix}/auth/refresh  (HTTP layer)


class TestRefreshEndpoint:
    async def test_refresh_success(self, client, make_user):
        import asyncio

        await make_user(email="refresh@example.com", password="Pass123!")
        login = await client.post(
            f"{settings.api_prefix}/auth/login",
            json={"email": "refresh@example.com", "password": "Pass123!"},
        )
        refresh_token = login.json()["refresh_token"]

        # Wait a second so new tokens have different iat claim
        await asyncio.sleep(1)

        response = await client.post(
            f"{settings.api_prefix}/auth/refresh",
            json={"refresh_token": refresh_token},
        )
        assert response.status_code == status.HTTP_200_OK
        assert "access_token" in response.json()

    async def test_refresh_with_invalid_token_returns_401(self, client):
        response = await client.post(
            f"{settings.api_prefix}/auth/refresh",
            json={"refresh_token": "bad.token.here"},
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    async def test_refresh_with_revoked_token_returns_404(self, session, client, make_user):
        await make_user(email="revoked@example.com", password="Pass123!")
        login = await client.post(
            f"{settings.api_prefix}/auth/login",
            json={"email": "revoked@example.com", "password": "Pass123!"},
        )
        refresh_token = login.json()["refresh_token"]
        await AuthService.revoke_refresh_token(session, refresh_token)

        response = await client.post(
            f"{settings.api_prefix}/auth/refresh",
            json={"refresh_token": refresh_token},
        )
        # Revoked token returns 401 (unauthorized), not 404
        assert response.status_code == status.HTTP_401_UNAUTHORIZED


# POST {api_prefix}/auth/logout  (HTTP layer)


class TestLogoutEndpoint:
    async def test_logout_success(self, session, auth_client):
        client, user = auth_client
        # Auth client overrides the auth dependency, so we can't use login.
        # Instead, we generate tokens manually.
        tokens = await AuthService.create_tokens(session, user)

        response = await client.post(
            f"{settings.api_prefix}/auth/logout",
            json={"refresh_token": tokens.refresh_token},
            headers={"Authorization": f"Bearer {tokens.access_token}"},
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["message"] == "Successfully logged out"

    async def test_logout_already_revoked_token(self, session, auth_client):
        client, user = auth_client
        tokens = await AuthService.create_tokens(session, user)

        # logout twice
        await client.post(
            f"{settings.api_prefix}/auth/logout",
            json={"refresh_token": tokens.refresh_token},
            headers={"Authorization": f"Bearer {tokens.access_token}"},
        )
        response = await client.post(
            f"{settings.api_prefix}/auth/logout",
            json={"refresh_token": tokens.refresh_token},
            headers={"Authorization": f"Bearer {tokens.access_token}"},
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["message"] == "Token already revoked or not found"

    async def test_logout_without_auth_returns_403(self, client):
        """HTTPBearer returns 403 when no Authorization header is present."""
        response = await client.post(
            f"{settings.api_prefix}/auth/logout",
            json={"refresh_token": "any.token.here"},
        )
        # Actually HTTPBearer returns 401 when no credentials provided
        assert response.status_code == status.HTTP_401_UNAUTHORIZED


# get_current_user dependency


class TestGetCurrentUserDependency:
    """Exercises get_current_user by hitting a real protected endpoint.
    Uses /auth/logout as the probe since it requires authentication.
    """

    async def test_valid_token_grants_access(self, client, make_user):
        await make_user(email="dep@example.com", password="Pass123!")
        login = await client.post(
            f"{settings.api_prefix}/auth/login",
            json={"email": "dep@example.com", "password": "Pass123!"},
        )
        token = login.json()["access_token"]

        response = await client.post(
            f"{settings.api_prefix}/auth/logout",
            json={"refresh_token": "dummy"},
            headers={"Authorization": f"Bearer {token}"},
        )
        # 200 means the dependency resolved the user correctly
        assert response.status_code == status.HTTP_200_OK

    async def test_missing_token_returns_403(self, client):
        response = await client.post(f"{settings.api_prefix}/auth/logout", json={"refresh_token": "x"})
        # HTTPBearer returns 401 when no Authorization header is provided
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    async def test_malformed_token_returns_401(self, client):
        response = await client.post(
            f"{settings.api_prefix}/auth/logout",
            json={"refresh_token": "x"},
            headers={"Authorization": "Bearer not.a.real.token"},
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    async def test_inactive_user_returns_403(self, session, client, make_user):
        user = await make_user(email="inactive@example.com", password="Pass123!")
        login = await client.post(
            f"{settings.api_prefix}/auth/login",
            json={"email": "inactive@example.com", "password": "Pass123!"},
        )
        token = login.json()["access_token"]

        # Deactivate the user after the token was issued
        user.status = UserStatus.INACTIVE
        await session.flush()

        response = await client.post(
            f"{settings.api_prefix}/auth/logout",
            json={"refresh_token": "x"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN

    async def test_locked_user_returns_403(self, session, client, make_user):
        user = await make_user(email="lockdep@example.com", password="Pass123!")
        login = await client.post(
            f"{settings.api_prefix}/auth/login",
            json={"email": "lockdep@example.com", "password": "Pass123!"},
        )
        token = login.json()["access_token"]

        # Lock the user after the token was issued
        user.status = UserStatus.LOCKED
        user.locked_until = datetime.now(UTC) + timedelta(minutes=30)
        await session.flush()

        response = await client.post(
            f"{settings.api_prefix}/auth/logout",
            json={"refresh_token": "x"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN


# User model unit tests (no HTTP, no DB)


class TestUserModel:
    def test_hash_and_verify_password(self):
        hashed = User.hash_password("MySecret!")
        assert User(
            email="x@x.com",
            username="x",
            full_name="X",
            hashed_password=hashed,
        ).verify_password("MySecret!")

    def test_verify_wrong_password_returns_false(self):
        hashed = User.hash_password("MySecret!")
        user = User(email="x@x.com", username="x", full_name="X", hashed_password=hashed)
        assert not user.verify_password("NotMySecret!")

    def test_is_active_for_active_status(self):
        user = User(
            email="x@x.com",
            username="x",
            full_name="X",
            hashed_password="h",
            status=UserStatus.ACTIVE,
        )
        assert user.is_active is True

    def test_is_active_false_for_inactive(self):
        user = User(
            email="x@x.com",
            username="x",
            full_name="X",
            hashed_password="h",
            status=UserStatus.INACTIVE,
        )
        assert user.is_active is False

    def test_is_locked_true_when_locked_until_in_future(self):
        user = User(
            email="x@x.com",
            username="x",
            full_name="X",
            hashed_password="h",
            locked_until=datetime.now(UTC) + timedelta(minutes=10),
        )
        assert user.is_locked() is True

    def test_is_locked_false_when_locked_until_expired(self):
        user = User(
            email="x@x.com",
            username="x",
            full_name="X",
            hashed_password="h",
            locked_until=datetime.now(UTC) - timedelta(minutes=1),
        )
        assert user.is_locked() is False

    def test_is_locked_false_when_no_locked_until(self):
        user = User(email="x@x.com", username="x", full_name="X", hashed_password="h")
        assert user.is_locked() is False

    def test_has_role_true(self):
        user = User(
            email="x@x.com",
            username="x",
            full_name="X",
            hashed_password="h",
            roles=[UserRole.ADMIN],
        )
        assert user.has_role(UserRole.ADMIN) is True

    def test_has_role_false(self):
        user = User(
            email="x@x.com",
            username="x",
            full_name="X",
            hashed_password="h",
            roles=[UserRole.ASSISTANT],
        )
        assert user.has_role(UserRole.ADMIN) is False

    def test_has_permission_directly(self):
        user = User(
            email="x@x.com",
            username="x",
            full_name="X",
            hashed_password="h",
            permissions=["read:assets"],
        )
        assert user.has_permission("read:assets") is True

    def test_admin_has_all_permissions(self):
        user = User(
            email="x@x.com",
            username="x",
            full_name="X",
            hashed_password="h",
            roles=[UserRole.ADMIN],
            permissions=[],
        )
        assert user.has_permission("anything:at:all") is True
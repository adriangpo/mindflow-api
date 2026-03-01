"""Comprehensive tests for the user feature.
Covers: UserService, User CRUD, role/permission assignment, privilege checks.
"""

import pytest
from fastapi import status

from src.config.settings import settings
from src.features.user.exceptions import (
    EmailAlreadyExists,
    IncorrectPassword,
    UsernameAlreadyExists,
)
from src.features.user.models import User, UserRole, UserStatus
from src.features.user.schemas import UserRegisterRequest
from src.features.user.service import UserService
from src.shared.pagination.pagination import PaginationParams

# UserService Unit Tests


class TestUserServiceRegistration:
    """Tests for UserService.register_user()"""

    async def test_register_user_success(self, session):
        """Successfully register a new user with default TENANT_OWNER role."""
        data = UserRegisterRequest(
            email="newuser@example.com",
            username="newuser",
            full_name="New User",
            password="SecurePass123!",
            confirm_password="SecurePass123!",
        )
        user = await UserService.register_user(session, data)

        assert user.email == "newuser@example.com"
        assert user.username == "newuser"
        assert user.full_name == "New User"
        assert UserRole.TENANT_OWNER in user.roles
        assert user.status == UserStatus.ACTIVE
        assert user.verify_password("SecurePass123!")

    async def test_register_user_duplicate_username(self, session, make_user):
        """Cannot register with duplicate username."""
        await make_user(username="taken")

        data = UserRegisterRequest(
            email="other@example.com",
            username="taken",
            full_name="Other User",
            password="Pass123!",
            confirm_password="Pass123!",
        )

        with pytest.raises(UsernameAlreadyExists):
            await UserService.register_user(session, data)

    async def test_register_user_duplicate_email(self, session, make_user):
        """Cannot register with duplicate email."""
        await make_user(email="taken@example.com")

        data = UserRegisterRequest(
            email="taken@example.com",
            username="different",
            full_name="Other User",
            password="Pass123!",
            confirm_password="Pass123!",
        )

        with pytest.raises(EmailAlreadyExists):
            await UserService.register_user(session, data)


class TestUserServiceRoles:
    """Tests for UserService.assign_roles()"""

    async def test_assign_single_role(self, make_user):
        """Assign a single role to user."""
        user = await make_user(roles=[UserRole.TENANT_OWNER])

        updated = await UserService.assign_roles(user, [UserRole.ADMIN])

        assert UserRole.ADMIN in updated.roles
        assert len(updated.roles) == 1

    async def test_assign_multiple_roles(self, make_user):
        """Assign multiple roles to user."""
        user = await make_user(roles=[UserRole.TENANT_OWNER])

        updated = await UserService.assign_roles(user, [UserRole.ADMIN, UserRole.ASSISTANT])

        assert UserRole.ADMIN in updated.roles
        assert UserRole.ASSISTANT in updated.roles
        assert len(updated.roles) == 2

    async def test_assign_roles_replaces_previous(self, make_user):
        """Assigning roles replaces previous roles."""
        user = await make_user(roles=[UserRole.TENANT_OWNER])

        updated = await UserService.assign_roles(user, [UserRole.ASSISTANT])

        assert UserRole.ASSISTANT in updated.roles
        assert UserRole.TENANT_OWNER not in updated.roles


class TestUserServicePermissions:
    """Tests for UserService.assign_permissions()"""

    async def test_assign_single_permission(self, make_user):
        """Assign a single permission to user."""
        user = await make_user()

        updated = await UserService.assign_permissions(user, ["read:assets"])

        assert "read:assets" in updated.permissions
        assert len(updated.permissions) == 1

    async def test_assign_multiple_permissions(self, make_user):
        """Assign multiple permissions to user."""
        user = await make_user()

        permissions = ["read:assets", "write:assets", "delete:assets"]
        updated = await UserService.assign_permissions(user, permissions)

        for perm in permissions:
            assert perm in updated.permissions
        assert len(updated.permissions) == 3

    async def test_assign_permissions_replaces_previous(self, make_user):
        """Assigning permissions replaces previous permissions."""
        user = await make_user()

        await UserService.assign_permissions(user, ["read:assets"])
        updated = await UserService.assign_permissions(user, ["write:assets"])

        assert "write:assets" in updated.permissions
        assert "read:assets" not in updated.permissions


class TestUserServiceUpdate:
    """Tests for UserService.update_user()"""

    async def test_update_full_name(self, session, make_user):
        """Update user's full name."""
        user = await make_user(full_name="Old Name")

        updated = await UserService.update_user(session, user, full_name="New Name")

        assert updated.full_name == "New Name"

    async def test_update_email(self, session, make_user):
        """Update user's email."""
        user = await make_user(email="old@example.com")

        updated = await UserService.update_user(session, user, email="new@example.com")

        assert updated.email == "new@example.com"

    async def test_update_both_fields(self, session, make_user):
        """Update both full name and email."""
        user = await make_user(full_name="Old Name", email="old@example.com")

        updated = await UserService.update_user(session, user, full_name="New Name", email="new@example.com")

        assert updated.full_name == "New Name"
        assert updated.email == "new@example.com"

    async def test_update_only_provided_fields(self, session, make_user):
        """Only update provided fields, leave others unchanged."""
        original_email = "original@example.com"
        user = await make_user(full_name="Original Name", email=original_email)

        updated = await UserService.update_user(session, user, full_name="Updated Name")

        assert updated.full_name == "Updated Name"
        assert updated.email == original_email


class TestUserServicePassword:
    """Tests for UserService.change_password()"""

    async def test_change_password_success(self, session, make_user):
        """Successfully change user password."""
        user = await make_user(password="OldPass123!")

        success = await UserService.change_password(user, "OldPass123!", "NewPass456!")
        await session.commit()

        assert success is True
        # Verify password actually changed
        updated_user = await UserService.get_user(session, user.id)
        assert updated_user is not None
        assert updated_user.verify_password("NewPass456!")
        assert not updated_user.verify_password("OldPass123!")

    async def test_change_password_wrong_current(self, make_user):
        """Cannot change password with wrong current password."""
        user = await make_user(password="CorrectPass123!")

        with pytest.raises(IncorrectPassword):
            await UserService.change_password(user, "WrongPass123!", "NewPass456!")

    async def test_change_password_updates_timestamp(self, session, make_user):
        """Password change updates the updated_at timestamp."""
        user = await make_user(password="OldPass123!")
        original_updated_at = user.updated_at

        await UserService.change_password(user, "OldPass123!", "NewPass456!")
        await session.commit()

        updated_user = await UserService.get_user(session, user.id)
        
        assert updated_user is not None
        assert updated_user.updated_at > original_updated_at


class TestUserServiceDelete:
    """Tests for UserService.delete_user()"""

    async def test_delete_user_success(self, session, make_user):
        """Successfully delete a user."""
        user = await make_user()
        user_id = user.id

        success = await UserService.delete_user(session, user_id)
        await session.commit()

        assert success is True
        deleted = await UserService.get_user(session, user_id)
        assert deleted is None

    async def test_delete_nonexistent_user(self, session):
        """Deleting nonexistent user returns False."""
        fake_id = 999999
        success = await UserService.delete_user(session, fake_id)
        assert success is False


class TestUserServiceGet:
    """Tests for UserService.get_user() and get_users()"""

    async def test_get_user_by_id(self, session, make_user):
        """Retrieve user by ID."""
        user = await make_user(username="testuser")

        retrieved = await UserService.get_user(session, user.id)

        assert retrieved is not None
        assert retrieved.username == "testuser"

    async def test_get_nonexistent_user(self, session):
        """Getting nonexistent user returns None."""
        fake_id = 999999
        result = await UserService.get_user(session, fake_id)
        assert result is None

    async def test_get_users_list(self, session, make_user):
        """Get paginated list of users."""
        await make_user(username="user1", email="user1@example.com")
        await make_user(username="user2", email="user2@example.com")
        await make_user(username="user3", email="user3@example.com")

        pagination = PaginationParams(page=1, page_size=2)
        users, total = await UserService.get_users(session, pagination)

        assert len(users) == 2
        assert total >= 3

    async def test_get_users_pagination(self, session, make_user):
        """Pagination works correctly."""
        await make_user(username="user1", email="user1@example.com")
        await make_user(username="user2", email="user2@example.com")
        await make_user(username="user3", email="user3@example.com")

        # Page 1
        pagination1 = PaginationParams(page=1, page_size=2)
        page1, total = await UserService.get_users(session, pagination1)
        assert len(page1) == 2

        # Page 2
        pagination2 = PaginationParams(page=2, page_size=2)
        page2, total = await UserService.get_users(session, pagination2)
        assert len(page2) >= 1
        assert total >= 3

    async def test_get_users_no_pagination(self, session, make_user):
        """Can disable pagination to get all users."""
        await make_user(username="user1", email="user1@example.com")
        await make_user(username="user2", email="user2@example.com")
        await make_user(username="user3", email="user3@example.com")

        # Disable pagination
        pagination = PaginationParams(page=None, page_size=None)
        users, total = await UserService.get_users(session, pagination)

        assert len(users) >= 3
        assert total >= 3


# User API Endpoint Tests (HTTP Layer)


class TestUserEndpointGetMe:
    """Tests for GET {api_prefix}/users/me"""

    async def test_get_me_success(self, auth_client):
        """Get current user's profile."""
        client, user = auth_client

        response = await client.get(f"{settings.api_prefix}/users/me")

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["username"] == user.username
        assert data["email"] == user.email

    async def test_get_me_without_auth(self, client):
        """Cannot get /me without authentication."""
        response = await client.get(f"{settings.api_prefix}/users/me")

        # HTTPBearer returns 401 when no Authorization header
        assert response.status_code == status.HTTP_401_UNAUTHORIZED


class TestUserEndpointUpdateMe:
    """Tests for PUT {api_prefix}/users/me"""

    async def test_update_me_full_name(self, auth_client):
        """Update own full name."""
        client, user = auth_client

        response = await client.put(f"{settings.api_prefix}/users/me", json={"full_name": "New Name"})

        assert response.status_code == status.HTTP_200_OK
        assert response.json()["full_name"] == "New Name"

    async def test_update_me_email(self, auth_client):
        """Update own email."""
        client, user = auth_client

        response = await client.put(f"{settings.api_prefix}/users/me", json={"email": "newemail@example.com"})

        assert response.status_code == status.HTTP_200_OK
        assert response.json()["email"] == "newemail@example.com"

    async def test_update_me_both_fields(self, auth_client):
        """Update both full name and email."""
        client, user = auth_client

        response = await client.put(
            f"{settings.api_prefix}/users/me", json={"full_name": "New Name", "email": "new@example.com"}
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["full_name"] == "New Name"
        assert data["email"] == "new@example.com"

    async def test_update_me_without_auth(self, client):
        """Cannot update /me without authentication."""
        response = await client.put(f"{settings.api_prefix}/users/me", json={"full_name": "New Name"})

        # HTTPBearer returns 401 when no Authorization header
        assert response.status_code == status.HTTP_401_UNAUTHORIZED


class TestUserEndpointChangePassword:
    """Tests for POST {api_prefix}/users/me/change-password"""

    async def test_change_password_success(self, auth_client):
        """Successfully change password."""
        client, user = auth_client

        response = await client.post(
            f"{settings.api_prefix}/users/me/change-password",
            json={
                "current_password": "TestPass123!",
                "new_password": "NewPass456!",
                "confirm_new_password": "NewPass456!",
            },
        )

        assert response.status_code == status.HTTP_200_OK
        assert "Password changed" in response.json()["message"]

    async def test_change_password_wrong_current(self, auth_client):
        """Cannot change password with wrong current password."""
        client, user = auth_client

        response = await client.post(
            f"{settings.api_prefix}/users/me/change-password",
            json={
                "current_password": "WrongPass123!",
                "new_password": "NewPass456!",
                "confirm_new_password": "NewPass456!",
            },
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    async def test_change_password_mismatch(self, auth_client):
        """Cannot change password if new passwords don't match."""
        client, user = auth_client

        response = await client.post(
            f"{settings.api_prefix}/users/me/change-password",
            json={
                "current_password": "TestPass123!",
                "new_password": "NewPass456!",
                "confirm_new_password": "DifferentPass789!",
            },
        )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT

    async def test_change_password_without_auth(self, client):
        """Cannot change password without authentication."""
        response = await client.post(
            f"{settings.api_prefix}/users/me/change-password",
            json={"current_password": "Current123!", "new_password": "New456!", "confirm_new_password": "New456!"},
        )

        # HTTPBearer returns 401 when no Authorization header
        assert response.status_code == status.HTTP_401_UNAUTHORIZED


class TestUserEndpointListUsers:
    """Tests for GET {api_prefix}/users (list users - admin only)"""

    async def test_list_users_as_admin(self, admin_client, make_user):
        """Admin can list all users."""
        client, admin_user = admin_client
        await make_user(username="user1")
        await make_user(username="user2")

        response = await client.get(f"{settings.api_prefix}/users")

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "users" in data
        assert data["total"] >= 2

    async def test_list_users_pagination(self, admin_client, make_user):
        """List users with pagination."""
        client, admin_user = admin_client
        await make_user(username="user1")
        await make_user(username="user2")
        await make_user(username="user3")

        response = await client.get(f"{settings.api_prefix}/users?page=1&page_size=2")

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert len(data["users"]) == 2
        assert data["page"] == 1
        assert data["page_size"] == 2

    async def test_list_users_non_admin_forbidden(self, auth_client):
        """Non-admin cannot list users."""
        client, user = auth_client

        response = await client.get(f"{settings.api_prefix}/users")

        assert response.status_code == status.HTTP_403_FORBIDDEN


class TestUserEndpointGetUser:
    """Tests for GET {api_prefix}/users/{id} (admin only)"""

    async def test_get_user_as_admin(self, admin_client, make_user):
        """Admin can get specific user."""
        client, admin_user = admin_client
        user = await make_user(username="specific")

        response = await client.get(f"{settings.api_prefix}/users/{user.id}")

        assert response.status_code == status.HTTP_200_OK
        assert response.json()["username"] == "specific"

    async def test_get_nonexistent_user_as_admin(self, admin_client):
        """Getting nonexistent user returns 404."""
        client, admin_user = admin_client
        fake_id = "000000000000000000000000"

        response = await client.get(f"{settings.api_prefix}/users/{fake_id}")

        assert response.status_code == status.HTTP_404_NOT_FOUND

    async def test_get_user_non_admin_forbidden(self, auth_client, make_user):
        """Non-admin cannot get specific user."""
        client, user = auth_client
        other_user = await make_user(username="other")

        response = await client.get(f"{settings.api_prefix}/users/{other_user.id}")

        assert response.status_code == status.HTTP_403_FORBIDDEN


class TestUserEndpointUpdateUser:
    """Tests for PUT {api_prefix}/users/{id} (admin only)"""

    async def test_update_user_as_admin(self, admin_client, make_user):
        """Admin can update specific user."""
        client, admin_user = admin_client
        user = await make_user(full_name="Original")

        response = await client.put(f"{settings.api_prefix}/users/{user.id}", json={"full_name": "Updated"})

        assert response.status_code == status.HTTP_200_OK
        assert response.json()["full_name"] == "Updated"

    async def test_update_user_non_admin_forbidden(self, auth_client, make_user):
        """Non-admin cannot update other users."""
        client, user = auth_client
        other_user = await make_user(username="other")

        response = await client.put(f"{settings.api_prefix}/users/{other_user.id}", json={"full_name": "Hacked"})

        assert response.status_code == status.HTTP_403_FORBIDDEN


class TestUserEndpointAssignRoles:
    """Tests for POST {api_prefix}/users/{id}/roles (admin only)"""

    async def test_assign_role_as_admin(self, admin_client, make_user):
        """Admin can assign roles to user."""
        client, admin_user = admin_client
        user = await make_user(roles=[UserRole.ASSISTANT])

        response = await client.post(f"{settings.api_prefix}/users/{user.id}/roles", json={"roles": ["admin"]})

        assert response.status_code == status.HTTP_200_OK
        assert "admin" in response.json()["roles"]

    async def test_assign_role_non_admin_forbidden(self, auth_client, make_user):
        """Non-admin cannot assign roles."""
        client, user = auth_client
        other_user = await make_user(username="other")

        response = await client.post(f"{settings.api_prefix}/users/{other_user.id}/roles", json={"roles": ["admin"]})

        assert response.status_code == status.HTTP_403_FORBIDDEN


class TestUserEndpointAssignPermissions:
    """Tests for POST {api_prefix}/users/{id}/permissions (admin only)"""

    async def test_assign_permission_as_admin(self, admin_client, make_user):
        """Admin can assign permissions to user."""
        client, admin_user = admin_client
        user = await make_user()

        response = await client.post(
            f"{settings.api_prefix}/users/{user.id}/permissions", json={"permissions": ["read:assets", "write:assets"]}
        )

        assert response.status_code == status.HTTP_200_OK
        perms = response.json()["permissions"]
        assert "read:assets" in perms
        assert "write:assets" in perms

    async def test_assign_permission_non_admin_forbidden(self, auth_client, make_user):
        """Non-admin cannot assign permissions."""
        client, user = auth_client
        other_user = await make_user(username="other")

        response = await client.post(
            f"{settings.api_prefix}/users/{other_user.id}/permissions", json={"permissions": ["admin:all"]}
        )

        assert response.status_code == status.HTTP_403_FORBIDDEN


class TestUserEndpointDeleteUser:
    """Tests for DELETE {api_prefix}/users/{id} (admin only)"""

    async def test_delete_user_as_admin(self, admin_client, make_user):
        """Admin can delete user."""
        client, admin_user = admin_client
        user = await make_user(username="tobedeleted")

        response = await client.delete(f"{settings.api_prefix}/users/{user.id}")

        assert response.status_code == status.HTTP_200_OK
        assert "deleted successfully" in response.json()["message"]

    async def test_cannot_delete_own_account(self, admin_client):
        """Admin cannot delete their own account."""
        client, admin_user = admin_client

        response = await client.delete(f"{settings.api_prefix}/users/{admin_user.id}")

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    async def test_delete_nonexistent_user_as_admin(self, admin_client):
        """Deleting nonexistent user returns 404."""
        client, admin_user = admin_client
        fake_id = "000000000000000000000000"

        response = await client.delete(f"{settings.api_prefix}/users/{fake_id}")

        assert response.status_code == status.HTTP_404_NOT_FOUND

    async def test_delete_user_non_admin_forbidden(self, auth_client, make_user):
        """Non-admin cannot delete users."""
        client, user = auth_client
        other_user = await make_user(username="other")

        response = await client.delete(f"{settings.api_prefix}/users/{other_user.id}")

        assert response.status_code == status.HTTP_403_FORBIDDEN


class TestUserRolePermissions:
    """Tests for role and permission model logic"""

    def test_user_has_role(self):
        """Test has_role method."""
        user = User(
            email="test@example.com",
            username="test",
            full_name="Test",
            hashed_password="hash",
            roles=[UserRole.ADMIN, UserRole.ASSISTANT],
        )

        assert user.has_role(UserRole.ADMIN)
        assert user.has_role(UserRole.ASSISTANT)
        assert not user.has_role(UserRole.TENANT_OWNER)

    def test_user_has_permission_directly(self):
        """Test has_permission when user has permission directly."""
        user = User(
            email="test@example.com",
            username="test",
            full_name="Test",
            hashed_password="hash",
            permissions=["read:assets", "write:assets"],
        )

        assert user.has_permission("read:assets")
        assert user.has_permission("write:assets")
        assert not user.has_permission("delete:assets")

    def test_admin_has_all_permissions(self):
        """Test that ADMIN role grants all permissions."""
        user = User(
            email="test@example.com",
            username="test",
            full_name="Test",
            hashed_password="hash",
            roles=[UserRole.ADMIN],
            permissions=[],
        )

        assert user.has_permission("read:anything")
        assert user.has_permission("delete:everything")
        assert user.has_permission("do:anything:at:all")

    def test_non_admin_needs_explicit_permission(self):
        """Test that non-admin needs explicit permission."""
        user = User(
            email="test@example.com",
            username="test",
            full_name="Test",
            hashed_password="hash",
            roles=[UserRole.ASSISTANT],
            permissions=[],
        )

        assert not user.has_permission("write:assets")


class TestUserModelMethods:
    """Tests for User model methods and properties"""

    def test_hash_password_creates_different_hashes(self):
        """Test that hashing same password twice produces different hashes (due to different salts)."""
        password = "TestPassword123!"
        hash1 = User.hash_password(password)
        hash2 = User.hash_password(password)

        assert hash1 != hash2  # Different salts
        assert len(hash1) > 0
        assert len(hash2) > 0

    def test_verify_password_with_correct_password(self):
        """Test password verification with correct password."""
        password = "CorrectPass123!"
        hashed = User.hash_password(password)

        user = User(email="test@example.com", username="test", full_name="Test", hashed_password=hashed)

        assert user.verify_password(password) is True

    def test_verify_password_with_wrong_password(self):
        """Test password verification with wrong password."""
        password = "CorrectPass123!"
        hashed = User.hash_password(password)

        user = User(email="test@example.com", username="test", full_name="Test", hashed_password=hashed)

        assert user.verify_password("WrongPass123!") is False

    def test_is_active_property(self):
        """Test is_active property returns True for active users."""
        user = User(
            email="test@example.com",
            username="test",
            full_name="Test",
            hashed_password="hash",
            status=UserStatus.ACTIVE,
        )

        assert user.is_active is True

    def test_is_active_property_for_inactive(self):
        """Test is_active property returns False for inactive users."""
        user = User(
            email="test@example.com",
            username="test",
            full_name="Test",
            hashed_password="hash",
            status=UserStatus.INACTIVE,
        )

        assert user.is_active is False

    def test_is_active_property_for_locked(self):
        """Test is_active property returns False for locked users."""
        user = User(
            email="test@example.com",
            username="test",
            full_name="Test",
            hashed_password="hash",
            status=UserStatus.LOCKED,
        )

        assert user.is_active is False


class TestUserServiceEdgeCases:
    """Tests for edge cases in UserService"""

    async def test_update_user_with_duplicate_email(self, session, make_user):
        """Cannot update user email to an already existing email."""
        await make_user(email="user1@example.com", username="user1")
        user2 = await make_user(email="user2@example.com", username="user2")

        # Trying to update user2's email to user1's email should raise an error
        with pytest.raises(EmailAlreadyExists):
            await UserService.update_user(session, user2, email="user1@example.com")

    async def test_update_user_with_none_values(self, session, make_user):
        """Update with None values should not change existing data."""
        original_name = "Original Name"
        original_email = "original@example.com"
        user = await make_user(full_name=original_name, email=original_email)

        updated = await UserService.update_user(session, user, full_name=None, email=None)

        assert updated.full_name == original_name
        assert updated.email == original_email

    async def test_assign_empty_roles_list(self, make_user):
        """Can assign empty roles list to user."""
        user = await make_user(roles=[UserRole.ADMIN, UserRole.ASSISTANT])

        updated = await UserService.assign_roles(user, [])

        assert len(updated.roles) == 0

    async def test_assign_empty_permissions_list(self, make_user):
        """Can assign empty permissions list to user."""
        user = await make_user()
        await UserService.assign_permissions(user, ["read:assets", "write:assets"])

        updated = await UserService.assign_permissions(user, [])

        assert len(updated.permissions) == 0

    async def test_register_user_with_minimal_password(self, session):
        """Test registration with minimum valid password."""
        data = UserRegisterRequest(
            email="minpass@example.com",
            username="minpassuser",
            full_name="Min Pass User",
            password="Pass123!",
            confirm_password="Pass123!",
        )
        user = await UserService.register_user(session, data)

        assert user is not None
        assert user.verify_password("Pass123!")


class TestUserEndpointEdgeCases:
    """Tests for edge cases in User API endpoints"""

    async def test_list_users_with_page_zero(self, admin_client):
        """Test listing users with page=0."""
        client, admin_user = admin_client

        response = await client.get(f"{settings.api_prefix}/users?page=0&page_size=10")

        # Pagination validation rejects page=0
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT

    async def test_list_users_with_large_page_size(self, admin_client, make_user):
        """Test listing users with very large page_size."""
        client, admin_user = admin_client
        await make_user(username="user1")
        await make_user(username="user2")

        response = await client.get(f"{settings.api_prefix}/users?page=1&page_size=10000")

        # Validation rejects page_size > max (likely 1000)
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT

    async def test_list_users_without_pagination_params(self, admin_client, make_user):
        """Test listing users without any pagination params uses defaults."""
        client, admin_user = admin_client
        await make_user(username="user1")

        response = await client.get(f"{settings.api_prefix}/users")

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "users" in data
        assert "total" in data

    async def test_get_user_with_invalid_id_format(self, admin_client):
        """Test getting user with invalid ID format returns validation error."""
        client, admin_user = admin_client

        # Invalid integer ID format will fail path parameter validation
        # With SQLAlchemy integer IDs, this returns 422 UNPROCESSABLE_ENTITY
        response = await client.get(f"{settings.api_prefix}/users/not-a-valid-id")
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT

    async def test_update_user_with_empty_strings(self, admin_client, make_user):
        """Test updating user with empty strings."""
        client, admin_user = admin_client
        user = await make_user(full_name="Original Name")

        response = await client.put(f"{settings.api_prefix}/users/{user.id}", json={"full_name": "", "email": ""})

        # Validation rejects empty email (EmailStr validator)
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT

    async def test_assign_roles_with_invalid_role(self, admin_client, make_user):
        """Test assigning invalid role name."""
        client, admin_user = admin_client
        user = await make_user()

        response = await client.post(f"{settings.api_prefix}/users/{user.id}/roles", json={"roles": ["invalid_role"]})

        # Should return 422 validation error
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT

    async def test_assign_permissions_with_empty_list(self, admin_client, make_user, client):
        """Test assigning empty permissions list."""
        client, admin_user = admin_client
        user = await make_user()
        await UserService.assign_permissions(user, ["read:assets"])

        response = await client.post(f"{settings.api_prefix}/users/{user.id}/permissions", json={"permissions": []})

        # Validation requires at least one permission
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT

    async def test_delete_user_twice(self, admin_client, make_user):
        """Test deleting same user twice."""
        client, admin_user = admin_client
        user = await make_user(username="tobedeleted")

        # First delete
        response1 = await client.delete(f"{settings.api_prefix}/users/{user.id}")
        assert response1.status_code == status.HTTP_200_OK

        # Second delete
        response2 = await client.delete(f"{settings.api_prefix}/users/{user.id}")
        assert response2.status_code == status.HTTP_404_NOT_FOUND

    async def test_update_me_with_invalid_email(self, auth_client):
        """Test updating own email with invalid format."""
        client, user = auth_client

        response = await client.put(f"{settings.api_prefix}/users/me", json={"email": "not-an-email"})

        # Should return 422 validation error
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT

    async def test_change_password_with_same_password(self, auth_client):
        """Test changing password to the same password."""
        client, user = auth_client

        response = await client.post(
            f"{settings.api_prefix}/users/me/change-password",
            json={
                "current_password": "TestPass123!",
                "new_password": "TestPass123!",
                "confirm_new_password": "TestPass123!",
            },
        )

        # Should be allowed
        assert response.status_code == status.HTTP_200_OK

    async def test_get_user_unauthorized(self, client, make_user):
        """Test getting specific user without authentication."""
        user = await make_user(username="testuser")

        response = await client.get(f"{settings.api_prefix}/users/{user.id}")

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    async def test_list_users_unauthorized(self, client):
        """Test listing users without authentication."""
        response = await client.get(f"{settings.api_prefix}/users")

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    async def test_assign_roles_to_nonexistent_user(self, admin_client):
        """Test assigning roles to non-existent user."""
        client, admin_user = admin_client
        fake_id = "000000000000000000000000"

        response = await client.post(f"{settings.api_prefix}/users/{fake_id}/roles", json={"roles": ["admin"]})

        assert response.status_code == status.HTTP_404_NOT_FOUND

    async def test_assign_permissions_to_nonexistent_user(self, admin_client):
        """Test assigning permissions to non-existent user."""
        client, admin_user = admin_client
        fake_id = "000000000000000000000000"

        response = await client.post(
            f"{settings.api_prefix}/users/{fake_id}/permissions", json={"permissions": ["read:assets"]}
        )

        assert response.status_code == status.HTTP_404_NOT_FOUND

    async def test_update_nonexistent_user_as_admin(self, admin_client):
        """Test updating non-existent user."""
        client, admin_user = admin_client
        fake_id = "000000000000000000000000"

        response = await client.put(f"{settings.api_prefix}/users/{fake_id}", json={"full_name": "New Name"})

        assert response.status_code == status.HTTP_404_NOT_FOUND


class TestUserRegistrationWithLoggedInFlag:
    """Tests for user registration and is_logged_in flag"""

    async def test_registered_user_is_not_logged_in_by_default(self, session):
        """Newly registered user should have is_logged_in=False."""
        data = UserRegisterRequest(
            email="newuser@example.com",
            username="newuser",
            full_name="New User",
            password="SecurePass123!",
            confirm_password="SecurePass123!",
        )
        user = await UserService.register_user(session, data)

        assert user.is_logged_in is False

    async def test_register_multiple_users_all_not_logged_in(self, session):
        """Multiple registered users should all have is_logged_in=False."""
        for i in range(3):
            data = UserRegisterRequest(
                email=f"user{i}@example.com",
                username=f"user{i}",
                full_name=f"User {i}",
                password="SecurePass123!",
                confirm_password="SecurePass123!",
            )
            user = await UserService.register_user(session, data)
            assert user.is_logged_in is False

    async def test_registration_preserves_is_logged_in_false_in_db(self, session):
        """After registration, is_logged_in should persist as False in database."""
        data = UserRegisterRequest(
            email="persist@example.com",
            username="persist",
            full_name="Persist User",
            password="SecurePass123!",
            confirm_password="SecurePass123!",
        )
        user = await UserService.register_user(session, data)
        await session.commit()
        user_id = user.id

        # Retrieve from DB to verify persistence
        retrieved_user = await UserService.get_user(session, user_id)

        assert retrieved_user is not None
        assert retrieved_user.is_logged_in is False

    async def test_register_user_with_all_fields_and_is_logged_in_false(self, session):
        """Register user with all fields and verify is_logged_in is False."""
        data = UserRegisterRequest(
            email="complete@example.com",
            username="complete",
            full_name="Complete User",
            password="ComplexPass789!@#",
            confirm_password="ComplexPass789!@#",
        )
        user = await UserService.register_user(session, data)

        assert user.email == "complete@example.com"
        assert user.username == "complete"
        assert user.full_name == "Complete User"
        assert user.status == UserStatus.ACTIVE
        assert UserRole.TENANT_OWNER in user.roles
        assert user.is_logged_in is False
        assert user.verify_password("ComplexPass789!@#")

    async def test_register_user_is_logged_in_flag_independent_of_status(self, session):
        """is_logged_in flag should be independent of user status."""
        data = UserRegisterRequest(
            email="statususer@example.com",
            username="statususer",
            full_name="Status User",
            password="SecurePass123!",
            confirm_password="SecurePass123!",
        )
        user = await UserService.register_user(session, data)

        # User is ACTIVE but not logged in
        assert user.status == UserStatus.ACTIVE
        assert user.is_logged_in is False

    async def test_register_user_created_at_and_is_logged_in(self, session):
        """Verify created_at is set and is_logged_in is False on registration."""
        data = UserRegisterRequest(
            email="created@example.com",
            username="created",
            full_name="Created User",
            password="SecurePass123!",
            confirm_password="SecurePass123!",
        )
        user = await UserService.register_user(session, data)
        await session.flush()  # Flush to apply server defaults (created_at)

        assert user.created_at is not None
        assert user.is_logged_in is False


class TestUserIsLoggedInProperty:
    """Tests for is_logged_in property and state transitions"""

    async def test_user_is_logged_in_defaults_to_false(self, make_user):
        """User created via factory defaults to is_logged_in=False."""
        user = await make_user()

        assert user.is_logged_in is False

    async def test_set_user_is_logged_in_true(self, session, make_user):
        """Can set user is_logged_in to True."""
        user = await make_user()

        user.is_logged_in = True
        await session.commit()

        assert user.is_logged_in is True

        # Verify it persists
        retrieved = await UserService.get_user(session, user.id)
        
        assert retrieved is not None
        assert retrieved.is_logged_in is True

    async def test_set_user_is_logged_in_false_after_true(self, session, make_user):
        """Can set user is_logged_in back to False."""
        user = await make_user()

        # Set to True
        user.is_logged_in = True
        await session.commit()
        assert user.is_logged_in is True

        # Set to False
        user.is_logged_in = False
        await session.commit()
        assert user.is_logged_in is False

        # Verify it persists
        retrieved = await UserService.get_user(session, user.id)
        
        assert retrieved is not None
        assert retrieved.is_logged_in is False

    async def test_multiple_users_independent_is_logged_in_states(self, session, make_user):
        """Different users can have different is_logged_in states independently."""
        user1 = await make_user(username="user1", email="user1@example.com")
        user2 = await make_user(username="user2", email="user2@example.com")
        user3 = await make_user(username="user3", email="user3@example.com")

        # Set different states
        user1.is_logged_in = True
        user2.is_logged_in = False
        user3.is_logged_in = True
        await session.commit()

        # Retrieve and verify independence
        retrieved1 = await UserService.get_user(session, user1.id)
        retrieved2 = await UserService.get_user(session, user2.id)
        retrieved3 = await UserService.get_user(session, user3.id)

        assert retrieved1 is not None
        assert retrieved2 is not None
        assert retrieved3 is not None
        
        assert retrieved1.is_logged_in is True
        assert retrieved2.is_logged_in is False
        assert retrieved3.is_logged_in is True

    async def test_is_logged_in_not_affected_by_other_updates(self, session, make_user):
        """Updating other user fields should not affect is_logged_in."""
        user = await make_user(full_name="Original Name")

        user.is_logged_in = True
        await session.commit()

        # Update full_name
        user.full_name = "Updated Name"
        await session.commit()

        assert user.is_logged_in is True

        # Verify in DB
        retrieved = await UserService.get_user(session, user.id)
        
        assert retrieved is not None
        assert retrieved.full_name == "Updated Name"
        assert retrieved.is_logged_in is True

    async def test_is_logged_in_with_role_assignment(self, session, make_user):
        """Assigning roles should not affect is_logged_in state."""
        user = await make_user(roles=[UserRole.TENANT_OWNER])

        user.is_logged_in = True
        await session.commit()

        # Assign new role
        updated = await UserService.assign_roles(user, [UserRole.ADMIN])
        await session.commit()

        assert updated.is_logged_in is True

    async def test_is_logged_in_with_permission_assignment(self, session, make_user):
        """Assigning permissions should not affect is_logged_in state."""
        user = await make_user()

        user.is_logged_in = True
        await session.commit()

        # Assign permissions
        updated = await UserService.assign_permissions(user, ["read:assets"])
        await session.commit()

        assert updated.is_logged_in is True

    async def test_is_logged_in_preserved_across_password_change(self, session, make_user):
        """Changing password should preserve is_logged_in state."""
        user = await make_user(password="OldPass123!")

        user.is_logged_in = True
        await session.commit()

        # Change password
        await UserService.change_password(user, "OldPass123!", "NewPass456!")
        await session.commit()

        # Retrieve and verify
        retrieved = await UserService.get_user(session, user.id)
        
        assert retrieved is not None
        assert retrieved.is_logged_in is True

    async def test_is_logged_in_with_inactive_user(self, session, make_user):
        """Inactive user can still have is_logged_in flag set independently."""
        user = await make_user(status=UserStatus.INACTIVE)

        user.is_logged_in = True
        await session.commit()

        assert user.status == UserStatus.INACTIVE
        assert user.is_logged_in is True

    async def test_is_logged_in_with_locked_user(self, session, make_user):
        """Locked user can still have is_logged_in flag set independently."""
        user = await make_user(status=UserStatus.LOCKED)

        user.is_logged_in = True
        await session.commit()

        assert user.status == UserStatus.LOCKED
        assert user.is_logged_in is True


class TestUserRegistrationEdgeCases:
    """Additional edge case tests for registration"""

    async def test_register_user_special_characters_in_name(self, session):
        """Register user with special characters in full name."""
        data = UserRegisterRequest(
            email="special@example.com",
            username="special",
            full_name="José García-López O'Brien",
            password="SecurePass123!",
            confirm_password="SecurePass123!",
        )
        user = await UserService.register_user(session, data)

        assert user.full_name == "José García-López O'Brien"
        assert user.is_logged_in is False

    async def test_register_user_long_full_name(self, session):
        """Register user with long full name (max 200 characters)."""
        long_name = "A" * 200  # Max allowed length per schema
        data = UserRegisterRequest(
            email="longname@example.com",
            username="longname",
            full_name=long_name,
            password="SecurePass123!",
            confirm_password="SecurePass123!",
        )
        user = await UserService.register_user(session, data)

        assert user.full_name == long_name
        assert len(user.full_name) == 200
        assert user.is_logged_in is False

    async def test_register_user_case_sensitive_username(self, session):
        """Username should respect case sensitivity during registration."""
        data1 = UserRegisterRequest(
            email="case1@example.com",
            username="TestUser",
            full_name="User 1",
            password="SecurePass123!",
            confirm_password="SecurePass123!",
        )
        user1 = await UserService.register_user(session, data1)

        # Try with different case (should succeed if case-sensitive)
        data2 = UserRegisterRequest(
            email="case2@example.com",
            username="testuser",
            full_name="User 2",
            password="SecurePass123!",
            confirm_password="SecurePass123!",
        )
        user2 = await UserService.register_user(session, data2)

        assert user1.username != user2.username
        assert user1.is_logged_in is False
        assert user2.is_logged_in is False

    async def test_register_user_numeric_username(self, session):
        """Register user with numeric username."""
        data = UserRegisterRequest(
            email="numeric@example.com",
            username="12345",
            full_name="Numeric User",
            password="SecurePass123!",
            confirm_password="SecurePass123!",
        )
        user = await UserService.register_user(session, data)

        assert user.username == "12345"
        assert user.is_logged_in is False

    async def test_register_user_hyphenated_email(self, session):
        """Register user with hyphenated email domain."""
        data = UserRegisterRequest(
            email="user@my-domain.co.uk",
            username="hyphenated",
            full_name="Hyphenated Email",
            password="SecurePass123!",
            confirm_password="SecurePass123!",
        )
        user = await UserService.register_user(session, data)

        assert user.email == "user@my-domain.co.uk"
        assert user.is_logged_in is False

    async def test_register_user_with_plus_in_email(self, session):
        """Register user with plus sign in email (Gmail-style)."""
        data = UserRegisterRequest(
            email="user+test@example.com",
            username="plusemail",
            full_name="Plus Email User",
            password="SecurePass123!",
            confirm_password="SecurePass123!",
        )
        user = await UserService.register_user(session, data)

        assert user.email == "user+test@example.com"
        assert user.is_logged_in is False

    async def test_register_user_strong_password_preserved(self, session):
        """Registration preserves ability to verify strong passwords."""
        strong_password = "MyStr0ng!Pass@word#123$456"
        data = UserRegisterRequest(
            email="strong@example.com",
            username="strong",
            full_name="Strong Pass User",
            password=strong_password,
            confirm_password=strong_password,
        )
        user = await UserService.register_user(session, data)

        assert user.verify_password(strong_password)
        assert user.is_logged_in is False

    async def test_register_user_fails_with_duplicate_username_both_not_logged_in(self, session, make_user):
        """When registration fails due to duplicate username, both are not logged in."""
        user1 = await make_user(username="duplicate", email="first@example.com")

        data = UserRegisterRequest(
            email="second@example.com",
            username="duplicate",
            full_name="Duplicate User",
            password="SecurePass123!",
            confirm_password="SecurePass123!",
        )

        with pytest.raises(UsernameAlreadyExists):
            await UserService.register_user(session, data)

        # Original user still not logged in
        assert user1.is_logged_in is False

    async def test_register_user_fails_with_duplicate_email_both_not_logged_in(self, session, make_user):
        """When registration fails due to duplicate email, both are not logged in."""
        user1 = await make_user(email="duplicate@example.com", username="user1")

        data = UserRegisterRequest(
            email="duplicate@example.com",
            username="different",
            full_name="Different User",
            password="SecurePass123!",
            confirm_password="SecurePass123!",
        )

        with pytest.raises(EmailAlreadyExists):
            await UserService.register_user(session, data)

        # Original user still not logged in
        assert user1.is_logged_in is False

    async def test_register_user_default_role_is_tenant_owner(self, session):
        """Newly registered user should have TENANT_OWNER role by default."""
        data = UserRegisterRequest(
            email="tenant_owner@example.com",
            username="tenant_owner",
            full_name="Tenant Owner User",
            password="SecurePass123!",
            confirm_password="SecurePass123!",
        )
        user = await UserService.register_user(session, data)

        assert UserRole.TENANT_OWNER in user.roles
        assert len(user.roles) == 1
        assert user.is_logged_in is False

    async def test_register_user_has_no_permissions_initially(self, session):
        """Newly registered user should have no permissions."""
        data = UserRegisterRequest(
            email="noperm@example.com",
            username="noperm",
            full_name="No Permissions User",
            password="SecurePass123!",
            confirm_password="SecurePass123!",
        )
        user = await UserService.register_user(session, data)

        assert len(user.permissions) == 0
        assert user.is_logged_in is False

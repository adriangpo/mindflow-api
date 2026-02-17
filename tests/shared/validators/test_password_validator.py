"""Tests for the shared validators module."""

import pytest

from src.shared.validators.password import validate_password_strength


class TestPasswordValidation:
    """Test password strength validation."""

    def test_valid_password_with_all_requirements(self):
        """Test password with all requirements passes validation."""
        result = validate_password_strength("SecurePass123")
        assert result == "SecurePass123"

    def test_valid_password_with_special_characters(self):
        """Test password with special characters passes validation."""
        result = validate_password_strength("Secure@Pass123!")
        assert result == "Secure@Pass123!"

    def test_valid_password_minimum_length(self):
        """Test password with minimum requirements passes validation."""
        result = validate_password_strength("Abcd123")
        assert result == "Abcd123"

    def test_password_without_uppercase_fails(self):
        """Test password without uppercase letter fails validation."""
        with pytest.raises(ValueError, match="Password must contain at least one uppercase letter"):
            validate_password_strength("securepass123")

    def test_password_without_lowercase_fails(self):
        """Test password without lowercase letter fails validation."""
        with pytest.raises(ValueError, match="Password must contain at least one lowercase letter"):
            validate_password_strength("SECUREPASS123")

    def test_password_without_digit_fails(self):
        """Test password without digit fails validation."""
        with pytest.raises(ValueError, match="Password must contain at least one digit"):
            validate_password_strength("SecurePass")

    def test_password_only_uppercase_and_digit_fails(self):
        """Test password with only uppercase and digit fails (missing lowercase)."""
        with pytest.raises(ValueError, match="Password must contain at least one lowercase letter"):
            validate_password_strength("SECUREPASS123")

    def test_password_only_lowercase_and_digit_fails(self):
        """Test password with only lowercase and digit fails (missing uppercase)."""
        with pytest.raises(ValueError, match="Password must contain at least one uppercase letter"):
            validate_password_strength("securepass123")

    def test_password_only_letters_fails(self):
        """Test password with only letters fails (missing digit)."""
        with pytest.raises(ValueError, match="Password must contain at least one digit"):
            validate_password_strength("SecurePassword")

    def test_password_with_spaces(self):
        """Test password with spaces passes if requirements are met."""
        result = validate_password_strength("Secure Pass 123")
        assert result == "Secure Pass 123"

    def test_password_with_unicode_characters(self):
        """Test password with unicode characters passes if requirements are met."""
        result = validate_password_strength("Sécure123")
        assert result == "Sécure123"

    def test_password_very_long(self):
        """Test very long password passes validation."""
        long_password = "SecurePassword123" * 10
        result = validate_password_strength(long_password)
        assert result == long_password

    def test_password_edge_case_single_chars(self):
        """Test password with single character of each type passes."""
        result = validate_password_strength("A1a")
        assert result == "A1a"

    def test_password_multiple_digits(self):
        """Test password with multiple digits passes."""
        result = validate_password_strength("Pass123456789")
        assert result == "Pass123456789"

    def test_password_multiple_uppercase(self):
        """Test password with multiple uppercase letters passes."""
        result = validate_password_strength("SECUREpass123")
        assert result == "SECUREpass123"

    def test_password_multiple_lowercase(self):
        """Test password with multiple lowercase letters passes."""
        result = validate_password_strength("SECUREpassword123")
        assert result == "SECUREpassword123"

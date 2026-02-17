"""Password validation functions."""


def validate_password_strength(password: str) -> str:
    """Validate password strength requirements.

    Requirements:
    - At least 8 characters (should be enforced by Field min_length)
    - At least one uppercase letter (A-Z)
    - At least one lowercase letter (a-z)
    - At least one digit (0-9)

    Args:
        password: Password string to validate

    Returns:
        The validated password string

    Raises:
        ValueError: If password doesn't meet strength requirements

    Examples:
        >>> validate_password_strength("SecurePass123")
        'SecurePass123'
        >>> validate_password_strength("weakpass")
        Traceback (most recent call last):
        ...
        ValueError: Password must contain at least one uppercase letter

    """
    if not any(c.isupper() for c in password):
        raise ValueError("Password must contain at least one uppercase letter")
    if not any(c.islower() for c in password):
        raise ValueError("Password must contain at least one lowercase letter")
    if not any(c.isdigit() for c in password):
        raise ValueError("Password must contain at least one digit")
    return password

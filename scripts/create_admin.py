#!/usr/bin/env python3
"""Create an admin user in the database.

Usage:
    uv run python scripts/create_admin.py \
      --email admin@example.com \
      --username admin \
      --full-name "System Admin" \
      --password "StrongPass123!"
"""

import argparse
import asyncio
import sys
from pathlib import Path

from sqlalchemy import or_, select
from sqlalchemy.exc import ProgrammingError

# Ensure project root is available on PYTHONPATH when running as a script.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.database.client import close_db, get_session, init_db
from src.features.user.models import User, UserRole, UserStatus
from src.shared.validators.password import validate_password_strength


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(description="Create an admin user")
    parser.add_argument("--email", default="admin@example.com", help="Admin email")
    parser.add_argument("--username", default="sys.admin", help="Admin username")
    parser.add_argument("--full-name", default="System Administrator", help="Admin full name")
    parser.add_argument(
        "--password",
        default="Admin123!",
        help="Admin password",
    )
    return parser.parse_args()


async def create_admin(email: str, username: str, full_name: str, password: str) -> int:
    """Create admin user and return id."""
    await init_db()
    try:
        async with get_session() as session:
            stmt = select(User).where(or_(User.email == email, User.username == username))
            result = await session.execute(stmt)
            existing = result.scalar_one_or_none()

            if existing:
                if UserRole.ADMIN.value in existing.roles:
                    raise ValueError(
                        f"Admin user already exists (id={existing.id}, email={existing.email}, username={existing.username})"
                    )
                raise ValueError(
                    "User already exists with same email/username but is not admin. "
                    f"Existing id={existing.id}, email={existing.email}, username={existing.username}"
                )

            user = User(
                email=email,
                username=username,
                full_name=full_name,
                hashed_password=User.hash_password(password),
                roles=[UserRole.ADMIN.value],
                status=UserStatus.ACTIVE.value,
                is_logged_in=False,
                permissions=[],
                tenant_ids=[],
            )
            session.add(user)
            await session.flush()
            return user.id
    finally:
        await close_db()


def main() -> int:
    """CLI entrypoint."""
    args = parse_args()
    password = args.password

    try:
        validate_password_strength(password)
    except ValueError as exc:
        print(f"Invalid password: {exc}", file=sys.stderr)
        return 1

    try:
        user_id = asyncio.run(
            create_admin(
                email=args.email.strip(),
                username=args.username.strip(),
                full_name=args.full_name.strip(),
                password=password,
            )
        )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except ProgrammingError as exc:
        if "UndefinedTableError" in str(exc) or 'relation "users" does not exist' in str(exc):
            print(
                "Database schema is missing. Run migrations first:\n"
                "  uv run alembic upgrade head",
                file=sys.stderr,
            )
            return 1
        print(f"Database error while creating admin user: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # pragma: no cover - defensive CLI guard
        print(f"Failed to create admin user: {exc}", file=sys.stderr)
        return 1

    print(f"Admin user created successfully (id={user_id})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

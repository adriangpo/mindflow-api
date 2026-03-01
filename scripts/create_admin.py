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
import getpass
import sys
from pathlib import Path

from sqlalchemy import or_, select
from sqlalchemy.exc import ProgrammingError

# Ensure project root is available on PYTHONPATH when running as a script.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.database.base import Base
from src.database.client import close_db, get_session, init_db
from src.features.user.models import User, UserRole, UserStatus
from src.shared.validators.password import validate_password_strength


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(description="Create an admin user")
    parser.add_argument("--email", required=True, help="Admin email")
    parser.add_argument("--username", required=True, help="Admin username")
    parser.add_argument("--full-name", required=True, help="Admin full name")
    parser.add_argument(
        "--password",
        required=False,
        help="Admin password (if omitted, prompt securely)",
    )
    parser.add_argument(
        "--bootstrap-schema",
        action="store_true",
        help="Create database tables if they do not exist (dev/local convenience)",
    )
    return parser.parse_args()


async def bootstrap_schema() -> None:
    """Create all tables from SQLAlchemy metadata."""
    from src.database.client import get_engine

    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def create_admin(email: str, username: str, full_name: str, password: str, bootstrap: bool = False) -> int:
    """Create admin user and return id."""
    await init_db()
    try:
        if bootstrap:
            await bootstrap_schema()

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
    password = args.password or getpass.getpass("Password: ")

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
                bootstrap=args.bootstrap_schema,
            )
        )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except ProgrammingError as exc:
        if "UndefinedTableError" in str(exc) or 'relation "users" does not exist' in str(exc):
            print(
                "Database schema is missing. Run migrations first:\n"
                "  uv run alembic upgrade head\n"
                "Or run this script with --bootstrap-schema for local/dev setup.",
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

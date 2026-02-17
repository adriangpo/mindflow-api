.PHONY: help lint format type-check test test-cov clean install check-all test-auth test-user test-audit db-upgrade db-downgrade db-revision db-migrate docker-up docker-down docker-test-up docker-test-down
UV_RUN := uv run
PYTEST := $(UV_RUN) pytest
BLACK := $(UV_RUN) black
RUFF := $(UV_RUN) ruff
MYPY := $(UV_RUN) mypy
ALEMBIC := $(UV_RUN) alembic

help:
	@echo "Mindflow - Development Commands"
	@echo ""
	@echo "Setup:"
	@echo "  make install          Install development dependencies"
	@echo ""
	@echo "Docker:"
	@echo "  make docker-up        Start PostgreSQL (dev)"
	@echo "  make docker-down      Stop PostgreSQL (dev)"
	@echo "  make docker-test-up   Start PostgreSQL (test)"
	@echo "  make docker-test-down Stop PostgreSQL (test)"
	@echo ""
	@echo "Database:"
	@echo "  make db-upgrade       Apply all pending migrations"
	@echo "  make db-downgrade     Rollback last migration"
	@echo "  make db-revision      Create a new migration (autogenerate)"
	@echo "  make db-migrate       Shortcut for db-revision + db-upgrade"
	@echo ""
	@echo "Code Quality:"
	@echo "  make lint             Run all linting checks (ruff + black --check)"
	@echo "  make format           Format code with black"
	@echo "  make type-check       Run type checking with mypy"
	@echo "  make check-all        Run lint + type-check (all checks without changes)"
	@echo ""
	@echo "Testing:"
	@echo "  make test             Run all tests"
	@echo "  make test-cov         Run tests with coverage report"
	@echo "  make test-auth        Run only auth feature tests"
	@echo "  make test-user        Run only user feature tests"
	@echo "  make test-audit       Run only audit feature tests"
	@echo ""
	@echo "Cleanup:"
	@echo "  make clean            Remove cache files and build artifacts"
	@echo ""

install:
	@echo "Installing dependencies..."
	uv sync
	@echo "✓ Dependencies installed"

docker-up:
	@echo "Starting PostgreSQL (dev)..."
	docker compose up -d postgres
	@echo "Waiting for PostgreSQL to be ready..."
	@sleep 2
	@echo "✓ PostgreSQL is running on port 5432"

docker-down:
	@echo "Stopping PostgreSQL (dev)..."
	docker compose down
	@echo "✓ PostgreSQL stopped"

docker-test-up:
	@echo "Starting PostgreSQL (test)..."
	docker compose up -d postgres_test
	@echo "Waiting for PostgreSQL to be ready..."
	@sleep 2
	@echo "✓ Test PostgreSQL is running on port 5433"

docker-test-down:
	@echo "Stopping PostgreSQL (test)..."
	docker compose stop postgres_test
	@echo "✓ Test PostgreSQL stopped"

db-upgrade:
	@echo "Applying database migrations..."
	$(ALEMBIC) upgrade head
	@echo "✓ Migrations applied"

db-downgrade:
	@echo "Rolling back last migration..."
	$(ALEMBIC) downgrade -1
	@echo "✓ Migration rolled back"

db-revision:
	@echo "Creating new migration..."
	@read -p "Migration message: " msg; \
	$(ALEMBIC) revision --autogenerate -m "$$msg"
	@echo "✓ Migration created"

db-migrate: db-revision db-upgrade
	@echo "✓ Migration created and applied"

lint:
	@echo "Running linting checks..."
	@echo ""
	@echo "→ Checking code style with black..."
	$(BLACK) --check src tests
	@echo "✓ Black check passed"
	@echo ""
	@echo "→ Checking code with ruff (imports, style, complexity)..."
	$(RUFF) check src tests
	@echo "✓ Ruff check passed"
	@echo ""
	@echo "✓ All linting checks passed"
format:
	@echo "Formatting code with black..."
	$(BLACK) src tests
	@echo "✓ Code formatted"
type-check:
	@echo "Running type checking with mypy..."
	$(MYPY) src
	@echo "✓ Type checking passed"
check-all: lint type-check
	@echo "✓ All checks passed!"
test: docker-test-up
	@echo "Running all tests..."
	$(PYTEST) tests/ -v
test-cov: docker-test-up
	@echo "Running tests with coverage..."
	$(PYTEST) tests/ -v --cov=src --cov-report=html --cov-report=term-missing
	@echo "✓ Tests completed. Coverage report: htmlcov/index.html"
test-auth:
	@echo "Running auth tests..."
	$(PYTEST) tests/features/auth/ -v
test-user:
	@echo "Running user tests..."
	$(PYTEST) tests/features/user/ -v
test-audit:
	@echo "Running audit tests..."
	$(PYTEST) tests/features/test_audit.py -v
clean:
	@echo "Cleaning cache files..."
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .mypy_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name htmlcov -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type f -name ".coverage" -delete
	@echo "✓ Cache cleaned"
.DEFAULT_GOAL := help

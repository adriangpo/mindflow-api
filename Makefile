.PHONY: help lint format type-check security-audit test test-cov clean install check-all db-upgrade db-downgrade db-revision db-migrate docker-start docker-up docker-down docker-test-up docker-test-down docker-test-reset
UV_RUN := uv run
ENVIRONMENT ?= development
CLEAR_VOLUMES ?= false
REMOVE_ORPHANS ?= true
REMOVE_IMAGES ?= none
PYTEST := $(UV_RUN) pytest
BLACK := $(UV_RUN) black
RUFF := $(UV_RUN) ruff
MYPY := $(UV_RUN) mypy
ALEMBIC := $(UV_RUN) alembic
PIP_AUDIT := $(UV_RUN) pip-audit

help:
	@echo "Mindflow - Development Commands"
	@echo ""
	@echo "Setup:"
	@echo "  make install          Install development dependencies"
	@echo ""
	@echo "Docker:"
	@echo "  make docker-start     Start API + DB (ENVIRONMENT=development|staging|production)"
	@echo "  make docker-up        Start API + DB without build"
	@echo "  make docker-down      Stop Docker services (supports cleanup flags)"
	@echo "  make docker-test-up   Start PostgreSQL test service"
	@echo "  make docker-test-down Stop PostgreSQL test service"
	@echo "  make docker-test-reset Force recreate PostgreSQL test service"
	@echo ""
	@echo "  Examples:"
	@echo "    make docker-start ENVIRONMENT=development"
	@echo "    make docker-start ENVIRONMENT=production"
	@echo "    make docker-up ENVIRONMENT=staging"
	@echo "    make docker-test-up"
	@echo "    make docker-test-reset"
	@echo "    make docker-down ENVIRONMENT=development CLEAR_VOLUMES=true"
	@echo "    make docker-down REMOVE_ORPHANS=false REMOVE_IMAGES=local"
	@echo ""
	@echo "Database:"
	@echo "  make db-upgrade       Apply all pending migrations"
	@echo "  make db-downgrade     Rollback last migration"
	@echo "  make db-revision      Create a new migration (autogenerate)"
	@echo "  make db-migrate       Shortcut for db-revision + db-upgrade"
	@echo ""
	@echo "Code Quality:"
	@echo "  make security-audit   Run dependency vulnerability audit with pip-audit"
	@echo "  make format           Format code with black"
	@echo "  make lint             Run all linting checks (ruff + black --check)"
	@echo "  make type-check       Run type checking with mypy"
	@echo "  make check-all        Run format + lint + type-check"
	@echo ""
	@echo "Testing:"
	@echo "  make test             Run all tests"
	@echo "  make test-cov         Run tests with coverage report"
	@echo ""
	@echo "Cleanup:"
	@echo "  make clean            Remove cache files and build artifacts"
	@echo ""

install:
	@echo "Installing dependencies..."
	uv sync --all-extras
	@echo "✓ Dependencies installed"

docker-start:
	@echo "Starting Docker services for ENVIRONMENT=$(ENVIRONMENT)..."
	@COMPOSE_PROFILES="$(ENVIRONMENT)" docker compose up --build -d
	@echo "✓ Docker services started"

docker-up:
	@echo "Starting Docker services for ENVIRONMENT=$(ENVIRONMENT) (no build)..."
	@COMPOSE_PROFILES="$(ENVIRONMENT)" docker compose up -d
	@echo "✓ Docker services started (no build)"

docker-down:
	@echo "Stopping Docker services for ENVIRONMENT=$(ENVIRONMENT)..."
	@cmd="docker compose down"; \
	cmd="COMPOSE_PROFILES=$(ENVIRONMENT) $$cmd"; \
	if [ "$(CLEAR_VOLUMES)" = "true" ]; then \
		cmd="$$cmd -v"; \
	fi; \
	if [ "$(REMOVE_ORPHANS)" = "true" ]; then \
		cmd="$$cmd --remove-orphans"; \
	fi; \
	if [ "$(REMOVE_IMAGES)" != "none" ]; then \
		cmd="$$cmd --rmi $(REMOVE_IMAGES)"; \
	fi; \
	eval "$$cmd"
	@echo "✓ Docker services stopped"

docker-test-up:
	@echo "Ensuring PostgreSQL test service is running..."
	@test -f .env.test || { echo "ERROR: .env.test not found. Create it from .env.test.example."; exit 1; }; \
	test_port=$$(awk -F= '/^TEST_POSTGRES_PORT=/{print $$2}' .env.test | tail -n1 | tr -d '\r'); \
	if [ -z "$$test_port" ]; then test_port="5433"; fi; \
	docker compose --env-file .env.test up -d postgres_test; \
	echo "Waiting for PostgreSQL test service to be ready..."; \
	container_id=$$(docker compose --env-file .env.test ps -q postgres_test); \
	for i in $$(seq 1 30); do \
		status=$$(docker inspect --format '{{.State.Health.Status}}' $$container_id 2>/dev/null || echo "starting"); \
		if [ "$$status" = "healthy" ]; then \
			echo "✓ PostgreSQL test service is ready on port $$test_port"; \
			exit 0; \
		fi; \
		if [ "$$status" = "unhealthy" ]; then \
			echo "ERROR: PostgreSQL test service became unhealthy"; \
			docker logs --tail 80 $$container_id; \
			exit 1; \
		fi; \
		sleep 1; \
	done; \
	echo "ERROR: Timed out waiting for PostgreSQL test service to become healthy"; \
	docker logs --tail 80 $$container_id; \
	exit 1

docker-test-down:
	@echo "Stopping PostgreSQL test service..."
	@docker compose --env-file .env.test stop postgres_test
	@echo "✓ PostgreSQL test service stopped"

docker-test-reset:
	@echo "Resetting PostgreSQL test service..."
	@docker compose --env-file .env.test rm -f -s postgres_test >/dev/null 2>&1 || true
	@$(MAKE) docker-test-up

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

security-audit:
	@echo "Running dependency vulnerability audit..."
	$(PIP_AUDIT)
	@echo "✓ Dependency audit passed"

format:
	@echo "Formatting code with black..."
	$(BLACK) src tests
	@echo "✓ Code formatted"

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

type-check:
	@echo "Running type checking with mypy..."
	$(MYPY) src
	@echo "✓ Type checking passed"

check-all: security-audit format lint type-check
	@echo "✓ All checks passed!"

test: docker-test-up
	@echo "Running all tests..."
	$(PYTEST) tests/ -v

test-cov: docker-test-up
	@echo "Running tests with coverage..."
	$(PYTEST) tests/ -v --cov=src --cov-report=html --cov-report=term-missing
	@echo "✓ Tests completed. Coverage report: htmlcov/index.html"

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

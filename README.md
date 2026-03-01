# Mindflow API

Backend system for corporate fixed-asset management with FastAPI, PostgreSQL, and Multi-Tenancy support.

## 📚 Documentation

## Quick Start

### 1. Install Dependencies

```bash
# Using uv (recommended)
uv sync

# Or using pip
pip install -e .
```

### 2. Configure Environment

Copy the example environment file and edit as needed:

```bash
cp .env.example .env
```

**Important:** Update the configuration in `.env`:

```bash
# Generate a secure secret key
openssl rand -hex 32
```

Edit `.env` and configure:
- `SECRET_KEY` - Use the generated key above
- `POSTGRES_URL` - Your PostgreSQL connection string

Example PostgreSQL URL:
```
POSTGRES_URL=postgresql+asyncpg://username:password@localhost:5432/dbname
```

### 3. Start PostgreSQL

Make sure PostgreSQL is running:

```bash
# Using Docker (recommended for development)
docker run -d \
  --name mindflow-postgres \
  -e POSTGRES_USER=mindflow \
  -e POSTGRES_PASSWORD=mindflow \
  -e POSTGRES_DB=mindflow \
  -p 5432:5432 \
  postgres:16-alpine

# Or use your local PostgreSQL installation
```

### 4. Run Database Migrations

```bash
# Apply all migrations to create tables
make db-upgrade

# Or use alembic directly
alembic upgrade head
```

### 5. Run the API

```bash
uvicorn src.main:app --reload
```

Visit http://localhost:8000/docs for interactive API documentation.

## Project Structure

```
src/
├── config/          # Configuration and settings
├── database/        # Database connection management
├── features/        # Feature-based modules
│   └── auth/        # Authentication & authorization
│       ├── models.py      # User and RefreshToken models
│       ├── schemas.py     # API request/response schemas
│       ├── service.py     # Business logic
│       ├── dependencies.py # FastAPI dependencies
│       ├── router.py      # API endpoints
│       └── jwt_utils.py   # JWT token utilities
└── main.py          # FastAPI application entry point
```

## Authentication

### User Roles

- **ADMIN**: Platform-level administrator (cross-tenant). Can manage accounts, enforce read-only mode, manage plans, and perform support operations. Does NOT participate in clinical operations.
- **TENANT_OWNER**: The autonomous professional. Owner of the tenant. Has full access to: patients, medical records, agenda, scheduling, financial management, notifications, and assistants. ONLY role allowed to access medical records.
- **ASSISTANT**: Secretary role. Can: schedule appointments, update appointment status, manage financial entries, send notifications. Cannot: access medical records, export records, modify configuration, delete patients.

### API Endpoints

#### Public Endpoints
- `POST /api/auth/login` - Login with username/password
- `POST /api/auth/refresh` - Refresh access token

#### Authenticated Endpoints
- `GET /api/users/me` - Get current user profile
- `PUT /api/users/me` - Update current user profile
- `POST /api/users/me/change-password` - Change password
- `POST /api/auth/logout` - Logout (revoke refresh token)

#### Admin Endpoints
- `POST /api/users` - Register new user
- `GET /api/users` - List all users
- `GET /api/users/{user_id}` - Get user by ID
- `PUT /api/users/{user_id}` - Update user
- `DELETE /api/users/{user_id}` - Delete user

### Using Authentication

1. **Login:**
```bash
curl -X POST "http://localhost:8000/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}'
```

Response:
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "token_type": "bearer",
  "expires_in": 1800
}
```

2. **Use Access Token:**
```bash
curl -X GET "http://localhost:8000/api/users/me" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

3. **Refresh Token:**
```bash
curl -X POST "http://localhost:8000/api/auth/refresh" \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "YOUR_REFRESH_TOKEN"}'
```

## Configuration

All configuration is managed through environment variables. Copy `.env.example` to `.env` and customize:

```bash
cp .env.example .env
```

Key configuration options:

```env
# Application
DEBUG=False

# PostgreSQL
POSTGRES_URL=postgresql+asyncpg://user:password@localhost:5432/dbname

# Security (CHANGE IN PRODUCTION!)
SECRET_KEY=your-secret-key-here
ACCESS_TOKEN_EXPIRE_MINUTES=30

# Logging
LOG_LEVEL=INFO
```

See `.env.example` for all available configuration options.

## What's Included

✅ FastAPI application with async support  
✅ PostgreSQL database with SQLAlchemy (async)  
✅ Database migrations with Alembic  
✅ JWT-based authentication  
✅ Role-based access control (RBAC)  
✅ User management (CRUD)  
✅ Password hashing (argon2)  
✅ Refresh token rotation  
✅ Account locking after failed attempts  
✅ Environment-based configuration  
✅ Health check endpoints  
✅ OpenAPI/Swagger documentation  
✅ Comprehensive test suite with SQLite  
✅ Multi-tenancy with PostgreSQL Row-Level Security (RLS)  
✅ CORS support with configurable origins  
✅ Rate limiting via SlowAPI  
✅ UUID v7 for modern ID generation

## Security Features

- **Password Hashing**: Using argon2 via pwdlib
- **JWT Tokens**: Access tokens (30 min) + Refresh tokens (7 days)
- **Token Rotation**: New refresh token issued on every refresh
- **Account Locking**: Auto-lock after 5 failed login attempts (30 min)
- **Role-Based Access Control**: Fine-grained permissions per role
- **Audit Trail**: Track login times, failed attempts, token usage
- **Multi-Tenancy**: PostgreSQL Row-Level Security ensures strict tenant isolation
- **CORS**: Configurable cross-origin resource sharing for frontend integration
- **Rate Limiting**: Per-IP rate limiting via SlowAPI for DDoS protection

## Recent Improvements

### Multi-Tenancy (Production-Ready)
- ✅ Shared-table multi-tenancy model with PostgreSQL RLS
- ✅ Tenant identification via X-Tenant-ID header
- ✅ Database-level enforcement of tenant isolation
- ✅ Three-layer defense: HTTP → Application → Database

### Modern Infrastructure
- ✅ **UUID v7** for better timestamp ordering and performance
- ✅ **CORS middleware** with configurable origins (default: allow all)
- ✅ **Rate limiting** with per-IP tracking via SlowAPI
- ✅ Clean module structure with no circular imports

## Next Steps

Future features to be added:
- Exception handling and approvals
- Export functionality (Excel/CSV)
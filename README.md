# EVA Authentication & Authorization Service

**OAuth 2.0, JWT validation, RBAC, and session management for EVA Suite**

## Overview

eva-auth provides authentication and authorization services for the entire EVA Suite:

- **Dual Authentication Channels**: Azure AD B2C (citizens) + Microsoft Entra ID (employees)
- **OAuth 2.0 Flows**: Authorization Code Flow with PKCE
- **JWT Validation**: RS256 signature verification with JWKS caching
- **RBAC**: Role-based access control with tenant isolation
- **Session Management**: Redis-backed sessions with token blacklisting
- **API Keys**: M2M authentication for service-to-service calls

## Quick Start

### Prerequisites

- Python 3.11+
- Poetry 1.7+
- Docker & Docker Compose
- Redis 7.2+

### Installation

```bash
# Install dependencies
poetry install

# Copy environment template
cp .env.example .env

# Edit .env with your Azure AD configuration
nano .env

# Start services with Docker Compose
docker-compose up -d

# Run the application
poetry run uvicorn eva_auth.main:app --reload
```

### Development with Mock Authentication

For local development without Azure AD:

```bash
# Enable mock authentication in .env
ENABLE_MOCK_AUTH=true

# Generate test token
curl -X POST "http://localhost:8000/auth/mock/token?user_id=test-user&email=test@example.com"

# Validate token
curl -X POST "http://localhost:8000/auth/validate" \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

## Testing

```bash
# Run all tests
poetry run pytest

# Run with coverage
poetry run pytest --cov=eva_auth --cov-report=html

# Run specific test file
poetry run pytest tests/test_jwt_validator.py

# View coverage report
open htmlcov/index.html
```

## API Endpoints

### Health Check

- `GET /health` - Health check
- `GET /ready` - Readiness check

### Authentication

- `POST /auth/mock/token` - Generate mock token (dev only)
- `POST /auth/validate` - Validate JWT token
- `GET /auth/b2c/authorize` - Start Azure AD B2C OAuth flow
- `GET /auth/b2c/callback` - Handle B2C OAuth callback
- `GET /auth/entra/authorize` - Start Microsoft Entra ID OAuth flow
- `GET /auth/entra/callback` - Handle Entra ID OAuth callback

### Documentation

- `GET /docs` - Swagger UI
- `GET /redoc` - ReDoc
- `GET /openapi.json` - OpenAPI specification

## Architecture

```
┌─────────────────────────────────────────────┐
│          EVA Suite Services                 │
│  eva-api │ eva-core │ eva-rag │ eva-ui     │
└─────────────────┬───────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────┐
│              eva-auth                       │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐ │
│  │   JWT    │  │   RBAC   │  │ Session  │ │
│  │Validator │  │  Engine  │  │  Manager │ │
│  └──────────┘  └──────────┘  └──────────┘ │
└─────────────────┬───────────────────────────┘
                  │
       ┌──────────┴──────────┐
       ▼                     ▼
┌─────────────┐     ┌─────────────────┐
│ Azure AD    │     │ Microsoft       │
│ B2C         │     │ Entra ID        │
└─────────────┘     └─────────────────┘
```

## Configuration

Key environment variables:

```bash
# Azure AD B2C
AZURE_B2C_TENANT_NAME=your-tenant
AZURE_B2C_CLIENT_ID=your-client-id
AZURE_B2C_CLIENT_SECRET=your-client-secret

# Microsoft Entra ID
AZURE_ENTRA_TENANT_ID=your-tenant-id
AZURE_ENTRA_CLIENT_ID=your-client-id
AZURE_ENTRA_CLIENT_SECRET=your-client-secret

# Redis
REDIS_URL=redis://localhost:6379

# JWT
JWT_ALGORITHM=RS256
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=60
```

See `.env.example` for complete configuration options.

## Development

### Project Structure

```
eva-auth/
├── src/eva_auth/
│   ├── config.py              # Configuration settings
│   ├── models.py              # Data models
│   ├── main.py                # FastAPI application
│   ├── middleware/            # Authentication middleware
│   ├── providers/             # OAuth providers (B2C, Entra ID)
│   ├── validators/            # JWT validators
│   ├── session/               # Session management
│   ├── routers/               # API routes
│   └── testing/               # Mock providers
├── tests/                     # Test suite
├── docker-compose.yml         # Docker services
├── pyproject.toml            # Dependencies
└── README.md                 # This file
```

### Code Quality

```bash
# Format code
poetry run black src/ tests/

# Sort imports
poetry run isort src/ tests/

# Lint code
poetry run ruff src/ tests/

# Type checking
poetry run mypy src/

# Run pre-commit hooks
poetry run pre-commit run --all-files
```

## Phase 1 Deliverables

✅ **Core Infrastructure**
- FastAPI application with Docker Compose
- Configuration management with Pydantic
- Redis session management
- Pytest with 100% coverage target

✅ **OAuth Providers**
- Azure AD B2C integration
- Microsoft Entra ID integration
- Authorization URL generation
- Token exchange flows

✅ **JWT Validation**
- RS256 signature verification
- JWKS caching
- Claim extraction
- Mock validator for testing

✅ **Session Management**
- Redis-backed sessions
- Token blacklisting
- Session CRUD operations

✅ **Testing**
- Mock authentication provider
- Pytest fixtures
- Comprehensive test suite

## License

Internal use only - EVA Suite project

## Support

For issues or questions, contact the EVA team or refer to the specification:
- `docs/SPECIFICATION.md` - Complete technical specification
- `.eva-memory.json` - Project memory and context

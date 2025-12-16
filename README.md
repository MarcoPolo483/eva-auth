# EVA Authentication & Authorization Service

**Production-ready authentication service for EVA Suite**

[![Coverage](https://img.shields.io/badge/coverage-99.61%25-brightgreen)](./COVERAGE-REPORT.md)
[![Tests](https://img.shields.io/badge/tests-202%20passing-brightgreen)](./tests)
[![Security](https://img.shields.io/badge/security-97%2F100-brightgreen)](./docs/SECURITY-CHECKLIST.md)
[![Performance](https://img.shields.io/badge/performance-Grade%20A-brightgreen)](./reports/LOAD-TEST-RESULTS.md)

## Status

✅ **Production Ready** - Version 1.0.0

Comprehensive authentication service with 99.61% test coverage, Grade A performance (194.8 RPS), and OWASP Top 10 compliance (97/100).

## Overview

eva-auth provides enterprise-grade authentication and authorization services for the entire EVA Suite:

- **Dual Authentication Channels**: Azure AD B2C (citizens) + Microsoft Entra ID (employees)
- **OAuth 2.0 Flows**: Authorization Code Flow with PKCE
- **JWT Validation**: RS256 signature verification with JWKS caching
- **RBAC**: Role-based access control with tenant isolation
- **Session Management**: Redis-backed sessions with token blacklisting
- **API Keys**: M2M authentication for service-to-service calls
- **Audit Logging**: Comprehensive event tracking in Azure Cosmos DB

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
├── .github/workflows/         # CI/CD pipelines
├── docs/                      # Documentation
├── infrastructure/azure/      # Bicep templates
├── reports/                   # Test reports
├── scripts/                   # Automation scripts
├── src/eva_auth/
│   ├── config.py              # Configuration settings
│   ├── models.py              # Data models
│   ├── main.py                # FastAPI application
│   ├── apikeys/               # API key management
│   ├── audit/                 # Audit logging
│   ├── middleware/            # Authentication middleware
│   ├── providers/             # OAuth providers (B2C, Entra ID)
│   ├── rbac/                  # RBAC engine
│   ├── routers/               # API routes
│   ├── session/               # Session management
│   ├── testing/               # Mock providers
│   └── validators/            # JWT validators
├── tests/                     # Test suite (202 tests)
├── docker-compose.yml         # Docker services
├── Dockerfile                 # Container image
├── pyproject.toml            # Dependencies
├── COVERAGE-REPORT.md        # Coverage analysis
└── PROJECT-SUMMARY.md        # Executive summary
```

## Documentation

**Project Documentation:**
- [Project Summary](./PROJECT-SUMMARY.md) - Executive overview and metrics
- [Coverage Report](./COVERAGE-REPORT.md) - Test coverage analysis (99.61%)
- [Specification](./docs/SPECIFICATION.md) - Detailed requirements and design

**Implementation Evidence:**
- [Phase 1 Evidence](./docs/PHASE-1-EVIDENCE.md) - Foundation implementation
- [Phase 2 Evidence](./docs/PHASE-2-EVIDENCE.md) - Data layer implementation
- [Phase 3 Evidence](./docs/PHASE-3-EVIDENCE.md) - Integration & testing

**Operations:**
- [Deployment Guide](./docs/DEPLOYMENT.md) - Azure infrastructure & CI/CD
- [Integration Guide](./docs/INTEGRATION.md) - Service integration patterns
- [Security Checklist](./docs/SECURITY-CHECKLIST.md) - OWASP Top 10 compliance
- [Load Test Results](./reports/LOAD-TEST-RESULTS.md) - Performance metrics

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

## Quality Metrics

**Test Coverage:** 99.61% (758/761 statements)
- 202 tests passing, 0 failures
- All critical paths covered
- Edge cases validated

**Performance:** Grade A
- 194.8 RPS sustained load
- P95 latency: 25ms
- P99 latency: 48ms
- 2x capacity headroom

**Security:** 97/100 OWASP Top 10
- 0 critical vulnerabilities
- TLS 1.2+ enforced
- Secrets in Azure Key Vault
- Regular security audits

## Deployment

### Azure Infrastructure

Deploy using Bicep templates:

```powershell
cd infrastructure/azure
./deploy.ps1 -Environment dev -Location eastus
```

Environments: `dev`, `staging`, `prod`

### CI/CD Pipeline

GitHub Actions workflow:
1. Test suite (99% coverage threshold)
2. Security scanning (Safety + Bandit)
3. Code quality checks (Black, isort)
4. Docker build → GitHub Container Registry
5. Deploy to Azure App Service

See [docs/DEPLOYMENT.md](./docs/DEPLOYMENT.md) for complete guide.

## Integration

### Service Registration

Register in eva-orchestrator:

```yaml
services:
  eva-auth:
    endpoints:
      prod: https://eva-auth.azurewebsites.net
    health: /health
    capabilities:
      - oauth2-authentication
      - jwt-validation
      - rbac
```

See [docs/INTEGRATION.md](./docs/INTEGRATION.md) for integration patterns.

## Phase Completion

✅ **Phase 1: Foundation** (84 tests, 84.04%)
- OAuth providers (Azure B2C, Entra ID)
- JWT validators (RS256, HS256)
- Session management
- Authentication middleware

✅ **Phase 2: Data Layer** (138 tests, 88.70%)
- Cosmos DB audit logger
- API key manager
- RBAC engine

✅ **Phase 3: Integration** (153 tests)
- Integration tests
- Load testing (Grade A)
- Security testing (97/100)

✅ **Phase 4: Coverage** (202 tests, 99.61%)
- Enhanced test coverage
- Edge case validation
- Exception handling

✅ **Phase 5: Deployment**
- Azure infrastructure (Bicep)
- CI/CD pipeline (GitHub Actions)
- Comprehensive documentation
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

<!-- Phase 3 enforcement system test -->

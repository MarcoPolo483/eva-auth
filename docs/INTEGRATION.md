# EVA Auth - Service Integration Guide

Integration guide for eva-orchestrator and other EVA Suite services.

---

## Service Registration

### eva-orchestrator Registry Entry

Add to `eva-orchestrator/agents/registry.yaml`:

```yaml
services:
  eva-auth:
    name: eva-auth
    version: 1.0.0
    pod: POD-F
    owners:
      - P04-LIB
      - P15-DVM
    
    endpoints:
      dev: https://eva-auth-dev.azurewebsites.net
      staging: https://eva-auth-staging.azurewebsites.net
      prod: https://eva-auth.azurewebsites.net
    
    health:
      path: /health
      method: GET
      interval: 30s
      timeout: 5s
      retries: 3
    
    readiness:
      path: /health/ready
      method: GET
      interval: 10s
      timeout: 3s
    
    capabilities:
      - oauth2-authentication
      - jwt-validation
      - session-management
      - rbac
      - api-key-management
      - audit-logging
    
    dependencies:
      - azure-ad-b2c
      - microsoft-entra-id
      - azure-cosmos-db
      - azure-redis-cache
      - azure-key-vault
    
    metrics:
      coverage: 99.61%
      tests: 202
      performance:
        rps: 194.8
        p95_latency_ms: 25
        p99_latency_ms: 48
      security_score: 97
    
    authentication:
      type: bearer
      scheme: JWT
      issuer: https://eva-auth.azurewebsites.net
      audience: eva-suite
    
    repository: https://github.com/MarcoPolo483/eva-auth
    documentation: https://eva-auth.azurewebsites.net/docs
    ci_cd: https://github.com/MarcoPolo483/eva-auth/actions
```

---

## Authentication Integration

### For EVA Suite Services

#### 1. Install Client Library (Python)

```python
# pyproject.toml
[tool.poetry.dependencies]
httpx = "^0.25.0"
pyjwt = "^2.8.0"
cryptography = "^41.0.0"
```

#### 2. EVA Auth Client

```python
# eva_client/auth.py
import httpx
import jwt
from typing import Optional
from datetime import datetime, timedelta

class EVAAuthClient:
    """Client for EVA Auth service integration."""
    
    def __init__(self, base_url: str, client_id: str, client_secret: str):
        self.base_url = base_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.client = httpx.AsyncClient(base_url=base_url)
    
    async def validate_token(self, token: str) -> dict:
        """Validate JWT token with EVA Auth."""
        response = await self.client.post(
            "/auth/validate",
            json={"token": token}
        )
        response.raise_for_status()
        return response.json()
    
    async def get_session(self, session_id: str) -> dict:
        """Retrieve session information."""
        response = await self.client.get(
            f"/sessions/{session_id}",
            headers={"Authorization": f"Bearer {self._get_service_token()}"}
        )
        response.raise_for_status()
        return response.json()
    
    async def check_permission(
        self,
        user_token: str,
        permission: str
    ) -> bool:
        """Check if user has specific permission."""
        response = await self.client.post(
            "/rbac/check-permission",
            json={"permission": permission},
            headers={"Authorization": f"Bearer {user_token}"}
        )
        return response.status_code == 200
    
    def _get_service_token(self) -> str:
        """Generate service-to-service JWT token."""
        payload = {
            "sub": self.client_id,
            "iss": "eva-service",
            "aud": "eva-auth",
            "exp": datetime.utcnow() + timedelta(minutes=5)
        }
        return jwt.encode(payload, self.client_secret, algorithm="HS256")
```

#### 3. FastAPI Middleware Integration

```python
# middleware/auth.py
from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware

class EVAAuthMiddleware(BaseHTTPMiddleware):
    """Middleware for EVA Auth integration."""
    
    def __init__(self, app, auth_client: EVAAuthClient, public_paths: list[str]):
        super().__init__(app)
        self.auth_client = auth_client
        self.public_paths = public_paths
    
    async def dispatch(self, request: Request, call_next):
        # Skip public paths
        if request.url.path in self.public_paths:
            return await call_next(request)
        
        # Extract token
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Missing authentication")
        
        token = auth_header[7:]
        
        # Validate with EVA Auth
        try:
            claims = await self.auth_client.validate_token(token)
            request.state.user = claims
        except Exception as e:
            raise HTTPException(status_code=401, detail=f"Invalid token: {e}")
        
        return await call_next(request)
```

#### 4. Application Setup

```python
# main.py
from fastapi import FastAPI
from eva_client.auth import EVAAuthClient
from middleware.auth import EVAAuthMiddleware

app = FastAPI()

# Initialize auth client
auth_client = EVAAuthClient(
    base_url="https://eva-auth.azurewebsites.net",
    client_id=settings.service_client_id,
    client_secret=settings.service_client_secret
)

# Add middleware
app.add_middleware(
    EVAAuthMiddleware,
    auth_client=auth_client,
    public_paths=["/health", "/docs", "/openapi.json"]
)

@app.get("/protected")
async def protected_endpoint(request: Request):
    """Example protected endpoint."""
    user = request.state.user
    return {
        "message": "Access granted",
        "user_id": user["sub"],
        "email": user["email"],
        "roles": user["roles"]
    }
```

---

## Service-to-Service Authentication

### API Key Method (Recommended for Backend Services)

#### 1. Generate API Key

```bash
# Using EVA Auth API
curl -X POST https://eva-auth.azurewebsites.net/api-keys \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "eva-orchestrator-service",
    "tenant_id": "eva-suite",
    "permissions": ["read:sessions", "write:audit"],
    "expires_in_days": 365
  }'
```

#### 2. Use API Key

```python
# In your service
import httpx

async def call_eva_auth(api_key: str):
    async with httpx.AsyncClient() as client:
        response = await client.get(
            "https://eva-auth.azurewebsites.net/sessions",
            headers={"X-API-Key": api_key}
        )
        return response.json()
```

---

## Health Check Integration

### Monitoring Configuration

Add to eva-orchestrator health checks:

```yaml
# eva-orchestrator/monitoring/health-checks.yml
services:
  - name: eva-auth
    url: https://eva-auth.azurewebsites.net/health
    interval: 30s
    timeout: 5s
    method: GET
    expected_status: 200
    alerts:
      - type: slack
        channel: "#eva-alerts"
      - type: email
        recipients: ["ops@eva.com"]
    
  - name: eva-auth-readiness
    url: https://eva-auth.azurewebsites.net/health/ready
    interval: 10s
    timeout: 3s
    method: GET
    expected_status: 200
    dependencies:
      - redis
      - cosmos-db
```

### Prometheus Metrics Endpoint

EVA Auth exposes metrics at `/metrics` (future enhancement):

```yaml
# Prometheus scrape config
scrape_configs:
  - job_name: 'eva-auth'
    scrape_interval: 15s
    static_configs:
      - targets: ['eva-auth.azurewebsites.net:443']
    metrics_path: '/metrics'
    scheme: https
```

---

## Event Integration

### Audit Events

EVA Auth emits audit events to Cosmos DB that can be consumed by other services:

```python
# Subscribe to audit events (future enhancement)
from azure.cosmos import CosmosClient

cosmos_client = CosmosClient(endpoint, key)
container = cosmos_client.get_database_client("eva-auth").get_container_client("audit-logs")

# Query recent authentication events
query = """
    SELECT * FROM c
    WHERE c.event_type = 'authentication'
    AND c.timestamp >= @since
    ORDER BY c.timestamp DESC
"""

items = container.query_items(
    query=query,
    parameters=[{"name": "@since", "value": "2025-12-07T00:00:00Z"}],
    enable_cross_partition_query=True
)

for event in items:
    print(f"User {event['user_id']} authenticated at {event['timestamp']}")
```

---

## Cross-Origin Configuration

### CORS Setup for Frontend Integration

EVA Auth CORS is configured per environment:

```python
# Development
CORS_ORIGINS = ["*"]

# Staging
CORS_ORIGINS = [
    "https://eva-staging.azurewebsites.net",
    "https://staging.eva.com"
]

# Production
CORS_ORIGINS = [
    "https://eva.azurewebsites.net",
    "https://eva.com",
    "https://www.eva.com"
]
```

---

## Testing Integration

### Integration Test Example

```python
# tests/integration/test_eva_auth_integration.py
import pytest
import httpx

@pytest.mark.integration
async def test_authenticate_and_access():
    """Test full authentication flow with EVA Auth."""
    
    # Step 1: Start OAuth flow
    async with httpx.AsyncClient() as client:
        # Get authorization URL
        response = await client.get(
            "https://eva-auth-dev.azurewebsites.net/auth/b2c/authorize",
            params={"redirect_uri": "https://myapp.com/callback"}
        )
        assert response.status_code == 200
        auth_data = response.json()
        
        # Step 2: Simulate callback (in real scenario, user authenticates)
        # This would come from Azure AD B2C
        mock_code = "mock_auth_code_12345"
        
        # Exchange code for tokens
        response = await client.get(
            "https://eva-auth-dev.azurewebsites.net/auth/b2c/callback",
            params={"code": mock_code, "state": auth_data["state"]}
        )
        assert response.status_code == 200
        tokens = response.json()
        
        # Step 3: Use access token
        response = await client.get(
            "https://myapp.com/api/protected",
            headers={"Authorization": f"Bearer {tokens['access_token']}"}
        )
        assert response.status_code == 200
```

---

## Troubleshooting

### Common Integration Issues

#### 1. Token Validation Fails

**Symptom:** 401 Unauthorized errors

**Solutions:**
- Verify token hasn't expired
- Check token issuer matches EVA Auth endpoint
- Ensure audience claim is correct
- Validate signing algorithm (RS256 for production, HS256 for mock)

```python
# Debug token
import jwt
claims = jwt.decode(token, options={"verify_signature": False})
print(f"Issuer: {claims.get('iss')}")
print(f"Audience: {claims.get('aud')}")
print(f"Expires: {claims.get('exp')}")
```

#### 2. CORS Errors

**Symptom:** Browser blocks requests

**Solutions:**
- Check origin is in CORS allowlist
- Verify preflight OPTIONS requests succeed
- Ensure credentials mode matches CORS policy

#### 3. Session Not Found

**Symptom:** Session lookups return 404

**Solutions:**
- Verify Redis connection is healthy
- Check session hasn't expired (default TTL: 24h)
- Ensure session_id is correct format

---

## Security Best Practices

### 1. Token Storage

**Frontend (Browser):**
- Store access tokens in memory (JavaScript variable)
- Store refresh tokens in httpOnly cookies
- Never store tokens in localStorage (XSS risk)

**Backend:**
- Store service tokens in Azure Key Vault
- Rotate tokens regularly (recommended: 90 days)
- Use managed identities when possible

### 2. Token Validation

**Always validate:**
- Signature (using JWKS)
- Expiration (exp claim)
- Issuer (iss claim)
- Audience (aud claim)
- Not before (nbf claim if present)

### 3. Rate Limiting

EVA Auth implements rate limiting:
- 100 requests/minute per IP for authentication endpoints
- 1000 requests/minute per API key for service endpoints

**Handle rate limits:**
```python
from tenacity import retry, wait_exponential, stop_after_attempt

@retry(
    wait=wait_exponential(multiplier=1, min=2, max=10),
    stop=stop_after_attempt(3)
)
async def call_eva_auth_with_retry():
    response = await client.get("...")
    if response.status_code == 429:
        raise Exception("Rate limited")
    return response.json()
```

---

## Migration Guide

### From Legacy Auth System

#### Phase 1: Dual Authentication (2 weeks)
- Deploy EVA Auth alongside legacy system
- Configure both auth methods in services
- Monitor and compare behavior

#### Phase 2: Gradual Migration (4 weeks)
- Migrate dev environment first
- Migrate staging after 1 week stability
- Test all authentication flows

#### Phase 3: Legacy Deprecation (2 weeks)
- Disable legacy auth in dev/staging
- Monitor for issues
- Final production cutover

#### Phase 4: Cleanup (1 week)
- Remove legacy auth code
- Update documentation
- Archive legacy infrastructure

---

## Support & Contact

**Technical Support:**
- GitHub Issues: https://github.com/MarcoPolo483/eva-auth/issues
- Email: marco.presta@eva.com

**Documentation:**
- API Docs: https://eva-auth.azurewebsites.net/docs
- Deployment: [DEPLOYMENT.md](./DEPLOYMENT.md)
- Security: [SECURITY-CHECKLIST.md](./SECURITY-CHECKLIST.md)

**SLA:**
- Response Time: 1 hour (business hours)
- Resolution Time: 4 hours (critical), 24 hours (normal)
- Uptime Target: 99.9%

---

## Appendix: Service Topology

```
┌─────────────────────────────────────────────────────────────┐
│                         EVA Suite                            │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐      ┌──────────────┐                    │
│  │  Frontend    │─────▶│  EVA Auth    │                    │
│  │  (React/Vue) │      │  (POD-F)     │                    │
│  └──────────────┘      └──────┬───────┘                    │
│         │                      │                             │
│         │                      │ JWT Validation              │
│         │                      │                             │
│  ┌──────▼──────────────────────▼───────┐                   │
│  │     EVA Orchestrator                 │                   │
│  │     (Control Plane)                  │                   │
│  └──────┬───────────────────────────────┘                   │
│         │                                                    │
│         │ Authenticated Requests                            │
│         │                                                    │
│  ┌──────▼───────┐  ┌──────────┐  ┌──────────┐             │
│  │  EVA Service │  │  EVA     │  │  EVA     │             │
│  │  A (POD-X)   │  │  Service │  │  Service │             │
│  │              │  │  B       │  │  C       │             │
│  └──────────────┘  └──────────┘  └──────────┘             │
│                                                              │
└─────────────────────────────────────────────────────────────┘

External Dependencies:
  - Azure AD B2C (Citizen Auth)
  - Microsoft Entra ID (Employee Auth)
  - Azure Cosmos DB (Audit Logs)
  - Azure Redis Cache (Sessions)
  - Azure Key Vault (Secrets)
```

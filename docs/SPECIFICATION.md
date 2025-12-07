# EVA Authentication & Authorization Service (eva-auth)

**Comprehensive Specification for Autonomous Implementation**

---

## 1. Vision & Business Value

### What This Service Delivers

EVA-Auth is the **identity and access control foundation** for the entire EVA Suite. It provides:

- **Dual Authentication Channels**: Azure AD B2C for citizens, Microsoft Entra ID for employees
- **Zero-Trust Architecture**: Every request validated, tenant isolation enforced, audit trail complete
- **Seamless Integration**: Drop-in middleware for FastAPI/Express, SDK for all services
- **Developer Experience**: Test tokens, mock providers, clear error messages, bilingual support

### Success Metrics

- **Security**: Zero authentication bypasses, 100% token validation, complete audit trail
- **Performance**: Token validation < 50ms (p95), session management < 100ms (p95)
- **Reliability**: 99.95% uptime (authentication is critical path for all services)
- **Developer Experience**: < 5 min integration time, test tokens generated in < 1 second

### Business Impact

- **Compliance**: Protected B security, PBMM-compliant authentication, audit trail for ATIP
- **Multi-Tenancy**: 500+ organizations isolated, tenant boundary enforcement, cross-tenant blocked
- **Enterprise SSO**: Microsoft Entra ID for 50,000+ employees, seamless login experience
- **Citizen Access**: Azure AD B2C for 1M+ citizens, accessible authentication flows

---

## 2. Architecture Overview

### System Context

```
┌─────────────────────────────────────────────────────────────────────┐
│                         EVA Suite Services                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐           │
│  │ eva-api  │  │ eva-core │  │ eva-rag  │  │ eva-ui   │  ...       │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘           │
│       │             │             │             │                   │
│       └─────────────┴─────────────┴─────────────┘                   │
│                           │                                         │
│                           ▼                                         │
│       ┌───────────────────────────────────────────┐                │
│       │         eva-auth (This Service)           │                │
│       │  Token Validation │ RBAC │ Session Mgmt  │                │
│       └───────────┬───────────────────────────────┘                │
│                   │                                                 │
└───────────────────┼─────────────────────────────────────────────────┘
                    │
        ┌───────────┴───────────┐
        ▼                       ▼
┌────────────────┐     ┌────────────────────┐
│  Azure AD B2C  │     │ Microsoft Entra ID │
│   (Citizens)   │     │    (Employees)     │
└────────────────┘     └────────────────────┘
```

### Component Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                          eva-auth Service                           │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                     API Layer (FastAPI)                       │  │
│  │  POST /auth/token   │ POST /auth/refresh │ POST /auth/logout │  │
│  └────────────────────────┬─────────────────────────────────────┘  │
│                           │                                         │
│  ┌────────────────────────▼─────────────────────────────────────┐  │
│  │                   Authentication Core                         │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       │  │
│  │  │ JWT Validator│  │ RBAC Engine  │  │ Session Mgr  │       │  │
│  │  │ (RS256/HS256)│  │ (Claims→Roles)│  │ (Redis Cache)│       │  │
│  │  └──────────────┘  └──────────────┘  └──────────────┘       │  │
│  └────────────────────────┬─────────────────────────────────────┘  │
│                           │                                         │
│  ┌────────────────────────▼─────────────────────────────────────┐  │
│  │                   Identity Providers                          │  │
│  │  ┌──────────────────────┐  ┌──────────────────────┐          │  │
│  │  │   Azure AD B2C       │  │ Microsoft Entra ID   │          │  │
│  │  │  (OAuth 2.0 / OIDC)  │  │  (OAuth 2.0 / OIDC)  │          │  │
│  │  └──────────────────────┘  └──────────────────────┘          │  │
│  └────────────────────────┬─────────────────────────────────────┘  │
│                           │                                         │
│  ┌────────────────────────▼─────────────────────────────────────┐  │
│  │                     Storage Layer                             │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       │  │
│  │  │ Azure Key    │  │ Redis Cache  │  │ Cosmos DB    │       │  │
│  │  │ Vault (Keys) │  │ (Sessions)   │  │ (Audit Logs) │       │  │
│  │  └──────────────┘  └──────────────┘  └──────────────┘       │  │
│  └──────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 3. Technical Stack

### Primary Technologies

- **Framework**: FastAPI 0.110+ (Python 3.11+, async/await, Pydantic v2)
- **Authentication**: 
  - Azure Identity SDK (`azure-identity` 1.15+)
  - PyJWT 2.8+ (JWT encoding/decoding)
  - Authlib 1.3+ (OAuth 2.0 flows)
- **Cryptography**: `cryptography` 41.0+ (token encryption, key management)
- **Storage**: 
  - Azure Key Vault (signing keys, client secrets)
  - Redis 7.2+ (session cache, token blacklist)
  - Azure Cosmos DB (audit logs, user sessions)
- **Testing**: pytest + pytest-asyncio + pytest-mock + fakeredis
- **Observability**: OpenTelemetry, Azure Monitor, structlog

### Authentication Protocols

- **OAuth 2.0**: Authorization Code Flow (with PKCE), Client Credentials Flow (M2M)
- **OpenID Connect (OIDC)**: ID tokens, UserInfo endpoint, discovery
- **JWT**: RS256 (production), HS256 (development), claims validation
- **Token Types**: Access tokens (1 hour), Refresh tokens (30 days), ID tokens (1 hour)

### Security Standards

- **Encryption**: TLS 1.3 (in transit), AES-256 (at rest), Fernet (token encryption)
- **Key Management**: Azure Key Vault (automatic rotation), separate keys per environment
- **Password Hashing**: bcrypt (cost factor 12) for API keys, N/A for SSO users
- **Rate Limiting**: Token bucket (20 auth attempts per IP per minute)

---

## 4. Core Capabilities

### 4.1 Azure AD B2C Authentication (Citizens)

**Purpose**: Enable citizens to authenticate with government-issued credentials or social logins.

**OAuth 2.0 Flow**:
```
1. User → EVA UI: Click "Sign In"
2. EVA UI → eva-auth: GET /auth/b2c/authorize
3. eva-auth → User: Redirect to Azure AD B2C login page
4. User → Azure AD B2C: Enter credentials (or use social login)
5. Azure AD B2C → eva-auth: Redirect with authorization code
6. eva-auth → Azure AD B2C: POST /token (exchange code for tokens)
7. Azure AD B2C → eva-auth: Return access_token + id_token + refresh_token
8. eva-auth → EVA UI: Set HTTP-only cookie with session ID
9. eva-auth → Redis: Store session (user_id, tenant_id, roles, expires_at)
10. eva-auth → Cosmos DB: Log authentication event (timestamp, IP, user_agent)
```

**Key Configuration**:
- **Tenant**: `your-tenant.b2clogin.com`
- **User Flow**: `B2C_1_signin` (sign-in/sign-up combined)
- **Scopes**: `openid`, `profile`, `email`, `offline_access`
- **Claims**: `sub`, `email`, `given_name`, `family_name`, `tid` (tenant ID)
- **Token Lifetime**: Access token (1 hour), Refresh token (30 days)

**Implementation**:
```python
# src/eva_auth/providers/azure_ad_b2c.py
from authlib.integrations.httpx_client import AsyncOAuth2Client
from eva_auth.models import AuthSession, UserClaims

class AzureADB2CProvider:
    def __init__(self, tenant_id: str, client_id: str, client_secret: str):
        self.authority = f"https://{tenant_id}.b2clogin.com/{tenant_id}/B2C_1_signin"
        self.client = AsyncOAuth2Client(
            client_id=client_id,
            client_secret=client_secret,
            token_endpoint=f"{self.authority}/oauth2/v2.0/token",
            authorization_endpoint=f"{self.authority}/oauth2/v2.0/authorize",
        )
    
    async def get_authorization_url(self, redirect_uri: str, state: str) -> str:
        url, _ = await self.client.create_authorization_url(
            self.client.authorization_endpoint,
            redirect_uri=redirect_uri,
            scope="openid profile email offline_access",
            state=state,
        )
        return url
    
    async def exchange_code_for_tokens(
        self, code: str, redirect_uri: str
    ) -> dict[str, str]:
        token = await self.client.fetch_token(
            self.client.token_endpoint,
            grant_type="authorization_code",
            code=code,
            redirect_uri=redirect_uri,
        )
        return token
    
    async def validate_id_token(self, id_token: str) -> UserClaims:
        # Fetch JWKS from Azure AD B2C
        jwks = await self._fetch_jwks()
        
        # Verify signature and claims
        claims = jwt.decode(
            id_token,
            jwks,
            algorithms=["RS256"],
            audience=self.client.client_id,
            issuer=self.authority,
        )
        
        return UserClaims(
            sub=claims["sub"],
            email=claims.get("email"),
            given_name=claims.get("given_name"),
            family_name=claims.get("family_name"),
            tenant_id=claims["tid"],
        )
```

**API Endpoints**:
- `GET /auth/b2c/authorize` - Start OAuth flow (redirect to B2C login)
- `GET /auth/b2c/callback` - Handle OAuth callback (exchange code for tokens)
- `POST /auth/b2c/refresh` - Refresh access token (using refresh token)
- `POST /auth/b2c/logout` - End user session (revoke tokens, clear cookies)

---

### 4.2 Microsoft Entra ID Authentication (Employees)

**Purpose**: Enable government employees to authenticate with their organization accounts (SSO).

**OAuth 2.0 Flow**:
```
1. User → EVA UI: Click "Sign In with Microsoft"
2. EVA UI → eva-auth: GET /auth/entra/authorize
3. eva-auth → User: Redirect to Microsoft Entra ID login page
4. User → Entra ID: Enter work email (SSO to organization IdP)
5. Entra ID → eva-auth: Redirect with authorization code
6. eva-auth → Entra ID: POST /token (exchange code for tokens)
7. Entra ID → eva-auth: Return access_token + id_token + refresh_token
8. eva-auth → EVA UI: Set HTTP-only cookie with session ID
9. eva-auth → Redis: Store session (user_id, tenant_id, roles, groups, expires_at)
10. eva-auth → Cosmos DB: Log authentication event (timestamp, IP, user_agent, organization)
```

**Key Configuration**:
- **Tenant**: `your-tenant.onmicrosoft.com` or custom domain
- **Authority**: `https://login.microsoftonline.com/{tenant_id}`
- **Scopes**: `openid`, `profile`, `email`, `User.Read`, `offline_access`
- **Claims**: `sub`, `email`, `name`, `oid` (object ID), `tid` (tenant ID), `roles`, `groups`
- **Token Lifetime**: Access token (1 hour), Refresh token (90 days for employees)

**Group/Role Mapping**:
```yaml
# Entra ID groups → EVA roles
entra_groups:
  "EVA-Admins": ["eva:admin", "eva:user"]
  "EVA-Analysts": ["eva:analyst", "eva:user"]
  "EVA-Viewers": ["eva:viewer", "eva:user"]

# Entra ID app roles → EVA permissions
app_roles:
  "eva.admin": ["spaces:write", "documents:write", "users:manage", "audit:read"]
  "eva.analyst": ["spaces:read", "documents:write", "queries:execute"]
  "eva.viewer": ["spaces:read", "documents:read", "queries:execute"]
```

**Implementation**:
```python
# src/eva_auth/providers/microsoft_entra_id.py
from authlib.integrations.httpx_client import AsyncOAuth2Client
from eva_auth.models import AuthSession, UserClaims

class MicrosoftEntraIDProvider:
    def __init__(self, tenant_id: str, client_id: str, client_secret: str):
        self.authority = f"https://login.microsoftonline.com/{tenant_id}"
        self.client = AsyncOAuth2Client(
            client_id=client_id,
            client_secret=client_secret,
            token_endpoint=f"{self.authority}/oauth2/v2.0/token",
            authorization_endpoint=f"{self.authority}/oauth2/v2.0/authorize",
        )
    
    async def get_authorization_url(self, redirect_uri: str, state: str) -> str:
        url, _ = await self.client.create_authorization_url(
            self.client.authorization_endpoint,
            redirect_uri=redirect_uri,
            scope="openid profile email User.Read offline_access",
            state=state,
        )
        return url
    
    async def exchange_code_for_tokens(
        self, code: str, redirect_uri: str
    ) -> dict[str, str]:
        token = await self.client.fetch_token(
            self.client.token_endpoint,
            grant_type="authorization_code",
            code=code,
            redirect_uri=redirect_uri,
        )
        return token
    
    async def get_user_groups(self, access_token: str) -> list[str]:
        # Call Microsoft Graph API to get user groups
        url = "https://graph.microsoft.com/v1.0/me/memberOf"
        headers = {"Authorization": f"Bearer {access_token}"}
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers)
            response.raise_for_status()
            data = response.json()
            return [group["displayName"] for group in data.get("value", [])]
    
    def map_groups_to_roles(self, groups: list[str]) -> list[str]:
        # Map Entra ID groups to EVA roles
        role_mapping = {
            "EVA-Admins": ["eva:admin", "eva:user"],
            "EVA-Analysts": ["eva:analyst", "eva:user"],
            "EVA-Viewers": ["eva:viewer", "eva:user"],
        }
        
        roles = set()
        for group in groups:
            if group in role_mapping:
                roles.update(role_mapping[group])
        
        return list(roles) if roles else ["eva:user"]  # Default role
```

**API Endpoints**:
- `GET /auth/entra/authorize` - Start OAuth flow (redirect to Entra ID login)
- `GET /auth/entra/callback` - Handle OAuth callback (exchange code for tokens)
- `POST /auth/entra/refresh` - Refresh access token (using refresh token)
- `POST /auth/entra/logout` - End user session (revoke tokens, clear cookies)

---

### 4.3 JWT Token Validation & RBAC

**Purpose**: Validate JWT tokens from Azure AD B2C/Entra ID, extract claims, enforce role-based access control.

**JWT Structure**:
```json
{
  "header": {
    "alg": "RS256",
    "typ": "JWT",
    "kid": "abc123..."
  },
  "payload": {
    "sub": "user-uuid-1234",
    "email": "john.doe@example.com",
    "name": "John Doe",
    "tid": "tenant-uuid-5678",
    "roles": ["eva:analyst", "eva:user"],
    "groups": ["EVA-Analysts"],
    "iss": "https://login.microsoftonline.com/{tenant_id}/v2.0",
    "aud": "{client_id}",
    "exp": 1735776000,
    "iat": 1735772400,
    "nbf": 1735772400
  },
  "signature": "..."
}
```

**Validation Steps**:
1. **Fetch JWKS**: Get public keys from `{authority}/.well-known/jwks.json`
2. **Verify Signature**: Use RS256 algorithm with public key matching `kid`
3. **Verify Issuer**: Ensure `iss` matches Azure AD B2C/Entra ID authority
4. **Verify Audience**: Ensure `aud` matches client ID
5. **Verify Expiration**: Ensure `exp` > current time
6. **Verify Not Before**: Ensure `nbf` <= current time
7. **Extract Claims**: Parse `sub`, `email`, `name`, `tid`, `roles`, `groups`
8. **Tenant Isolation**: Ensure user can only access resources in their tenant

**Implementation**:
```python
# src/eva_auth/validators/jwt_validator.py
import jwt
from jwt import PyJWKClient
from eva_auth.models import JWTClaims, ValidationError

class JWTValidator:
    def __init__(self, jwks_uri: str, issuer: str, audience: str):
        self.jwks_client = PyJWKClient(jwks_uri)
        self.issuer = issuer
        self.audience = audience
    
    async def validate_token(self, token: str) -> JWTClaims:
        try:
            # Get signing key from JWKS
            signing_key = self.jwks_client.get_signing_key_from_jwt(token)
            
            # Decode and validate token
            payload = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                issuer=self.issuer,
                audience=self.audience,
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_iat": True,
                    "verify_aud": True,
                    "verify_iss": True,
                },
            )
            
            return JWTClaims(
                sub=payload["sub"],
                email=payload.get("email"),
                name=payload.get("name"),
                tenant_id=payload["tid"],
                roles=payload.get("roles", ["eva:user"]),
                groups=payload.get("groups", []),
                expires_at=payload["exp"],
            )
        except jwt.ExpiredSignatureError:
            raise ValidationError("Token has expired", error_code="TOKEN_EXPIRED")
        except jwt.InvalidAudienceError:
            raise ValidationError("Invalid audience", error_code="INVALID_AUDIENCE")
        except jwt.InvalidIssuerError:
            raise ValidationError("Invalid issuer", error_code="INVALID_ISSUER")
        except jwt.InvalidTokenError as e:
            raise ValidationError(f"Invalid token: {e}", error_code="INVALID_TOKEN")
```

**RBAC Engine**:
```python
# src/eva_auth/rbac/rbac_engine.py
from eva_auth.models import JWTClaims, RBACPolicy

class RBACEngine:
    def __init__(self):
        self.policies = self._load_policies()
    
    def _load_policies(self) -> dict[str, RBACPolicy]:
        return {
            "eva:admin": RBACPolicy(
                role="eva:admin",
                permissions=[
                    "spaces:read", "spaces:write", "spaces:delete",
                    "documents:read", "documents:write", "documents:delete",
                    "queries:execute", "users:manage", "audit:read",
                ],
            ),
            "eva:analyst": RBACPolicy(
                role="eva:analyst",
                permissions=[
                    "spaces:read", "spaces:write",
                    "documents:read", "documents:write",
                    "queries:execute",
                ],
            ),
            "eva:viewer": RBACPolicy(
                role="eva:viewer",
                permissions=["spaces:read", "documents:read", "queries:execute"],
            ),
        }
    
    def has_permission(self, claims: JWTClaims, permission: str) -> bool:
        """Check if user has specific permission."""
        for role in claims.roles:
            policy = self.policies.get(role)
            if policy and permission in policy.permissions:
                return True
        return False
    
    def enforce_tenant_isolation(self, claims: JWTClaims, resource_tenant_id: str):
        """Ensure user can only access resources in their tenant."""
        if claims.tenant_id != resource_tenant_id:
            raise PermissionError(
                f"User from tenant {claims.tenant_id} cannot access "
                f"resource from tenant {resource_tenant_id}"
            )
```

**FastAPI Middleware**:
```python
# src/eva_auth/middleware/auth_middleware.py
from fastapi import Request, HTTPException, status
from eva_auth.validators import JWTValidator
from eva_auth.rbac import RBACEngine

async def auth_middleware(request: Request, call_next):
    # Skip authentication for public endpoints
    if request.url.path in ["/health", "/docs", "/openapi.json"]:
        return await call_next(request)
    
    # Extract Bearer token from Authorization header
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid Authorization header",
        )
    
    token = auth_header[7:]  # Remove "Bearer " prefix
    
    # Validate JWT token
    validator = JWTValidator(...)
    try:
        claims = await validator.validate_token(token)
        request.state.user = claims
    except ValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
        )
    
    # Continue to next middleware/route handler
    response = await call_next(request)
    return response
```

**Permission Decorator**:
```python
# src/eva_auth/decorators/require_permission.py
from functools import wraps
from fastapi import Request, HTTPException, status

def require_permission(permission: str):
    def decorator(func):
        @wraps(func)
        async def wrapper(request: Request, *args, **kwargs):
            claims = request.state.user
            rbac_engine = RBACEngine()
            
            if not rbac_engine.has_permission(claims, permission):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Missing required permission: {permission}",
                )
            
            return await func(request, *args, **kwargs)
        return wrapper
    return decorator

# Usage in route handler
@router.delete("/spaces/{space_id}")
@require_permission("spaces:delete")
async def delete_space(request: Request, space_id: str):
    claims = request.state.user
    # Delete space logic...
    return {"message": "Space deleted"}
```

---

### 4.4 Session Management (Redis)

**Purpose**: Maintain user sessions, support logout, prevent token replay attacks.

**Session Storage**:
```python
# src/eva_auth/session/session_manager.py
import redis.asyncio as redis
from eva_auth.models import AuthSession
import json
from datetime import timedelta

class SessionManager:
    def __init__(self, redis_client: redis.Redis):
        self.redis = redis_client
    
    async def create_session(
        self, session_id: str, claims: JWTClaims, expires_in: int = 3600
    ):
        """Store session in Redis with expiration."""
        session_data = {
            "user_id": claims.sub,
            "email": claims.email,
            "tenant_id": claims.tenant_id,
            "roles": claims.roles,
            "groups": claims.groups,
            "created_at": datetime.utcnow().isoformat(),
        }
        
        await self.redis.setex(
            f"session:{session_id}",
            timedelta(seconds=expires_in),
            json.dumps(session_data),
        )
    
    async def get_session(self, session_id: str) -> AuthSession | None:
        """Retrieve session from Redis."""
        data = await self.redis.get(f"session:{session_id}")
        if not data:
            return None
        
        return AuthSession(**json.loads(data))
    
    async def delete_session(self, session_id: str):
        """Delete session from Redis (logout)."""
        await self.redis.delete(f"session:{session_id}")
    
    async def blacklist_token(self, token: str, expires_in: int):
        """Add token to blacklist (prevent replay after logout)."""
        await self.redis.setex(
            f"blacklist:{token}",
            timedelta(seconds=expires_in),
            "1",
        )
    
    async def is_token_blacklisted(self, token: str) -> bool:
        """Check if token is blacklisted."""
        return await self.redis.exists(f"blacklist:{token}") > 0
```

**Session Cookie**:
```python
# Set HTTP-only cookie with session ID
response.set_cookie(
    key="eva_session_id",
    value=session_id,
    httponly=True,  # Prevent JavaScript access
    secure=True,    # HTTPS only
    samesite="strict",  # CSRF protection
    max_age=3600,   # 1 hour
)
```

---

### 4.5 API Key Authentication (M2M)

**Purpose**: Enable machine-to-machine authentication for API integrations.

**API Key Structure**:
```
sk_eva_live_abc123def456ghi789jkl012mno345pqr678stu901vwx234yz567
│  │    │    │
│  │    │    └─ Random 48-character string (base62)
│  │    └────── Environment (live, test, dev)
│  └─────────── Product identifier (eva)
└────────────── Prefix (sk = secret key)
```

**API Key Management**:
```python
# src/eva_auth/api_keys/api_key_manager.py
import secrets
import hashlib
from datetime import datetime, timedelta
from eva_auth.models import APIKey

class APIKeyManager:
    def __init__(self, cosmos_client):
        self.cosmos = cosmos_client
    
    def generate_api_key(
        self, 
        name: str,
        tenant_id: str,
        permissions: list[str],
        expires_in_days: int = 365,
    ) -> str:
        """Generate new API key."""
        # Generate random key
        random_part = secrets.token_urlsafe(36)
        api_key = f"sk_eva_live_{random_part}"
        
        # Hash for storage (bcrypt)
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        
        # Store in Cosmos DB
        api_key_doc = {
            "id": key_hash,
            "name": name,
            "tenant_id": tenant_id,
            "permissions": permissions,
            "key_prefix": api_key[:12],  # For identification
            "created_at": datetime.utcnow().isoformat(),
            "expires_at": (datetime.utcnow() + timedelta(days=expires_in_days)).isoformat(),
            "revoked": False,
        }
        self.cosmos.create_item(api_key_doc)
        
        return api_key  # Only returned once
    
    async def validate_api_key(self, api_key: str) -> APIKey | None:
        """Validate API key and return metadata."""
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        
        try:
            doc = self.cosmos.read_item(key_hash, partition_key=key_hash)
            
            # Check if revoked
            if doc["revoked"]:
                return None
            
            # Check expiration
            if datetime.fromisoformat(doc["expires_at"]) < datetime.utcnow():
                return None
            
            return APIKey(
                id=doc["id"],
                name=doc["name"],
                tenant_id=doc["tenant_id"],
                permissions=doc["permissions"],
                expires_at=doc["expires_at"],
            )
        except Exception:
            return None
    
    async def revoke_api_key(self, api_key: str):
        """Revoke API key."""
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        doc = self.cosmos.read_item(key_hash, partition_key=key_hash)
        doc["revoked"] = True
        self.cosmos.replace_item(key_hash, doc)
```

**Usage in Route Handler**:
```python
@router.get("/api/v1/spaces")
async def list_spaces(request: Request, api_key: str = Header(alias="X-API-Key")):
    # Validate API key
    api_key_manager = APIKeyManager(...)
    key_metadata = await api_key_manager.validate_api_key(api_key)
    
    if not key_metadata:
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    # Check permissions
    if "spaces:read" not in key_metadata.permissions:
        raise HTTPException(status_code=403, detail="Missing permission: spaces:read")
    
    # Proceed with request
    return {"spaces": [...]}
```

---

### 4.6 Audit Logging (Cosmos DB)

**Purpose**: Track all authentication events for security, compliance, and debugging.

**Audit Log Schema**:
```json
{
  "id": "uuid-1234",
  "timestamp": "2025-12-07T19:30:00Z",
  "event_type": "auth.login.success",
  "user_id": "user-uuid-5678",
  "tenant_id": "tenant-uuid-9012",
  "ip_address": "203.0.113.42",
  "user_agent": "Mozilla/5.0...",
  "auth_method": "entra_id",
  "session_id": "session-uuid-3456",
  "metadata": {
    "organization": "Department of Example",
    "roles": ["eva:analyst", "eva:user"],
    "groups": ["EVA-Analysts"]
  }
}
```

**Event Types**:
- `auth.login.success` - User successfully authenticated
- `auth.login.failure` - Authentication failed (wrong credentials, expired token)
- `auth.token.refreshed` - Access token refreshed
- `auth.logout.success` - User logged out
- `auth.apikey.created` - New API key created
- `auth.apikey.revoked` - API key revoked
- `auth.permission.denied` - User attempted action without permission

**Implementation**:
```python
# src/eva_auth/audit/audit_logger.py
from azure.cosmos import CosmosClient
from datetime import datetime
import uuid

class AuditLogger:
    def __init__(self, cosmos_client: CosmosClient, database: str, container: str):
        self.container = cosmos_client.get_database_client(database).get_container_client(container)
    
    async def log_event(
        self,
        event_type: str,
        user_id: str,
        tenant_id: str,
        ip_address: str,
        user_agent: str,
        metadata: dict | None = None,
    ):
        """Log authentication event to Cosmos DB."""
        log_entry = {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": event_type,
            "user_id": user_id,
            "tenant_id": tenant_id,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "metadata": metadata or {},
        }
        
        self.container.create_item(log_entry)
```

---

### 4.7 Test Utilities & Mock Providers

**Purpose**: Enable fast development and testing without Azure AD dependencies.

**Mock JWT Token Generator**:
```python
# src/eva_auth/testing/mock_auth.py
import jwt
from datetime import datetime, timedelta

class MockAuthProvider:
    def __init__(self, secret: str = "test-secret"):
        self.secret = secret
    
    def generate_token(
        self,
        user_id: str = "test-user-1234",
        email: str = "test@example.com",
        tenant_id: str = "test-tenant-5678",
        roles: list[str] = ["eva:user"],
        expires_in: int = 3600,
    ) -> str:
        """Generate mock JWT token for testing."""
        payload = {
            "sub": user_id,
            "email": email,
            "tid": tenant_id,
            "roles": roles,
            "iss": "https://mock.auth.eva.ai",
            "aud": "mock-client-id",
            "exp": datetime.utcnow() + timedelta(seconds=expires_in),
            "iat": datetime.utcnow(),
        }
        
        return jwt.encode(payload, self.secret, algorithm="HS256")
    
    async def validate_token(self, token: str) -> dict:
        """Validate mock token (for testing only)."""
        return jwt.decode(
            token,
            self.secret,
            algorithms=["HS256"],
            options={"verify_signature": True},
        )
```

**pytest Fixtures**:
```python
# tests/conftest.py
import pytest
from eva_auth.testing import MockAuthProvider

@pytest.fixture
def mock_auth():
    return MockAuthProvider()

@pytest.fixture
def test_token(mock_auth):
    return mock_auth.generate_token(
        user_id="test-user-1234",
        email="analyst@example.com",
        tenant_id="test-tenant-5678",
        roles=["eva:analyst", "eva:user"],
    )

@pytest.fixture
def admin_token(mock_auth):
    return mock_auth.generate_token(
        user_id="admin-user-5678",
        email="admin@example.com",
        tenant_id="test-tenant-5678",
        roles=["eva:admin", "eva:user"],
    )
```

---

## 5. API Endpoints

### Authentication Endpoints

#### POST /auth/b2c/authorize
**Purpose**: Start Azure AD B2C OAuth flow
**Response**: Redirect URL to B2C login page
```json
{
  "authorization_url": "https://tenant.b2clogin.com/tenant/B2C_1_signin/oauth2/v2.0/authorize?client_id=...&redirect_uri=...&state=...",
  "state": "random-state-token"
}
```

#### GET /auth/b2c/callback
**Purpose**: Handle OAuth callback from B2C
**Query Parameters**: `code`, `state`
**Response**: Session cookie set, redirect to application
```json
{
  "message": "Authentication successful",
  "user": {
    "id": "user-uuid-1234",
    "email": "john.doe@example.com",
    "name": "John Doe"
  }
}
```

#### POST /auth/b2c/refresh
**Purpose**: Refresh access token using refresh token
**Request Body**:
```json
{
  "refresh_token": "eyJ..."
}
```
**Response**:
```json
{
  "access_token": "eyJ...",
  "expires_in": 3600,
  "token_type": "Bearer"
}
```

#### POST /auth/b2c/logout
**Purpose**: End user session
**Response**: Session cookie cleared, tokens revoked
```json
{
  "message": "Logout successful"
}
```

### Token Validation Endpoints

#### POST /auth/validate
**Purpose**: Validate JWT token and return claims
**Request Headers**: `Authorization: Bearer {token}`
**Response**:
```json
{
  "valid": true,
  "claims": {
    "sub": "user-uuid-1234",
    "email": "john.doe@example.com",
    "tenant_id": "tenant-uuid-5678",
    "roles": ["eva:analyst", "eva:user"],
    "expires_at": 1735776000
  }
}
```

### API Key Endpoints

#### POST /auth/api-keys
**Purpose**: Generate new API key (admin only)
**Request Body**:
```json
{
  "name": "Production Integration",
  "tenant_id": "tenant-uuid-5678",
  "permissions": ["spaces:read", "documents:write", "queries:execute"],
  "expires_in_days": 365
}
```
**Response**:
```json
{
  "api_key": "sk_eva_live_abc123def456...",
  "name": "Production Integration",
  "expires_at": "2026-12-07T19:30:00Z",
  "warning": "Store this key securely. It will not be shown again."
}
```

#### GET /auth/api-keys
**Purpose**: List all API keys for tenant
**Response**:
```json
{
  "api_keys": [
    {
      "id": "key-hash-1234",
      "name": "Production Integration",
      "key_prefix": "sk_eva_live_",
      "permissions": ["spaces:read", "documents:write"],
      "created_at": "2025-12-07T19:30:00Z",
      "expires_at": "2026-12-07T19:30:00Z",
      "revoked": false
    }
  ]
}
```

#### DELETE /auth/api-keys/{key_id}
**Purpose**: Revoke API key
**Response**:
```json
{
  "message": "API key revoked successfully"
}
```

---

## 6. Quality Gates (All Must Pass)

### 1. Test Coverage: 100%
- **Tool**: pytest + Coverage.py
- **Command**: `pytest --cov=eva_auth --cov-report=html --cov-fail-under=100`
- **Target**: 100% line coverage, 100% branch coverage
- **Evidence**: Coverage report showing all modules at 100%

### 2. Security Validation
- **JWT Signature**: All tokens verified with RS256, JWKS fetched from Azure AD
- **Token Expiration**: Expired tokens rejected with `TOKEN_EXPIRED` error
- **Tenant Isolation**: Cross-tenant access blocked (user from tenant A cannot access tenant B resources)
- **Session Security**: HTTP-only cookies, SameSite=Strict, Secure flag enabled
- **API Key Security**: Keys hashed with SHA-256, stored in Cosmos DB, never logged
- **Evidence**: Security test suite passing (100% coverage of attack vectors)

### 3. Performance Benchmarks
- **Token Validation**: < 50ms (p95), < 100ms (p99)
- **Session Lookup**: < 100ms (p95), < 200ms (p99)
- **API Key Validation**: < 150ms (p95), < 300ms (p99)
- **JWKS Caching**: Public keys cached for 24 hours, refreshed on 401 errors
- **Evidence**: Locust load test report with 1000 concurrent users

### 4. API Contract Testing
- **OpenAPI Spec**: Complete specification for all endpoints (Swagger UI validated)
- **Request/Response Validation**: Pydantic models for all inputs/outputs
- **Error Responses**: Standardized error format (RFC 7807 Problem Details)
- **Evidence**: Schemathesis test report showing 100% endpoint coverage

### 5. Observability
- **OpenTelemetry Tracing**: 100% of auth operations traced (login, logout, token validation)
- **Structured Logging**: All events logged with context (user_id, tenant_id, IP, event_type)
- **Metrics**: Success rate, latency (p50/p95/p99), error rate by type
- **Alerts**: Token validation failures > 5%, session creation latency > 500ms
- **Evidence**: Jaeger traces, Azure Monitor logs, Grafana dashboards

### 6. Compliance & Audit
- **Audit Trail**: All authentication events logged to Cosmos DB (100% coverage)
- **ATIP Readiness**: Audit logs queryable by user_id, tenant_id, date range
- **Data Retention**: 7 years (Cosmos DB TTL policy)
- **Bilingual Errors**: EN-CA/FR-CA error messages for citizen-facing flows
- **Evidence**: Audit log query results, bilingual error test suite

### 7. Documentation
- **OpenAPI Specification**: Complete API documentation (Swagger UI)
- **Integration Guide**: Step-by-step instructions for eva-api, eva-core, eva-ui
- **Architecture Diagrams**: OAuth flows, system architecture, deployment
- **Runbook**: Common issues, troubleshooting, key rotation procedures
- **Evidence**: Published documentation site, internal review feedback

### 8. Reliability
- **Uptime**: 99.95% (authentication is critical path for all services)
- **Graceful Degradation**: Mock provider fallback for development/testing
- **Circuit Breaker**: Azure AD failures don't block local token validation
- **Retry Logic**: Token refresh retries 3 times with exponential backoff
- **Evidence**: Uptime monitoring report, chaos testing results

### 9. CI/CD Pipeline
- **Docker Build**: Multi-stage Dockerfile, image size < 200MB
- **Security Scan**: Trivy scan passing (no HIGH/CRITICAL vulnerabilities)
- **Linting**: ruff + mypy passing (type-safe code)
- **GitHub Actions**: All checks passing on pull requests
- **Evidence**: CI/CD workflow logs, Docker image scan report

### 10. Accessibility (Developer Portal)
- **WCAG 2.2 AA**: Login UI accessible (keyboard navigation, screen readers)
- **Color Contrast**: 4.5:1 minimum contrast ratio
- **ARIA Labels**: All form fields properly labeled
- **Evidence**: Lighthouse accessibility score > 95

### 11. Internationalization
- **Bilingual Errors**: EN-CA/FR-CA error messages
- **ISO 8601 Dates**: All timestamps in UTC with timezone
- **Currency**: N/A (authentication service)
- **Evidence**: i18n test suite passing (EN/FR coverage)

### 12. Developer Experience
- **Setup Time**: < 5 minutes (Docker Compose, sample .env)
- **Test Token Generation**: < 1 second (MockAuthProvider)
- **Error Messages**: Clear, actionable (e.g., "Token expired. Refresh with POST /auth/refresh")
- **SDK**: Python client library for easy integration
- **Evidence**: Developer feedback survey (5/5 satisfaction), SDK examples

---

## 7. Implementation Phases (6 Phases, 8 Weeks)

### Phase 1: Foundation (Week 1-2)
**Goal**: Core authentication infrastructure

**Tasks**:
1. Project setup: FastAPI app, pytest, Docker Compose, pre-commit hooks
2. Azure AD B2C integration: OAuth flow, token exchange, ID token validation
3. Microsoft Entra ID integration: OAuth flow, group/role mapping
4. JWT validator: RS256 signature verification, JWKS caching, claim extraction
5. Session manager: Redis integration, session CRUD, token blacklisting
6. Middleware: FastAPI auth middleware, Bearer token extraction
7. Mock provider: Test token generator, pytest fixtures
8. Tests: 100% coverage for Phase 1 modules

**Deliverables**:
- Working OAuth flows for B2C and Entra ID
- JWT validation with Azure AD public keys
- Session management with Redis
- 100% test coverage

**Evidence**:
- `pytest --cov=eva_auth --cov-report=html` passing
- `curl` examples hitting authenticated endpoints
- Docker Compose stack running (app + Redis + Cosmos DB emulator)

---

### Phase 2: RBAC & Permissions (Week 3-4)
**Goal**: Role-based access control and tenant isolation

**Tasks**:
1. RBAC engine: Policy definitions, permission checks, role hierarchy
2. Tenant isolation: Cross-tenant access prevention, resource ownership validation
3. Permission decorator: `@require_permission` for route handlers
4. Entra ID group mapping: Groups → EVA roles, configurable mapping
5. API key manager: Generation, validation, revocation, Cosmos DB storage
6. Audit logger: Event logging to Cosmos DB, structured logs
7. Tests: RBAC scenarios, tenant isolation, permission denial

**Deliverables**:
- Working RBAC with 3 roles (admin, analyst, viewer)
- Tenant isolation enforced
- API key authentication working
- Audit logs captured

**Evidence**:
- Permission tests passing (403 Forbidden on denied actions)
- Cross-tenant access blocked (user A cannot access tenant B resources)
- Audit log queries returning correct events

---

### Phase 3: Session Management & Security (Week 5)
**Goal**: Production-ready session handling and security hardening

**Tasks**:
1. Token refresh flow: Refresh token validation, new access token issuance
2. Logout flow: Token blacklisting, session deletion, cookie clearing
3. Rate limiting: Token bucket for auth attempts (20 per IP per minute)
4. Security headers: CORS, CSP, X-Frame-Options, HSTS
5. Error handling: Standardized error responses (RFC 7807 Problem Details)
6. Bilingual errors: EN-CA/FR-CA translations for citizen-facing flows
7. Tests: Token refresh, logout, rate limiting, error responses

**Deliverables**:
- Token refresh working (refresh token → new access token)
- Logout working (session deleted, cookies cleared)
- Rate limiting active (429 Too Many Requests after 20 attempts)
- Bilingual error messages

**Evidence**:
- Refresh token flow working (Postman/curl examples)
- Logout clearing cookies (DevTools inspection)
- Rate limiting triggered (429 response after 20 requests)
- French error messages displayed for French locale

---

### Phase 4: Observability & Monitoring (Week 6)
**Goal**: Production-grade observability for debugging and alerting

**Tasks**:
1. OpenTelemetry: Tracing for all auth operations (login, logout, validate)
2. Structured logging: JSON logs with context (user_id, tenant_id, IP)
3. Metrics: Prometheus metrics (success rate, latency, error rate)
4. Azure Monitor: Integration with Application Insights
5. Dashboards: Grafana dashboards for auth metrics
6. Alerts: Failed logins > 5%, token validation latency > 500ms
7. Tests: Trace validation, log output verification

**Deliverables**:
- OpenTelemetry traces visible in Jaeger
- Structured logs in JSON format
- Grafana dashboards showing auth metrics
- Alerts configured in Azure Monitor

**Evidence**:
- Jaeger UI showing auth traces
- Grafana dashboard screenshot
- Alert triggered (test scenario: high error rate)

---

### Phase 5: Documentation & Developer Tools (Week 7)
**Goal**: Enable developers to integrate eva-auth easily

**Tasks**:
1. OpenAPI specification: Complete API docs with examples
2. Integration guide: Step-by-step for eva-api, eva-core, eva-ui
3. Architecture diagrams: OAuth flows, system architecture, deployment
4. SDK: Python client library (`pip install eva-auth-sdk`)
5. Postman collection: Sample requests for all endpoints
6. Runbook: Common issues, troubleshooting, key rotation
7. Tests: SDK integration tests, documentation link validation

**Deliverables**:
- OpenAPI spec published (Swagger UI)
- Integration guide with code examples
- Python SDK published to internal registry
- Postman collection available

**Evidence**:
- Swagger UI accessible at `/docs`
- Integration guide walkthrough (5 min setup time)
- SDK installation working (`pip install eva-auth-sdk`)

---

### Phase 6: Production Readiness (Week 8)
**Goal**: Deploy to production with full quality gates passed

**Tasks**:
1. Load testing: Locust test with 10,000 concurrent users
2. Security audit: OWASP Top 10 validation, penetration testing
3. Key rotation: Azure Key Vault setup, automatic rotation
4. Multi-region: Deploy to 2+ Azure regions (Canada Central + Canada East)
5. Disaster recovery: Backup/restore procedures, RTO < 1 hour
6. Compliance review: PBMM checklist, ATIP readiness validation
7. Final review: All 12 quality gates verified

**Deliverables**:
- Load test passing (10,000 users, p95 < 100ms)
- Security audit report (no HIGH/CRITICAL findings)
- Azure Key Vault configured with rotation policy
- Multi-region deployment (blue-green)
- Disaster recovery runbook

**Evidence**:
- Locust report showing 10,000 concurrent users
- Security scan report (Trivy + manual audit)
- Azure Key Vault screenshot showing rotation schedule
- Multi-region deployment logs
- All 12 quality gates PASSED

---

## 8. References

### Azure Documentation
- **Azure AD B2C OAuth 2.0**: https://learn.microsoft.com/en-us/azure/active-directory-b2c/authorization-code-flow
- **Microsoft Entra ID OAuth 2.0**: https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow
- **JWT Validation**: https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens
- **Azure Key Vault**: https://learn.microsoft.com/en-us/azure/key-vault/general/overview
- **Azure Cosmos DB**: https://learn.microsoft.com/en-us/azure/cosmos-db/introduction

### Reference Implementations
- **OpenWebUI Authentication**: `OpenWebUI/backend/open_webui/routers/auths.py` (OAuth flows, session management)
- **OpenWebUI OAuth Utils**: `OpenWebUI/backend/open_webui/utils/oauth.py` (OAuthManager, token refresh)
- **PubSec Info Assistant**: `PubSec-Info-Assistant/app/backend/app.py` (Azure credential management)
- **eva-api Auth Service**: `eva-api/src/eva_api/services/auth_service.py` (Azure AD integration patterns)

### EVA Orchestrator Docs
- **Sprint 003 Plan**: `eva-orchestrator/archive/pre-dec7-2025/sprint-003/sprint-003-plan.md` (Authentication sprint)
- **eva-auth Brief**: `eva-orchestrator/docs/EVA-2.0/ESDC/eva2_fastlane_repo_v5_full/eva2_fastlane_repo_v5_full/copilot_briefs/eva-auth.md`

### Standards & Security
- **OAuth 2.0 RFC**: https://datatracker.ietf.org/doc/html/rfc6749
- **OpenID Connect**: https://openid.net/specs/openid-connect-core-1_0.html
- **JWT RFC**: https://datatracker.ietf.org/doc/html/rfc7519
- **OWASP Top 10**: https://owasp.org/www-project-top-ten/
- **RFC 7807 Problem Details**: https://datatracker.ietf.org/doc/html/rfc7807

### Libraries & Tools
- **FastAPI**: https://fastapi.tiangolo.com/
- **Authlib**: https://docs.authlib.org/en/latest/
- **PyJWT**: https://pyjwt.readthedocs.io/en/stable/
- **azure-identity**: https://learn.microsoft.com/en-us/python/api/overview/azure/identity-readme
- **redis-py**: https://redis-py.readthedocs.io/en/stable/

---

## 9. Autonomous Implementation Model

### Context Engineering Principles

This specification follows the **Three Concepts Pattern**:

1. **Context Engineering**: Complete specification (no gaps), reference implementations analyzed, proven patterns documented
2. **Complete SDLC**: TDD (tests first), CI/CD (automated), observability (traces/logs/metrics), documentation (OpenAPI + guides)
3. **Execution Evidence Rule**: All deliverables must include evidence (test reports, screenshots, logs, curl examples)

### Implementation Approach

Marco will **NOT** be available for incremental approvals during the 8-week implementation. The agent must:

1. **Follow Requirements TO THE LETTER**: No shortcuts, no approximations, no "close enough"
2. **Use Reference Implementations**: OpenWebUI OAuth patterns, PubSec Azure credential management
3. **Apply All 12 Quality Gates**: 100% coverage, security validated, performance benchmarked, docs complete
4. **Test Continuously**: TDD approach (write tests first), run tests after every change
5. **Document Decisions**: ADRs for architecture choices, inline comments for complex logic
6. **Generate Evidence**: Screenshots, logs, curl examples, test reports (not just "I did it")

### Binary Final Review

After 8 weeks, Marco will perform a **binary review**:

- ✅ **All 12 quality gates PASS** → Ship to production
- ❌ **Any gate FAILS** → List specific failures, agent fixes, resubmit for review

There is NO partial credit. All gates must pass.

### Success Criteria

**IF** this specification is followed completely **AND** all reference patterns are applied **AND** all 12 quality gates pass **THEN** eva-auth will be production-ready without Marco's incremental involvement.

This is the **proven model from EVA-Sovereign-UI** (733-line spec → autonomous implementation → all gates passed).

---

## 10. Next Steps

1. **Marco Opens eva-auth Workspace**:
   ```powershell
   cd "C:\Users\marco\Documents\_AI Dev\EVA Suite"
   code eva-auth
   ```

2. **Run Startup Script**:
   ```powershell
   .\_MARCO-use-this-to-tell_copilot-to-read-repo-specific-instructions.ps1
   ```

3. **Copy Output to Copilot**:
   - Copy green text (5 bullet points)
   - Paste as FIRST message to GitHub Copilot
   - Wait for Copilot to confirm it read `docs/SPECIFICATION.md`

4. **Give Task**:
   ```
   Implement Phase 1: Foundation (core authentication + OAuth flows + JWT validation).
   Follow specification TO THE LETTER.
   Use OpenWebUI OAuth patterns (OAuthManager, token refresh).
   Use PubSec Azure credential management patterns.
   Achieve 100% test coverage.
   Show curl examples when done.
   ```

5. **Check In Weekly** (NOT Daily):
   - Week 2: Phase 1 complete? (OAuth flows working, JWT validation, tests passing)
   - Week 4: Phase 2 complete? (RBAC working, tenant isolation, API keys)
   - Week 5: Phase 3 complete? (Token refresh, logout, rate limiting)
   - Week 6: Phase 4 complete? (OpenTelemetry traces, Grafana dashboards)
   - Week 7: Phase 5 complete? (OpenAPI docs, SDK published, integration guide)
   - Week 8: Phase 6 complete? (Load test passed, security audit clean, all gates PASSED)

6. **Final Review** (Week 9):
   - Marco validates all 12 quality gates
   - Binary decision: Ship OR Fix

---

**END OF SPECIFICATION**

This document contains ALL requirements for autonomous eva-auth implementation. No additional context needed. Follow TO THE LETTER. Good luck! 🚀

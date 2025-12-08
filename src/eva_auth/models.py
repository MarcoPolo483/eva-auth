"""Data models for eva-auth service."""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class UserClaims(BaseModel):
    """JWT claims for authenticated user."""

    sub: str = Field(..., description="Subject (user ID)")
    email: str | None = Field(None, description="User email address")
    name: str | None = Field(None, description="User full name")
    given_name: str | None = Field(None, description="User first name")
    family_name: str | None = Field(None, description="User last name")
    tenant_id: str = Field(..., description="Tenant ID")
    roles: list[str] = Field(default_factory=lambda: ["eva:user"], description="User roles")
    groups: list[str] = Field(default_factory=list, description="User groups")
    expires_at: int = Field(..., description="Token expiration timestamp (Unix epoch)")


class JWTClaims(BaseModel):
    """JWT token claims."""

    sub: str
    email: str | None = None
    name: str | None = None
    tenant_id: str
    roles: list[str] = Field(default_factory=lambda: ["eva:user"])
    groups: list[str] = Field(default_factory=list)
    expires_at: int
    iss: str | None = None
    aud: str | None = None


class AuthSession(BaseModel):
    """User session data stored in Redis."""

    user_id: str
    email: str | None = None
    tenant_id: str
    roles: list[str]
    groups: list[str] = Field(default_factory=list)
    created_at: datetime
    expires_at: datetime


class TokenResponse(BaseModel):
    """OAuth token response."""

    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    refresh_token: str | None = None
    id_token: str | None = None


class TokenValidationResponse(BaseModel):
    """Token validation response."""

    valid: bool
    claims: JWTClaims | None = None
    error: str | None = None


class APIKey(BaseModel):
    """API key metadata."""

    id: str
    name: str
    tenant_id: str
    permissions: list[str]
    key_prefix: str
    created_at: str  # ISO 8601
    created_by: str = Field(default="system")
    expires_at: str  # ISO 8601
    revoked: bool = False
    last_used_at: str | None = None
    usage_count: int = Field(default=0)


class APIKeyCreateRequest(BaseModel):
    """Request to create new API key."""

    name: str = Field(..., min_length=1, max_length=100)
    tenant_id: str
    permissions: list[str]
    expires_in_days: int = Field(default=365, ge=1, le=3650)


class APIKeyCreateResponse(BaseModel):
    """Response with newly created API key."""

    api_key: str
    name: str
    expires_at: datetime
    warning: str = "Store this key securely. It will not be shown again."


class RBACPolicy(BaseModel):
    """RBAC policy definition."""

    role: str
    permissions: list[str]


class AuditLogEntry(BaseModel):
    """Audit log entry."""

    id: str
    timestamp: datetime
    event_type: str
    user_id: str
    tenant_id: str
    ip_address: str
    user_agent: str
    auth_method: str | None = None
    session_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ValidationError(Exception):
    """Token validation error."""

    def __init__(self, message: str, error_code: str):
        self.message = message
        self.error_code = error_code
        super().__init__(self.message)


# Audit Event Models


class AuditEvent(BaseModel):
    """Base audit event model."""

    id: str
    timestamp: str  # ISO 8601 format
    event_type: str
    user_id: str
    tenant_id: str
    ip_address: str
    user_agent: str
    session_id: str | None = None
    auth_method: str | None = None
    success: bool = True
    error_message: str | None = None
    metadata: dict = Field(default_factory=dict)


class LoginEvent(BaseModel):
    """Login event with authentication details."""

    id: str
    timestamp: str
    event_type: Literal["auth.login.success", "auth.login.failure"]
    user_id: str
    tenant_id: str
    ip_address: str
    user_agent: str
    session_id: str | None = None
    auth_method: str  # azure_b2c, microsoft_entra, api_key
    success: bool
    error_message: str | None = None
    roles: list[str] = Field(default_factory=list)
    groups: list[str] = Field(default_factory=list)
    organization: str | None = None
    failure_reason: str | None = None  # expired_token, invalid_credentials, etc.


class TokenRefreshEvent(BaseModel):
    """Token refresh event."""

    id: str
    timestamp: str
    event_type: Literal["auth.token.refreshed"]
    user_id: str
    tenant_id: str
    ip_address: str
    user_agent: str
    session_id: str
    auth_method: str
    success: bool = True


class LogoutEvent(BaseModel):
    """Logout event."""

    id: str
    timestamp: str
    event_type: Literal["auth.logout.success"]
    user_id: str
    tenant_id: str
    ip_address: str
    user_agent: str
    session_id: str
    auth_method: str
    success: bool = True


class PermissionDeniedEvent(BaseModel):
    """Permission denied event."""

    id: str
    timestamp: str
    event_type: Literal["auth.permission.denied"]
    user_id: str
    tenant_id: str
    ip_address: str
    user_agent: str
    session_id: str
    resource: str
    action: str
    required_permission: str
    user_roles: list[str]
    success: bool = False
    error_message: str


class APIKeyCreatedEvent(BaseModel):
    """API key creation event."""

    id: str
    timestamp: str
    event_type: Literal["auth.apikey.created"]
    user_id: str  # User who created the key
    tenant_id: str
    ip_address: str
    user_agent: str
    api_key_id: str  # Hashed key ID
    api_key_name: str
    permissions: list[str]
    expires_at: str
    success: bool = True


class APIKeyRevokedEvent(BaseModel):
    """API key revocation event."""

    id: str
    timestamp: str
    event_type: Literal["auth.apikey.revoked"]
    user_id: str  # User who revoked the key
    tenant_id: str
    ip_address: str
    user_agent: str
    api_key_id: str
    api_key_name: str
    success: bool = True


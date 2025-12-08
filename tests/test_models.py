"""Tests for data models."""

import pytest
from datetime import datetime
from pydantic import ValidationError as PydanticValidationError

from eva_auth.models import (
    UserClaims,
    JWTClaims,
    AuthSession,
    TokenResponse,
    APIKeyCreateRequest,
    RBACPolicy,
    ValidationError,
)


class TestUserClaims:
    """Test suite for UserClaims model."""

    def test_create_user_claims(self):
        """Test creating user claims."""
        claims = UserClaims(
            sub="user-123",
            email="user@example.com",
            tenant_id="tenant-456",
            expires_at=1735776000
        )
        
        assert claims.sub == "user-123"
        assert claims.email == "user@example.com"
        assert claims.tenant_id == "tenant-456"
        assert claims.roles == ["eva:user"]  # Default role

    def test_user_claims_with_roles(self):
        """Test user claims with custom roles."""
        claims = UserClaims(
            sub="user-123",
            email="user@example.com",
            tenant_id="tenant-456",
            roles=["eva:admin", "eva:user"],
            expires_at=1735776000
        )
        
        assert "eva:admin" in claims.roles
        assert "eva:user" in claims.roles


class TestJWTClaims:
    """Test suite for JWTClaims model."""

    def test_create_jwt_claims(self):
        """Test creating JWT claims."""
        claims = JWTClaims(
            sub="user-123",
            tenant_id="tenant-456",
            expires_at=1735776000
        )
        
        assert claims.sub == "user-123"
        assert claims.tenant_id == "tenant-456"
        assert claims.expires_at == 1735776000


class TestAuthSession:
    """Test suite for AuthSession model."""

    def test_create_auth_session(self):
        """Test creating auth session."""
        now = datetime.utcnow()
        session = AuthSession(
            user_id="user-123",
            email="user@example.com",
            tenant_id="tenant-456",
            roles=["eva:user"],
            created_at=now,
            expires_at=now
        )
        
        assert session.user_id == "user-123"
        assert session.email == "user@example.com"
        assert session.tenant_id == "tenant-456"


class TestTokenResponse:
    """Test suite for TokenResponse model."""

    def test_create_token_response(self):
        """Test creating token response."""
        response = TokenResponse(
            access_token="token-123",
            expires_in=3600
        )
        
        assert response.access_token == "token-123"
        assert response.token_type == "Bearer"
        assert response.expires_in == 3600


class TestAPIKeyCreateRequest:
    """Test suite for APIKeyCreateRequest model."""

    def test_create_api_key_request(self):
        """Test creating API key request."""
        request = APIKeyCreateRequest(
            name="Test API Key",
            tenant_id="tenant-123",
            permissions=["spaces:read", "documents:write"]
        )
        
        assert request.name == "Test API Key"
        assert request.tenant_id == "tenant-123"
        assert len(request.permissions) == 2

    def test_api_key_request_validation(self):
        """Test API key request validation."""
        with pytest.raises(PydanticValidationError):
            APIKeyCreateRequest(
                name="",  # Empty name should fail
                tenant_id="tenant-123",
                permissions=[]
            )

    def test_api_key_expiration_limits(self):
        """Test API key expiration limits."""
        with pytest.raises(PydanticValidationError):
            APIKeyCreateRequest(
                name="Test",
                tenant_id="tenant-123",
                permissions=["read"],
                expires_in_days=10000  # Too long
            )


class TestRBACPolicy:
    """Test suite for RBACPolicy model."""

    def test_create_rbac_policy(self):
        """Test creating RBAC policy."""
        policy = RBACPolicy(
            role="eva:admin",
            permissions=["spaces:read", "spaces:write", "users:manage"]
        )
        
        assert policy.role == "eva:admin"
        assert len(policy.permissions) == 3


class TestValidationError:
    """Test suite for ValidationError exception."""

    def test_create_validation_error(self):
        """Test creating validation error."""
        error = ValidationError("Token expired", "TOKEN_EXPIRED")
        
        assert error.message == "Token expired"
        assert error.error_code == "TOKEN_EXPIRED"
        assert str(error) == "Token expired"

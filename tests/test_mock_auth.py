"""Tests for mock authentication provider."""

import jwt
import pytest

from eva_auth.testing import MockAuthProvider
from eva_auth.models import JWTClaims


class TestMockAuthProvider:
    """Test suite for MockAuthProvider."""

    def test_generate_token_default_params(self):
        """Test token generation with default parameters."""
        provider = MockAuthProvider()
        token = provider.generate_token()
        
        assert isinstance(token, str)
        assert len(token) > 0

    def test_generate_token_custom_params(self):
        """Test token generation with custom parameters."""
        provider = MockAuthProvider()
        token = provider.generate_token(
            user_id="custom-user-123",
            email="custom@example.com",
            name="Custom User",
            tenant_id="custom-tenant-456",
            roles=["eva:admin", "eva:user"],
            groups=["group1", "group2"],
        )
        
        # Decode without verification to check payload
        payload = jwt.decode(token, options={"verify_signature": False})
        
        assert payload["sub"] == "custom-user-123"
        assert payload["email"] == "custom@example.com"
        assert payload["name"] == "Custom User"
        assert payload["tid"] == "custom-tenant-456"
        assert payload["roles"] == ["eva:admin", "eva:user"]
        assert payload["groups"] == ["group1", "group2"]

    def test_validate_token_success(self):
        """Test successful token validation."""
        provider = MockAuthProvider()
        token = provider.generate_token()
        
        claims = provider.validate_token(token)
        
        assert isinstance(claims, JWTClaims)
        assert claims.sub == "test-user-1234"
        assert claims.email == "test@example.com"
        assert claims.tenant_id == "test-tenant-5678"
        assert "eva:user" in claims.roles

    def test_validate_expired_token(self):
        """Test validation of expired token."""
        provider = MockAuthProvider()
        expired_token = provider.generate_expired_token()
        
        with pytest.raises(jwt.ExpiredSignatureError):
            provider.validate_token(expired_token)

    def test_validate_token_wrong_secret(self):
        """Test validation with wrong secret."""
        provider1 = MockAuthProvider(secret="secret1")
        provider2 = MockAuthProvider(secret="secret2")
        
        token = provider1.generate_token()
        
        with pytest.raises(jwt.InvalidTokenError):
            provider2.validate_token(token)

    def test_validate_malformed_token(self):
        """Test validation of malformed token."""
        provider = MockAuthProvider()
        
        with pytest.raises(jwt.InvalidTokenError):
            provider.validate_token("not.a.valid.token")

    def test_token_expiration_field(self):
        """Test token expiration field."""
        provider = MockAuthProvider()
        token = provider.generate_token(expires_in=7200)
        
        payload = jwt.decode(token, options={"verify_signature": False})
        
        # Check that exp is set and is in the future
        assert "exp" in payload
        assert payload["exp"] > payload["iat"]
        assert payload["exp"] - payload["iat"] == 7200

    def test_generate_expired_token_is_expired(self):
        """Test that generate_expired_token actually creates an expired token."""
        provider = MockAuthProvider()
        expired_token = provider.generate_expired_token()
        
        payload = jwt.decode(expired_token, options={"verify_signature": False})
        
        import time
        current_time = int(time.time())
        assert payload["exp"] < current_time

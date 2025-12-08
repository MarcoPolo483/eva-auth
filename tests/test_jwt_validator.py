"""Tests for JWT validator."""

import jwt
import pytest
from unittest.mock import Mock, patch

from eva_auth.validators import MockJWTValidator
from eva_auth.models import ValidationError, JWTClaims


class TestMockJWTValidator:
    """Test suite for MockJWTValidator."""

    @pytest.fixture
    def validator(self):
        """Create validator instance."""
        return MockJWTValidator(secret="test-secret-12345")

    @pytest.fixture
    def valid_token(self):
        """Create valid JWT token."""
        from eva_auth.testing import MockAuthProvider
        provider = MockAuthProvider(secret="test-secret-12345")
        return provider.generate_token()

    @pytest.fixture
    def expired_token(self):
        """Create expired JWT token."""
        from eva_auth.testing import MockAuthProvider
        provider = MockAuthProvider(secret="test-secret-12345")
        return provider.generate_expired_token()

    @pytest.mark.asyncio
    async def test_validate_valid_token(self, validator, valid_token):
        """Test validation of valid token."""
        claims = await validator.validate_token(valid_token)
        
        assert isinstance(claims, JWTClaims)
        assert claims.sub == "test-user-1234"
        assert claims.email == "test@example.com"
        assert claims.tenant_id == "test-tenant-5678"

    @pytest.mark.asyncio
    async def test_validate_expired_token(self, validator, expired_token):
        """Test validation of expired token."""
        with pytest.raises(ValidationError) as exc_info:
            await validator.validate_token(expired_token)
        
        assert exc_info.value.error_code == "TOKEN_EXPIRED"
        assert "expired" in exc_info.value.message.lower()

    @pytest.mark.asyncio
    async def test_validate_malformed_token(self, validator):
        """Test validation of malformed token."""
        with pytest.raises(ValidationError) as exc_info:
            await validator.validate_token("not.a.valid.token")
        
        assert exc_info.value.error_code == "INVALID_TOKEN"

    @pytest.mark.asyncio
    async def test_validate_token_wrong_signature(self, validator):
        """Test validation with wrong signature."""
        from eva_auth.testing import MockAuthProvider
        provider = MockAuthProvider(secret="wrong-secret")
        token = provider.generate_token()
        
        with pytest.raises(ValidationError) as exc_info:
            await validator.validate_token(token)
        
        assert exc_info.value.error_code == "INVALID_TOKEN"

    @pytest.mark.asyncio
    async def test_validate_token_missing_claims(self, validator):
        """Test validation with missing required claims."""
        # Create token with missing 'sub' claim
        payload = {
            "email": "test@example.com",
            "exp": 9999999999,
            "iat": 1000000000,
            "nbf": 1000000000,
        }
        token = jwt.encode(payload, "test-secret-12345", algorithm="HS256")
        
        with pytest.raises(ValidationError):
            await validator.validate_token(token)

    @pytest.mark.asyncio
    async def test_claims_extraction(self, validator, valid_token):
        """Test correct extraction of all claims."""
        claims = await validator.validate_token(valid_token)
        
        assert claims.sub is not None
        assert claims.email is not None
        assert claims.tenant_id is not None
        assert isinstance(claims.roles, list)
        assert isinstance(claims.groups, list)
        assert claims.expires_at > 0

    @pytest.mark.asyncio
    async def test_default_roles(self, validator):
        """Test default roles when not provided in token."""
        from eva_auth.testing import MockAuthProvider
        provider = MockAuthProvider(secret="test-secret-12345")
        
        # Generate token without explicit roles
        payload = {
            "sub": "user-123",
            "email": "user@example.com",
            "tid": "tenant-456",
            "exp": 9999999999,
            "iat": 1000000000,
            "nbf": 1000000000,
        }
        token = jwt.encode(payload, "test-secret-12345", algorithm="HS256")
        
        claims = await validator.validate_token(token)
        assert claims.roles == ["eva:user"]

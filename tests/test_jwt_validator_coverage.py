"""Tests for jwt_validator.py to achieve 100% coverage (RS256)."""

import pytest
import jwt
import time
from unittest.mock import MagicMock, patch
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from eva_auth.validators.jwt_validator import JWTValidator
from eva_auth.models import ValidationError


@pytest.fixture
def rsa_keypair():
    """Generate RSA key pair for testing."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    public_key = private_key.public_key()
    
    # Serialize keys
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_key, public_key, private_pem, public_pem


@pytest.fixture
def mock_jwks_client(rsa_keypair):
    """Mock PyJWKClient for testing."""
    _, public_key, _, _ = rsa_keypair
    
    mock_signing_key = MagicMock()
    mock_signing_key.key = public_key
    
    mock_client = MagicMock()
    mock_client.get_signing_key_from_jwt.return_value = mock_signing_key
    
    return mock_client


@pytest.mark.asyncio
async def test_jwt_validator_initialization():
    """Test JWTValidator initialization."""
    validator = JWTValidator(
        jwks_uri="https://example.com/.well-known/jwks.json",
        issuer="https://issuer.example.com",
        audience="client-id",
        algorithms=["RS256", "RS384"],
    )
    
    assert validator.jwks_uri == "https://example.com/.well-known/jwks.json"
    assert validator.issuer == "https://issuer.example.com"
    assert validator.audience == "client-id"
    assert validator.algorithms == ["RS256", "RS384"]
    assert validator.jwks_client is not None


@pytest.mark.asyncio
async def test_jwt_validator_default_algorithms():
    """Test JWTValidator uses RS256 as default algorithm."""
    validator = JWTValidator(
        jwks_uri="https://example.com/.well-known/jwks.json",
        issuer="https://issuer.example.com",
        audience="client-id",
    )
    
    assert validator.algorithms == ["RS256"]


@pytest.mark.asyncio
async def test_jwt_validator_valid_token(rsa_keypair, mock_jwks_client):
    """Test JWTValidator successfully validates a valid RS256 token."""
    private_key, _, _, _ = rsa_keypair
    
    # Create a valid token
    now = int(time.time())
    payload = {
        "sub": "user123",
        "email": "test@example.com",
        "name": "Test User",
        "tid": "tenant123",
        "roles": ["eva:admin"],
        "groups": ["group1"],
        "exp": now + 3600,
        "iss": "https://issuer.example.com",
        "aud": "client-id",
    }
    
    token = jwt.encode(payload, private_key, algorithm="RS256")
    
    # Create validator with mocked JWKS client
    with patch("eva_auth.validators.jwt_validator.PyJWKClient", return_value=mock_jwks_client):
        validator = JWTValidator(
            jwks_uri="https://example.com/.well-known/jwks.json",
            issuer="https://issuer.example.com",
            audience="client-id",
        )
        
        claims = await validator.validate_token(token)
        
        assert claims.sub == "user123"
        assert claims.email == "test@example.com"
        assert claims.name == "Test User"
        assert claims.tenant_id == "tenant123"
        assert claims.roles == ["eva:admin"]
        assert claims.groups == ["group1"]
        assert claims.iss == "https://issuer.example.com"
        assert claims.aud == "client-id"


@pytest.mark.asyncio
async def test_jwt_validator_expired_token(rsa_keypair, mock_jwks_client):
    """Test JWTValidator raises ValidationError for expired token."""
    private_key, _, _, _ = rsa_keypair
    
    # Create an expired token
    now = int(time.time())
    payload = {
        "sub": "user123",
        "exp": now - 3600,  # Expired 1 hour ago
        "iss": "https://issuer.example.com",
        "aud": "client-id",
    }
    
    token = jwt.encode(payload, private_key, algorithm="RS256")
    
    with patch("eva_auth.validators.jwt_validator.PyJWKClient", return_value=mock_jwks_client):
        validator = JWTValidator(
            jwks_uri="https://example.com/.well-known/jwks.json",
            issuer="https://issuer.example.com",
            audience="client-id",
        )
        
        with pytest.raises(ValidationError) as exc_info:
            await validator.validate_token(token)
        
        assert exc_info.value.error_code == "TOKEN_EXPIRED"
        assert "expired" in exc_info.value.message.lower()


@pytest.mark.asyncio
async def test_jwt_validator_invalid_audience(rsa_keypair, mock_jwks_client):
    """Test JWTValidator raises ValidationError for invalid audience."""
    private_key, _, _, _ = rsa_keypair
    
    now = int(time.time())
    payload = {
        "sub": "user123",
        "exp": now + 3600,
        "iss": "https://issuer.example.com",
        "aud": "wrong-client-id",  # Wrong audience
    }
    
    token = jwt.encode(payload, private_key, algorithm="RS256")
    
    with patch("eva_auth.validators.jwt_validator.PyJWKClient", return_value=mock_jwks_client):
        validator = JWTValidator(
            jwks_uri="https://example.com/.well-known/jwks.json",
            issuer="https://issuer.example.com",
            audience="client-id",
        )
        
        with pytest.raises(ValidationError) as exc_info:
            await validator.validate_token(token)
        
        assert exc_info.value.error_code == "INVALID_AUDIENCE"


@pytest.mark.asyncio
async def test_jwt_validator_invalid_issuer(rsa_keypair, mock_jwks_client):
    """Test JWTValidator raises ValidationError for invalid issuer."""
    private_key, _, _, _ = rsa_keypair
    
    now = int(time.time())
    payload = {
        "sub": "user123",
        "exp": now + 3600,
        "iss": "https://wrong-issuer.example.com",  # Wrong issuer
        "aud": "client-id",
    }
    
    token = jwt.encode(payload, private_key, algorithm="RS256")
    
    with patch("eva_auth.validators.jwt_validator.PyJWKClient", return_value=mock_jwks_client):
        validator = JWTValidator(
            jwks_uri="https://example.com/.well-known/jwks.json",
            issuer="https://issuer.example.com",
            audience="client-id",
        )
        
        with pytest.raises(ValidationError) as exc_info:
            await validator.validate_token(token)
        
        assert exc_info.value.error_code == "INVALID_ISSUER"


@pytest.mark.asyncio
async def test_jwt_validator_malformed_token(mock_jwks_client):
    """Test JWTValidator raises ValidationError for malformed token."""
    with patch("eva_auth.validators.jwt_validator.PyJWKClient", return_value=mock_jwks_client):
        validator = JWTValidator(
            jwks_uri="https://example.com/.well-known/jwks.json",
            issuer="https://issuer.example.com",
            audience="client-id",
        )
        
        with pytest.raises(ValidationError) as exc_info:
            await validator.validate_token("not.a.valid.jwt")
        
        assert exc_info.value.error_code == "INVALID_TOKEN"


@pytest.mark.asyncio
async def test_jwt_validator_generic_exception(mock_jwks_client):
    """Test JWTValidator handles generic exceptions."""
    # Mock JWKS client to raise an exception
    mock_jwks_client.get_signing_key_from_jwt.side_effect = Exception("Network error")
    
    with patch("eva_auth.validators.jwt_validator.PyJWKClient", return_value=mock_jwks_client):
        validator = JWTValidator(
            jwks_uri="https://example.com/.well-known/jwks.json",
            issuer="https://issuer.example.com",
            audience="client-id",
        )
        
        with pytest.raises(ValidationError) as exc_info:
            await validator.validate_token("some.jwt.token")
        
        assert exc_info.value.error_code == "VALIDATION_FAILED"
        assert "Network error" in exc_info.value.message


@pytest.mark.asyncio
async def test_jwt_validator_extract_claims_with_tenant_id(rsa_keypair, mock_jwks_client):
    """Test _extract_claims handles tenant_id field."""
    private_key, _, _, _ = rsa_keypair
    
    now = int(time.time())
    payload = {
        "sub": "user123",
        "tenant_id": "tenant-from-tenant-id-field",  # Use tenant_id instead of tid
        "exp": now + 3600,
        "iss": "https://issuer.example.com",
        "aud": "client-id",
    }
    
    token = jwt.encode(payload, private_key, algorithm="RS256")
    
    with patch("eva_auth.validators.jwt_validator.PyJWKClient", return_value=mock_jwks_client):
        validator = JWTValidator(
            jwks_uri="https://example.com/.well-known/jwks.json",
            issuer="https://issuer.example.com",
            audience="client-id",
        )
        
        claims = await validator.validate_token(token)
        assert claims.tenant_id == "tenant-from-tenant-id-field"


@pytest.mark.asyncio
async def test_jwt_validator_extract_claims_minimal_payload(rsa_keypair, mock_jwks_client):
    """Test _extract_claims with minimal payload (only required fields)."""
    private_key, _, _, _ = rsa_keypair
    
    now = int(time.time())
    payload = {
        "sub": "user123",
        "exp": now + 3600,
        "iss": "https://issuer.example.com",
        "aud": "client-id",
    }
    
    token = jwt.encode(payload, private_key, algorithm="RS256")
    
    with patch("eva_auth.validators.jwt_validator.PyJWKClient", return_value=mock_jwks_client):
        validator = JWTValidator(
            jwks_uri="https://example.com/.well-known/jwks.json",
            issuer="https://issuer.example.com",
            audience="client-id",
        )
        
        claims = await validator.validate_token(token)
        
        assert claims.sub == "user123"
        assert claims.email is None
        assert claims.name is None
        assert claims.tenant_id == ""  # Default empty string
        assert claims.roles == ["eva:user"]  # Default role
        assert claims.groups == []  # Default empty list

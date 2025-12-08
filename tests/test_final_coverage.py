"""Targeted coverage tests for remaining uncovered lines."""

import pytest
from unittest.mock import Mock, AsyncMock
from azure.cosmos.exceptions import CosmosHttpResponseError
from eva_auth.models import JWTClaims


# ==================== Container Creation Tests ====================


@pytest.mark.asyncio
async def test_api_key_manager_container_creation():
    """Test APIKeyManager creates container when it doesn't exist (lines 44-50)."""
    from eva_auth.apikeys.api_key_manager import APIKeyManager
    
    mock_client = Mock()
    mock_database = Mock()
    mock_container = Mock()
    
    # First call raises error, second call succeeds after creation
    error = CosmosHttpResponseError(message="Not found", status_code=404)
    mock_database.get_container_client = Mock(side_effect=[error, mock_container])
    mock_database.create_container = Mock()
    mock_client.get_database_client = Mock(return_value=mock_database)
    
    manager = APIKeyManager(cosmos_client=mock_client)
    container = await manager._get_container()
    
    # Verify container was created
    assert mock_database.create_container.called
    assert container == mock_container


@pytest.mark.asyncio
async def test_audit_logger_container_creation():
    """Test AuditLogger creates container when it doesn't exist (lines 41-47)."""
    from eva_auth.audit.audit_logger import AuditLogger
    
    mock_client = Mock()
    mock_database = Mock()
    mock_container = Mock()
    
    error = CosmosHttpResponseError(message="Not found", status_code=404)
    mock_database.get_container_client = Mock(side_effect=[error, mock_container])
    mock_database.create_container = Mock()
    mock_client.get_database_client = Mock(return_value=mock_database)
    
    logger = AuditLogger(cosmos_client=mock_client)
    container = await logger._get_container()
    
    assert mock_database.create_container.called
    assert container == mock_container


# ==================== API Key Manager Error Paths ====================


@pytest.mark.asyncio
async def test_api_key_manager_validate_not_found():
    """Test validate_api_key returns None on error (lines 175-176)."""
    from eva_auth.apikeys.api_key_manager import APIKeyManager
    
    mock_container = Mock()
    # query_items raises CosmosHttpResponseError
    error = CosmosHttpResponseError(message="Query failed", status_code=500)
    mock_container.query_items = Mock(side_effect=error)
    
    manager = APIKeyManager(cosmos_client=Mock())
    manager._container = mock_container
    
    result = await manager.validate_api_key("test_key_value")
    assert result is None


@pytest.mark.asyncio
async def test_api_key_manager_get_by_id_not_found():
    """Test get_api_key_by_id returns None on error (lines 272-273)."""
    from eva_auth.apikeys.api_key_manager import APIKeyManager
    
    mock_container = Mock()
    error = CosmosHttpResponseError(message="Not found", status_code=404)
    mock_container.read_item = Mock(side_effect=error)
    
    manager = APIKeyManager(cosmos_client=Mock())
    manager._container = mock_container
    
    result = await manager.get_api_key_by_id("key_id", "tenant1")
    assert result is None


@pytest.mark.asyncio
async def test_api_key_manager_update_permissions_not_found():
    """Test update_api_key_permissions returns False on error (lines 298-299)."""
    from eva_auth.apikeys.api_key_manager import APIKeyManager
    
    mock_container = Mock()
    error = CosmosHttpResponseError(message="Not found", status_code=404)
    mock_container.read_item = Mock(side_effect=error)
    
    manager = APIKeyManager(cosmos_client=Mock())
    manager._container = mock_container
    
    result = await manager.update_api_key_permissions("key_id", "tenant1", ["read"])
    assert result is False


@pytest.mark.asyncio
async def test_api_key_manager_list_with_revoked():
    """Test list_api_keys includes revoked when requested (line 216)."""
    from eva_auth.apikeys.api_key_manager import APIKeyManager
    
    mock_container = Mock()
    mock_container.query_items = Mock(return_value=[])
    
    manager = APIKeyManager(cosmos_client=Mock())
    manager._container = mock_container
    
    # Call with include_revoked=True to trigger line 216
    result = await manager.list_api_keys("tenant1", include_revoked=True)
    
    # Verify query was called
    assert mock_container.query_items.called
    assert result == []


# ==================== RBAC Engine ====================


@pytest.mark.asyncio
async def test_rbac_invalid_role():
    """Test has_higher_or_equal_role with invalid role returns False (line 183)."""
    from eva_auth.rbac.rbac_engine import RBACEngine
    
    engine = RBACEngine()
    claims = JWTClaims(
        sub="user1",
        email="test@example.com",
        name="Test",
        roles=["eva:user"],  # Valid role
        tenant_id="tenant1",
        expires_at=9999999999,
        iss="issuer",
        aud="audience"
    )
    
    # Checking for an invalid role should return False (line 183)
    result = engine.has_higher_or_equal_role(claims, "invalid_role_name")
    assert result is False


# ==================== Azure B2C ====================


def test_azure_b2c_get_jwks_uri():
    """Test get_jwks_uri method (line 124)."""
    from eva_auth.providers.azure_ad_b2c import AzureADB2CProvider
    
    provider = AzureADB2CProvider(
        tenant_name="test",
        tenant_id="test_id",
        client_id="client",
        client_secret="secret"
    )
    
    uri = provider.get_jwks_uri()
    assert "test.b2clogin.com" in uri
    assert "discovery" in uri


# ==================== OAuth Endpoints ====================


@pytest.mark.asyncio
async def test_b2c_authorize_endpoint():
    """Test B2C authorize generates auth URL (lines 134-145)."""
    from eva_auth.routers.auth import b2c_authorize
    from eva_auth.providers.azure_ad_b2c import AzureADB2CProvider
    
    mock_provider = Mock(spec=AzureADB2CProvider)
    mock_provider.get_authorization_url = AsyncMock(
        return_value=("https://auth.example.com?state=abc", "abc")
    )
    
    result = await b2c_authorize(provider=mock_provider)
    
    assert "authorization_url" in result
    assert "state" in result


@pytest.mark.asyncio
async def test_b2c_callback_endpoint():
    """Test B2C callback exchanges code for tokens (lines 148-175)."""
    from eva_auth.routers.auth import b2c_callback
    from eva_auth.providers.azure_ad_b2c import AzureADB2CProvider
    import fakeredis.aioredis
    
    mock_provider = Mock(spec=AzureADB2CProvider)
    mock_provider.exchange_code_for_tokens = AsyncMock(
        return_value={
            "access_token": "token123",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "refresh123",
            "id_token": "id123"
        }
    )
    
    redis = fakeredis.aioredis.FakeRedis()
    
    result = await b2c_callback(
        code="auth_code",
        state="state123",
        provider=mock_provider,
        redis_client=redis
    )
    
    assert result.access_token == "token123"
    assert result.expires_in == 3600


@pytest.mark.asyncio
async def test_entra_authorize_endpoint():
    """Test Entra authorize generates auth URL (lines 185-193)."""
    from eva_auth.routers.auth import entra_authorize
    from eva_auth.providers.microsoft_entra_id import MicrosoftEntraIDProvider
    
    mock_provider = Mock(spec=MicrosoftEntraIDProvider)
    mock_provider.get_authorization_url = AsyncMock(
        return_value=("https://login.microsoftonline.com?state=xyz", "xyz")
    )
    
    result = await entra_authorize(provider=mock_provider)
    
    assert "authorization_url" in result
    assert "state" in result


@pytest.mark.asyncio
async def test_entra_callback_endpoint():
    """Test Entra callback exchanges code for tokens (lines 208-221)."""
    from eva_auth.routers.auth import entra_callback
    from eva_auth.providers.microsoft_entra_id import MicrosoftEntraIDProvider
    import fakeredis.aioredis
    
    mock_provider = Mock(spec=MicrosoftEntraIDProvider)
    mock_provider.exchange_code_for_tokens = AsyncMock(
        return_value={
            "access_token": "entra_token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "id_token": "entra_id"
        }
    )
    
    redis = fakeredis.aioredis.FakeRedis()
    
    result = await entra_callback(
        code="entra_code",
        state="entra_state",
        provider=mock_provider,
        redis_client=redis
    )
    
    assert result.access_token == "entra_token"


# ==================== Middleware Dispatch ====================


@pytest.mark.asyncio
async def test_middleware_missing_auth_header():
    """Test middleware rejects requests without Authorization (lines 53-57)."""
    from eva_auth.middleware.auth_middleware import AuthMiddleware
    from fastapi import Request, HTTPException
    
    middleware = AuthMiddleware(app=Mock())
    
    mock_request = Mock(spec=Request)
    mock_request.url.path = "/api/protected"
    mock_request.headers.get = Mock(return_value=None)
    
    with pytest.raises(HTTPException) as exc:
        await middleware.dispatch(mock_request, AsyncMock())
    
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_middleware_invalid_bearer():
    """Test middleware rejects invalid Bearer format (lines 53-57)."""
    from eva_auth.middleware.auth_middleware import AuthMiddleware
    from fastapi import Request, HTTPException
    
    middleware = AuthMiddleware(app=Mock())
    
    mock_request = Mock(spec=Request)
    mock_request.url.path = "/api/protected"
    mock_request.headers.get = Mock(return_value="InvalidFormat token")
    
    with pytest.raises(HTTPException) as exc:
        await middleware.dispatch(mock_request, AsyncMock())
    
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_middleware_validation_error():
    """Test middleware handles ValidationError (lines 67-72)."""
    from eva_auth.middleware.auth_middleware import AuthMiddleware
    from eva_auth.models import ValidationError
    from fastapi import Request, HTTPException
    
    mock_validator = Mock()
    mock_validator.validate_token = AsyncMock(
        side_effect=ValidationError(message="Token expired", error_code="TOKEN_EXPIRED")
    )
    
    middleware = AuthMiddleware(app=Mock(), validator=mock_validator)
    
    mock_request = Mock(spec=Request)
    mock_request.url.path = "/api/protected"
    mock_request.headers.get = Mock(return_value="Bearer expired_token")
    
    with pytest.raises(HTTPException) as exc:
        await middleware.dispatch(mock_request, AsyncMock())
    
    assert exc.value.status_code == 401
    assert "Token expired" in exc.value.detail


@pytest.mark.asyncio
async def test_middleware_generic_exception():
    """Test middleware handles generic exceptions (lines 73-77)."""
    from eva_auth.middleware.auth_middleware import AuthMiddleware
    from fastapi import Request, HTTPException
    
    mock_validator = Mock()
    mock_validator.validate_token = AsyncMock(
        side_effect=Exception("Unexpected error")
    )
    
    middleware = AuthMiddleware(app=Mock(), validator=mock_validator)
    
    mock_request = Mock(spec=Request)
    mock_request.url.path = "/api/protected"
    mock_request.headers.get = Mock(return_value="Bearer token123")
    
    with pytest.raises(HTTPException) as exc:
        await middleware.dispatch(mock_request, AsyncMock())
    
    assert exc.value.status_code == 401
    assert "validation failed" in exc.value.detail.lower()


@pytest.mark.asyncio
async def test_middleware_successful_token():
    """Test middleware validates and passes through valid tokens (lines 64-80)."""
    from eva_auth.middleware.auth_middleware import AuthMiddleware
    from eva_auth.testing.mock_auth import MockAuthProvider
    from fastapi import Request
    from fastapi.responses import JSONResponse
    
    # Use real MockAuthProvider for authentic token
    mock_provider = MockAuthProvider()
    token = mock_provider.generate_token()
    
    middleware = AuthMiddleware(app=Mock())
    
    mock_request = Mock(spec=Request)
    mock_request.url.path = "/api/protected"
    mock_request.headers.get = Mock(return_value=f"Bearer {token}")
    mock_request.state = Mock()
    
    mock_response = JSONResponse(content={"status": "ok"})
    mock_call_next = AsyncMock(return_value=mock_response)
    
    response = await middleware.dispatch(mock_request, mock_call_next)
    
    # Should have set user on request state
    assert hasattr(mock_request.state, 'user')
    assert response == mock_response

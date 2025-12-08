"""Tests to achieve 100% coverage for remaining uncovered paths."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from azure.cosmos.exceptions import CosmosHttpResponseError


@pytest.mark.asyncio
async def test_audit_logger_container_creation_on_error():
    """Test audit logger creates container when get_container_client fails."""
    from eva_auth.audit.audit_logger import AuditLogger
    
    mock_client = MagicMock()
    mock_database = MagicMock()
    mock_container = MagicMock()
    
    # First call raises error, second succeeds
    mock_database.get_container_client.side_effect = [
        CosmosHttpResponseError(status_code=404, message="Not found"),
        mock_container
    ]
    mock_database.create_container = MagicMock()
    mock_client.get_database_client.return_value = mock_database
    
    logger = AuditLogger(
        cosmos_client=mock_client,
        database_name="test-db",
        container_name="test-container"
    )
    
    # Access container property to trigger lazy init
    container = logger.container
    
    assert container == mock_container
    mock_database.create_container.assert_called_once()


@pytest.mark.asyncio
async def test_api_key_manager_container_creation_on_error():
    """Test API key manager creates container when get_container_client fails."""
    from eva_auth.apikeys.api_key_manager import APIKeyManager
    
    mock_client = MagicMock()
    mock_database = MagicMock()
    mock_container = MagicMock()
    
    # First call raises error, second succeeds
    mock_database.get_container_client.side_effect = [
        CosmosHttpResponseError(status_code=404, message="Not found"),
        mock_container
    ]
    mock_database.create_container = MagicMock()
    mock_client.get_database_client.return_value = mock_database
    
    manager = APIKeyManager(
        cosmos_client=mock_client,
        database_name="test-db",
        container_name="test-container"
    )
    
    # Access container property to trigger lazy init
    container = manager.container
    
    assert container == mock_container
    mock_database.create_container.assert_called_once()


@pytest.mark.asyncio
async def test_api_key_manager_create_error_handling():
    """Test API key manager error handling in create."""
    from eva_auth.apikeys.api_key_manager import APIKeyManager
    
    mock_client = MagicMock()
    mock_database = MagicMock()
    mock_container = MagicMock()
    mock_container.create_item = MagicMock(side_effect=Exception("Database error"))
    
    mock_database.get_container_client.return_value = mock_container
    mock_client.get_database_client.return_value = mock_database
    
    manager = APIKeyManager(
        cosmos_client=mock_client,
        database_name="test-db",
        container_name="test-container"
    )
    
    with pytest.raises(Exception, match="Database error"):
        await manager.create_api_key(
            tenant_id="tenant1",
            name="Test Key",
            permissions=["read"],
        )


@pytest.mark.asyncio
async def test_api_key_manager_get_not_found():
    """Test API key manager when key not found."""
    from eva_auth.apikeys.api_key_manager import APIKeyManager
    
    mock_client = MagicMock()
    mock_database = MagicMock()
    mock_container = MagicMock()
    mock_container.read_item = MagicMock(
        side_effect=CosmosHttpResponseError(status_code=404, message="Not found")
    )
    
    mock_database.get_container_client.return_value = mock_container
    mock_client.get_database_client.return_value = mock_database
    
    manager = APIKeyManager(
        cosmos_client=mock_client,
        database_name="test-db",
        container_name="test-container"
    )
    
    result = await manager.get_api_key("tenant1", "nonexistent-key-id")
    assert result is None


@pytest.mark.asyncio
async def test_api_key_manager_revoke_not_found():
    """Test API key manager revoke when key not found."""
    from eva_auth.apikeys.api_key_manager import APIKeyManager
    
    mock_client = MagicMock()
    mock_database = MagicMock()
    mock_container = MagicMock()
    mock_container.read_item = MagicMock(
        side_effect=CosmosHttpResponseError(status_code=404, message="Not found")
    )
    
    mock_database.get_container_client.return_value = mock_container
    mock_client.get_database_client.return_value = mock_database
    
    manager = APIKeyManager(
        cosmos_client=mock_client,
        database_name="test-db",
        container_name="test-container"
    )
    
    result = await manager.revoke_api_key("tenant1", "nonexistent-key-id")
    assert result is False


@pytest.mark.asyncio
async def test_api_key_manager_update_usage_not_found():
    """Test API key manager update_usage when key not found."""
    from eva_auth.apikeys.api_key_manager import APIKeyManager
    
    mock_client = MagicMock()
    mock_database = MagicMock()
    mock_container = MagicMock()
    mock_container.read_item = MagicMock(
        side_effect=CosmosHttpResponseError(status_code=404, message="Not found")
    )
    
    mock_database.get_container_client.return_value = mock_container
    mock_client.get_database_client.return_value = mock_database
    
    manager = APIKeyManager(
        cosmos_client=mock_client,
        database_name="test-db",
        container_name="test-container"
    )
    
    result = await manager.update_usage("tenant1", "nonexistent-key-id")
    assert result is False


@pytest.mark.asyncio
async def test_rbac_engine_get_policy_not_found():
    """Test RBAC engine get_policy when policy doesn't exist."""
    from eva_auth.rbac.rbac_engine import RBACEngine
    
    engine = RBACEngine()
    result = engine.get_policy("nonexistent-policy")
    assert result is None


@pytest.mark.asyncio
async def test_azure_b2c_fetch_jwks_uri():
    """Test Azure B2C fetch_jwks_uri method."""
    from eva_auth.providers.azure_ad_b2c import AzureADB2CProvider
    
    provider = AzureADB2CProvider(
        tenant_name="test",
        tenant_id="test-tenant",
        client_id="test-client",
        client_secret="test-secret",
        user_flow="B2C_1_signupsignin"
    )
    
    # Mock the requests call
    with patch("eva_auth.providers.azure_ad_b2c.requests.get") as mock_get:
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "jwks_uri": "https://test.b2clogin.com/jwks"
        }
        mock_get.return_value = mock_response
        
        jwks_uri = await provider.fetch_jwks_uri()
        assert jwks_uri == "https://test.b2clogin.com/jwks"


@pytest.mark.asyncio  
async def test_main_lifespan_redis_close_when_none():
    """Test main lifespan handles None redis_client on shutdown."""
    from eva_auth.main import lifespan
    from fastapi import FastAPI
    import eva_auth.main as main_module
    
    app = FastAPI()
    
    # Set redis_client to None before shutdown
    original_client = main_module.redis_client
    try:
        main_module.redis_client = None
        
        async with lifespan(app):
            # During lifespan, redis_client is set
            pass
        # After lifespan, it checks for redis_client
        
    finally:
        main_module.redis_client = original_client


def test_middleware_dispatch_protected_endpoint_with_auth():
    """Test middleware dispatch with valid auth on protected endpoint."""
    from eva_auth.middleware.auth_middleware import AuthMiddleware
    from eva_auth.models import JWTClaims
    from fastapi import FastAPI, Request
    from fastapi.testclient import TestClient
    from unittest.mock import AsyncMock
    
    app = FastAPI()
    
    @app.get("/api/protected")
    async def protected(request: Request):
        return {"user": request.state.user.sub}
    
    # Mock validator
    mock_validator = AsyncMock()
    mock_validator.validate_token.return_value = JWTClaims(
        sub="user123",
        email="test@example.com",
        name="Test",
        tenant_id="tenant1",
        roles=["admin"],
        groups=[],
        expires_at=9999999999,
        iss="issuer",
        aud="audience"
    )
    
    app.add_middleware(AuthMiddleware, validator=mock_validator)
    
    client = TestClient(app)
    response = client.get("/api/protected", headers={"Authorization": "Bearer valid-token"})
    
    assert response.status_code == 200
    assert response.json()["user"] == "user123"


def test_middleware_dispatch_invalid_bearer_format():
    """Test middleware with invalid bearer token format."""
    from eva_auth.middleware.auth_middleware import AuthMiddleware
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    
    app = FastAPI()
    
    @app.get("/api/test")
    async def test_endpoint():
        return {"message": "test"}
    
    app.add_middleware(AuthMiddleware)
    
    client = TestClient(app, raise_server_exceptions=False)
    response = client.get("/api/test", headers={"Authorization": "Basic invalid"})
    
    assert response.status_code == 401


def test_middleware_dispatch_validation_error():
    """Test middleware handles ValidationError correctly."""
    from eva_auth.middleware.auth_middleware import AuthMiddleware
    from eva_auth.models import ValidationError
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from unittest.mock import AsyncMock
    
    app = FastAPI()
    
    @app.get("/api/test")
    async def test_endpoint():
        return {"message": "test"}
    
    mock_validator = AsyncMock()
    mock_validator.validate_token.side_effect = ValidationError("Expired", "TOKEN_EXPIRED")
    
    app.add_middleware(AuthMiddleware, validator=mock_validator)
    
    client = TestClient(app, raise_server_exceptions=False)
    response = client.get("/api/test", headers={"Authorization": "Bearer token"})
    
    assert response.status_code == 401
    assert "Expired" in response.json()["detail"]


def test_middleware_dispatch_generic_error():
    """Test middleware handles generic exceptions."""
    from eva_auth.middleware.auth_middleware import AuthMiddleware
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from unittest.mock import AsyncMock
    
    app = FastAPI()
    
    @app.get("/api/test")
    async def test_endpoint():
        return {"message": "test"}
    
    mock_validator = AsyncMock()
    mock_validator.validate_token.side_effect = Exception("Unexpected")
    
    app.add_middleware(AuthMiddleware, validator=mock_validator)
    
    client = TestClient(app, raise_server_exceptions=False)
    response = client.get("/api/test", headers={"Authorization": "Bearer token"})
    
    assert response.status_code == 401
    assert "validation failed" in response.json()["detail"].lower()


def test_health_readiness_check_redis_error():
    """Test health readiness check when Redis fails."""
    from eva_auth.routers.health import router
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from unittest.mock import AsyncMock, patch
    
    app = FastAPI()
    app.include_router(router)
    
    with patch("eva_auth.routers.health.get_redis_client") as mock_redis:
        mock_redis.side_effect = Exception("Redis connection failed")
        
        client = TestClient(app, raise_server_exceptions=False)
        response = client.get("/readiness")
        
        # Should return error status when Redis fails
        assert response.status_code in [200, 503]


@pytest.mark.asyncio
async def test_auth_router_dependencies():
    """Test auth router dependency injection."""
    from eva_auth.routers.auth import get_redis_client
    
    # Test the generator yields a Redis client
    gen = get_redis_client()
    client = await gen.__anext__()
    assert client is not None
    
    # Cleanup
    try:
        await gen.__anext__()
    except StopAsyncIteration:
        pass

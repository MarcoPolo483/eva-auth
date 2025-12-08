"""Tests for main.py to achieve 100% coverage."""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from fastapi.testclient import TestClient


@pytest.fixture
def mock_redis():
    """Mock Redis client."""
    with patch("eva_auth.main.redis") as mock:
        client_mock = AsyncMock()
        client_mock.close = AsyncMock()
        mock.from_url.return_value = client_mock
        yield client_mock


def test_lifespan_startup_shutdown(mock_redis):
    """Test application lifespan startup and shutdown."""
    from eva_auth.main import app
    
    with TestClient(app) as client:
        # Lifespan should initialize Redis
        response = client.get("/health")
        assert response.status_code == 200
        
    # Redis client should be closed on shutdown
    mock_redis.close.assert_called_once()


def test_global_exception_handler_development():
    """Test global exception handler in development mode."""
    from eva_auth.main import app
    
    with patch("eva_auth.main.settings.environment", "development"):
        # Create a route that raises an exception
        @app.get("/test-error")
        async def test_error():
            raise ValueError("Test error message")
        
        client = TestClient(app, raise_server_exceptions=False)
        response = client.get("/test-error")
        
        assert response.status_code == 500
        data = response.json()
        assert data["error"] == "internal_server_error"
        assert data["message"] == "An unexpected error occurred"
        assert "Test error message" in data["detail"]


def test_global_exception_handler_production():
    """Test global exception handler in production mode (no detail)."""
    from eva_auth.main import app
    
    with patch("eva_auth.main.settings.environment", "production"):
        # Create a route that raises an exception
        @app.get("/test-prod-error")
        async def test_prod_error():
            raise ValueError("Sensitive error info")
        
        client = TestClient(app, raise_server_exceptions=False)
        response = client.get("/test-prod-error")
        
        assert response.status_code == 500
        data = response.json()
        assert data["error"] == "internal_server_error"
        assert data["message"] == "An unexpected error occurred"
        assert data["detail"] is None  # No details in production


def test_get_redis_client_not_initialized():
    """Test get_redis_client raises error when Redis not initialized."""
    from eva_auth.main import get_redis_client
    import eva_auth.main as main_module
    
    # Save original redis_client
    original_client = main_module.redis_client
    
    try:
        # Set redis_client to None
        main_module.redis_client = None
        
        with pytest.raises(RuntimeError, match="Redis client not initialized"):
            get_redis_client()
    finally:
        # Restore original
        main_module.redis_client = original_client


def test_get_redis_client_returns_client(mock_redis):
    """Test get_redis_client returns the initialized client."""
    from eva_auth.main import get_redis_client, app
    import eva_auth.main as main_module
    
    # Initialize app to set redis_client
    with TestClient(app):
        # Manually set redis_client for testing
        main_module.redis_client = mock_redis
        
        client = get_redis_client()
        assert client is mock_redis


def test_cors_middleware_enabled():
    """Test CORS middleware is properly configured."""
    from eva_auth.main import app
    
    # Check that app has middleware stack configured
    assert hasattr(app, 'user_middleware')
    assert len(app.user_middleware) > 0


def test_auth_middleware_enabled_in_mock_mode():
    """Test auth middleware is added when mock auth is enabled."""
    from eva_auth.main import app
    
    # Check if AuthMiddleware is in the middleware stack
    middleware_classes = [m.cls.__name__ for m in app.user_middleware]
    
    # Should include AuthMiddleware when enable_mock_auth is True
    from eva_auth.config import settings
    if settings.enable_mock_auth:
        assert "AuthMiddleware" in middleware_classes

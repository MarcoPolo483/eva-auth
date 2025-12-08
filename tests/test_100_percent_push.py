"""Push to 100% coverage - final remaining lines."""

import pytest
from unittest.mock import Mock, patch, AsyncMock


def test_main_app_without_mock_auth():
    """Test main app when mock auth is disabled (line 59)."""
    # Temporarily disable mock auth
    with patch("eva_auth.main.settings") as mock_settings:
        mock_settings.enable_mock_auth = False
        mock_settings.cors_origins = ["*"]
        mock_settings.environment = "development"
        
        # Re-import to apply settings
        import importlib
        import eva_auth.main
        importlib.reload(eva_auth.main)
        
        # Verify app exists
        from eva_auth.main import app
        assert app is not None
        
        # Restore original
        importlib.reload(eva_auth.main)


def test_azure_b2c_get_jwks_uri_returns_string():
    """Test get_jwks_uri returns correct URL format (line 124)."""
    from eva_auth.providers.azure_ad_b2c import AzureADB2CProvider
    
    provider = AzureADB2CProvider(
        tenant_name="mytenant",
        tenant_id="tenant-guid",
        client_id="client-id",
        client_secret="secret"
    )
    
    # Call the method to hit line 124
    uri = provider.get_jwks_uri()
    
    # Verify it's a string with correct format
    assert isinstance(uri, str)
    assert "mytenant.b2clogin.com" in uri
    assert "discovery/v2.0/keys" in uri


@pytest.mark.asyncio
async def test_auth_router_redis_dependency():
    """Test get_redis_client dependency (lines 22-35)."""
    import sys
    from unittest.mock import MagicMock
    
    # Mock redis.asyncio module
    mock_redis_module = MagicMock()
    mock_client = AsyncMock()
    mock_redis_module.from_url = Mock(return_value=mock_client)
    
    sys.modules['redis.asyncio'] = mock_redis_module
    
    try:
        # Now import after mocking
        from eva_auth.routers.auth import get_redis_client
        
        # Use the dependency
        async for client in get_redis_client():
            assert client == mock_client
        
        # Verify close was called
        mock_client.close.assert_called_once()
    finally:
        # Cleanup
        if 'redis.asyncio' in sys.modules:
            del sys.modules['redis.asyncio']


def test_get_b2c_provider_dependency():
    """Test get_b2c_provider creates provider (lines 46-55)."""
    from eva_auth.routers.auth import get_b2c_provider
    
    with patch("eva_auth.routers.auth.settings") as mock_settings:
        mock_settings.azure_b2c_tenant_name = "test_tenant"
        mock_settings.azure_b2c_tenant_id = "test_id"
        mock_settings.azure_b2c_client_id = "client_id"
        mock_settings.azure_b2c_client_secret = "secret"
        mock_settings.azure_b2c_user_flow = "B2C_1_signin"
        
        provider = get_b2c_provider()
        
        # Verify provider was created
        assert provider is not None
        assert provider.tenant_name == "test_tenant"


def test_get_entra_provider_dependency():
    """Test get_entra_provider creates provider (lines 59-68)."""
    from eva_auth.routers.auth import get_entra_provider
    
    with patch("eva_auth.routers.auth.settings") as mock_settings:
        mock_settings.azure_entra_tenant_id = "entra_tenant_id"
        mock_settings.azure_entra_client_id = "entra_client_id"
        mock_settings.azure_entra_client_secret = "entra_secret"
        
        provider = get_entra_provider()
        
        # Verify provider was created
        assert provider is not None
        assert provider.tenant_id == "entra_tenant_id"

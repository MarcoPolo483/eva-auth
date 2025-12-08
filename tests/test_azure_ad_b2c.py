"""Tests for Azure AD B2C provider."""

import pytest
from unittest.mock import AsyncMock, Mock, patch

from eva_auth.providers import AzureADB2CProvider


class TestAzureADB2CProvider:
    """Test suite for AzureADB2CProvider."""

    @pytest.fixture
    def provider(self):
        """Create provider instance."""
        return AzureADB2CProvider(
            tenant_name="test-tenant",
            tenant_id="test-tenant-id",
            client_id="test-client-id",
            client_secret="test-client-secret",
            user_flow="B2C_1_signin",
        )

    def test_provider_initialization(self, provider):
        """Test provider initialization."""
        assert provider.tenant_name == "test-tenant"
        assert provider.tenant_id == "test-tenant-id"
        assert provider.client_id == "test-client-id"
        assert provider.user_flow == "B2C_1_signin"

    def test_authority_url(self, provider):
        """Test authority URL construction."""
        expected = "https://test-tenant.b2clogin.com/test-tenant-id/B2C_1_signin"
        assert provider.authority == expected

    def test_token_endpoint(self, provider):
        """Test token endpoint URL."""
        expected = "https://test-tenant.b2clogin.com/test-tenant-id/B2C_1_signin/oauth2/v2.0/token"
        assert provider.token_endpoint == expected

    def test_authorization_endpoint(self, provider):
        """Test authorization endpoint URL."""
        expected = "https://test-tenant.b2clogin.com/test-tenant-id/B2C_1_signin/oauth2/v2.0/authorize"
        assert provider.authorization_endpoint == expected

    def test_jwks_uri(self, provider):
        """Test JWKS URI."""
        expected = "https://test-tenant.b2clogin.com/test-tenant-id/B2C_1_signin/discovery/v2.0/keys"
        assert provider.jwks_uri == expected

    @pytest.mark.asyncio
    async def test_get_authorization_url(self, provider):
        """Test authorization URL generation."""
        redirect_uri = "http://localhost:8000/auth/b2c/callback"
        state = "random-state-123"
        
        with patch.object(provider.client, 'create_authorization_url', return_value=("https://auth.url", state)):
            url, returned_state = await provider.get_authorization_url(redirect_uri, state)
            
            assert isinstance(url, str)
            assert returned_state == state

    @pytest.mark.asyncio
    async def test_get_authorization_url_with_default_scope(self, provider):
        """Test authorization URL with default scope."""
        redirect_uri = "http://localhost:8000/auth/b2c/callback"
        state = "random-state-123"
        
        with patch.object(provider.client, 'create_authorization_url', return_value=("https://auth.url", state)) as mock:
            await provider.get_authorization_url(redirect_uri, state)
            
            # Verify default scope was used
            mock.assert_called_once()
            call_kwargs = mock.call_args[1]
            assert call_kwargs['scope'] == "openid profile email offline_access"

    @pytest.mark.asyncio
    async def test_exchange_code_for_tokens(self, provider):
        """Test code exchange for tokens."""
        code = "auth-code-123"
        redirect_uri = "http://localhost:8000/auth/b2c/callback"
        
        mock_tokens = {
            "access_token": "access-token-abc",
            "id_token": "id-token-def",
            "refresh_token": "refresh-token-ghi",
            "expires_in": 3600,
        }
        
        with patch.object(provider.client, 'fetch_token', return_value=mock_tokens) as mock:
            tokens = await provider.exchange_code_for_tokens(code, redirect_uri)
            
            assert tokens["access_token"] == "access-token-abc"
            assert tokens["id_token"] == "id-token-def"
            assert tokens["refresh_token"] == "refresh-token-ghi"
            
            mock.assert_called_once()

    @pytest.mark.asyncio
    async def test_refresh_access_token(self, provider):
        """Test token refresh."""
        refresh_token = "refresh-token-xyz"
        
        mock_tokens = {
            "access_token": "new-access-token",
            "id_token": "new-id-token",
            "expires_in": 3600,
        }
        
        with patch.object(provider.client, 'fetch_token', return_value=mock_tokens) as mock:
            tokens = await provider.refresh_access_token(refresh_token)
            
            assert tokens["access_token"] == "new-access-token"
            mock.assert_called_once()

    def test_get_issuer(self, provider):
        """Test getting issuer URL."""
        issuer = provider.get_issuer()
        assert issuer == provider.authority

    def test_get_jwks_uri_method(self, provider):
        """Test getting JWKS URI."""
        jwks_uri = provider.get_jwks_uri()
        assert jwks_uri == provider.jwks_uri

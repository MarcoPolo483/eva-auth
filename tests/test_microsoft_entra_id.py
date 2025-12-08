"""Tests for Microsoft Entra ID provider."""

import pytest
from unittest.mock import AsyncMock, Mock, patch

from eva_auth.providers import MicrosoftEntraIDProvider


class TestMicrosoftEntraIDProvider:
    """Test suite for MicrosoftEntraIDProvider."""

    @pytest.fixture
    def provider(self):
        """Create provider instance."""
        return MicrosoftEntraIDProvider(
            tenant_id="test-tenant-id",
            client_id="test-client-id",
            client_secret="test-client-secret",
        )

    def test_provider_initialization(self, provider):
        """Test provider initialization."""
        assert provider.tenant_id == "test-tenant-id"
        assert provider.client_id == "test-client-id"
        assert provider.client_secret == "test-client-secret"

    def test_authority_url(self, provider):
        """Test authority URL construction."""
        expected = "https://login.microsoftonline.com/test-tenant-id"
        assert provider.authority == expected

    def test_token_endpoint(self, provider):
        """Test token endpoint URL."""
        expected = "https://login.microsoftonline.com/test-tenant-id/oauth2/v2.0/token"
        assert provider.token_endpoint == expected

    def test_authorization_endpoint(self, provider):
        """Test authorization endpoint URL."""
        expected = "https://login.microsoftonline.com/test-tenant-id/oauth2/v2.0/authorize"
        assert provider.authorization_endpoint == expected

    def test_jwks_uri(self, provider):
        """Test JWKS URI."""
        expected = "https://login.microsoftonline.com/test-tenant-id/discovery/v2.0/keys"
        assert provider.jwks_uri == expected

    @pytest.mark.asyncio
    async def test_get_authorization_url(self, provider):
        """Test authorization URL generation."""
        redirect_uri = "http://localhost:8000/auth/entra/callback"
        state = "random-state-456"
        
        with patch.object(provider.client, 'create_authorization_url', return_value=("https://auth.url", state)):
            url, returned_state = await provider.get_authorization_url(redirect_uri, state)
            
            assert isinstance(url, str)
            assert returned_state == state

    @pytest.mark.asyncio
    async def test_get_authorization_url_with_default_scope(self, provider):
        """Test authorization URL with default scope."""
        redirect_uri = "http://localhost:8000/auth/entra/callback"
        state = "random-state-456"
        
        with patch.object(provider.client, 'create_authorization_url', return_value=("https://auth.url", state)) as mock:
            await provider.get_authorization_url(redirect_uri, state)
            
            # Verify default scope was used
            mock.assert_called_once()
            call_kwargs = mock.call_args[1]
            assert call_kwargs['scope'] == "openid profile email User.Read offline_access"

    @pytest.mark.asyncio
    async def test_exchange_code_for_tokens(self, provider):
        """Test code exchange for tokens."""
        code = "auth-code-456"
        redirect_uri = "http://localhost:8000/auth/entra/callback"
        
        mock_tokens = {
            "access_token": "access-token-jkl",
            "id_token": "id-token-mno",
            "refresh_token": "refresh-token-pqr",
            "expires_in": 3600,
        }
        
        with patch.object(provider.client, 'fetch_token', return_value=mock_tokens) as mock:
            tokens = await provider.exchange_code_for_tokens(code, redirect_uri)
            
            assert tokens["access_token"] == "access-token-jkl"
            assert tokens["id_token"] == "id-token-mno"
            assert tokens["refresh_token"] == "refresh-token-pqr"
            
            mock.assert_called_once()

    @pytest.mark.asyncio
    async def test_refresh_access_token(self, provider):
        """Test token refresh."""
        refresh_token = "refresh-token-stu"
        
        mock_tokens = {
            "access_token": "new-access-token-entra",
            "id_token": "new-id-token-entra",
            "expires_in": 3600,
        }
        
        with patch.object(provider.client, 'fetch_token', return_value=mock_tokens) as mock:
            tokens = await provider.refresh_access_token(refresh_token)
            
            assert tokens["access_token"] == "new-access-token-entra"
            mock.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_user_groups(self, provider):
        """Test getting user groups from Microsoft Graph."""
        access_token = "access-token-graph"
        
        mock_response = {
            "value": [
                {"@odata.type": "#microsoft.graph.group", "displayName": "Group1"},
                {"@odata.type": "#microsoft.graph.group", "displayName": "Group2"},
                {"@odata.type": "#microsoft.graph.user", "displayName": "NotAGroup"},
            ]
        }
        
        with patch('httpx.AsyncClient') as mock_client:
            mock_get = AsyncMock(return_value=Mock(
                json=Mock(return_value=mock_response),
                raise_for_status=Mock()
            ))
            mock_client.return_value.__aenter__.return_value.get = mock_get
            
            groups = await provider.get_user_groups(access_token)
            
            assert len(groups) == 2
            assert "Group1" in groups
            assert "Group2" in groups
            assert "NotAGroup" not in groups

    def test_map_groups_to_roles_admin(self, provider):
        """Test mapping admin group to roles."""
        groups = ["EVA-Admins", "Other-Group"]
        roles = provider.map_groups_to_roles(groups)
        
        assert "eva:admin" in roles
        assert "eva:user" in roles

    def test_map_groups_to_roles_analyst(self, provider):
        """Test mapping analyst group to roles."""
        groups = ["EVA-Analysts"]
        roles = provider.map_groups_to_roles(groups)
        
        assert "eva:analyst" in roles
        assert "eva:user" in roles
        assert "eva:admin" not in roles

    def test_map_groups_to_roles_viewer(self, provider):
        """Test mapping viewer group to roles."""
        groups = ["EVA-Viewers"]
        roles = provider.map_groups_to_roles(groups)
        
        assert "eva:viewer" in roles
        assert "eva:user" in roles

    def test_map_groups_to_roles_default(self, provider):
        """Test default role for unrecognized groups."""
        groups = ["Unknown-Group", "Another-Unknown-Group"]
        roles = provider.map_groups_to_roles(groups)
        
        assert roles == ["eva:user"]

    def test_map_groups_to_roles_multiple(self, provider):
        """Test mapping multiple groups."""
        groups = ["EVA-Admins", "EVA-Analysts"]
        roles = provider.map_groups_to_roles(groups)
        
        # Should have unique roles from both groups
        assert "eva:admin" in roles
        assert "eva:analyst" in roles
        assert "eva:user" in roles

    def test_get_issuer(self, provider):
        """Test getting issuer URL."""
        issuer = provider.get_issuer()
        assert issuer == "https://login.microsoftonline.com/test-tenant-id/v2.0"

    def test_get_jwks_uri_method(self, provider):
        """Test getting JWKS URI."""
        jwks_uri = provider.get_jwks_uri()
        assert jwks_uri == provider.jwks_uri

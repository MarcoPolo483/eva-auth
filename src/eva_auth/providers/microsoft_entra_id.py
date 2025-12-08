"""Microsoft Entra ID OAuth provider."""

from typing import Optional

import httpx
from authlib.integrations.httpx_client import AsyncOAuth2Client

from eva_auth.models import JWTClaims


class MicrosoftEntraIDProvider:
    """OAuth 2.0 provider for Microsoft Entra ID (formerly Azure AD)."""

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
    ):
        """Initialize Microsoft Entra ID provider.
        
        Args:
            tenant_id: Entra ID tenant ID or domain
            client_id: Application (client) ID
            client_secret: Client secret
        """
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        
        # Build authority URL
        self.authority = f"https://login.microsoftonline.com/{tenant_id}"
        
        # OAuth endpoints
        self.token_endpoint = f"{self.authority}/oauth2/v2.0/token"
        self.authorization_endpoint = f"{self.authority}/oauth2/v2.0/authorize"
        self.jwks_uri = f"{self.authority}/discovery/v2.0/keys"
        
        # Microsoft Graph API
        self.graph_api_base = "https://graph.microsoft.com/v1.0"
        
        # OAuth client
        self.client = AsyncOAuth2Client(
            client_id=client_id,
            client_secret=client_secret,
            token_endpoint=self.token_endpoint,
        )

    async def get_authorization_url(
        self, redirect_uri: str, state: str, scope: Optional[str] = None
    ) -> tuple[str, str]:
        """Generate OAuth authorization URL.
        
        Args:
            redirect_uri: Callback URL after authentication
            state: Random state parameter for CSRF protection
            scope: OAuth scopes (default: "openid profile email User.Read offline_access")
            
        Returns:
            Tuple of (authorization_url, state)
        """
        if scope is None:
            scope = "openid profile email User.Read offline_access"
            
        url, state = self.client.create_authorization_url(
            self.authorization_endpoint,
            redirect_uri=redirect_uri,
            scope=scope,
            state=state,
        )
        return url, state

    async def exchange_code_for_tokens(
        self, code: str, redirect_uri: str
    ) -> dict[str, str]:
        """Exchange authorization code for tokens.
        
        Args:
            code: Authorization code from callback
            redirect_uri: Callback URL (must match authorization request)
            
        Returns:
            Dictionary with access_token, id_token, refresh_token, etc.
        """
        # Note: authlib OAuth2 client operations are sync, not async
        token = self.client.fetch_token(
            self.token_endpoint,
            grant_type="authorization_code",
            code=code,
            redirect_uri=redirect_uri,
        )
        return token

    async def refresh_access_token(self, refresh_token: str) -> dict[str, str]:
        """Refresh access token using refresh token.
        
        Args:
            refresh_token: Refresh token from previous authentication
            
        Returns:
            Dictionary with new access_token, id_token, etc.
        """
        # Note: authlib OAuth2 client operations are sync, not async
        token = self.client.fetch_token(
            self.token_endpoint,
            grant_type="refresh_token",
            refresh_token=refresh_token,
        )
        return token

    async def get_user_groups(self, access_token: str) -> list[str]:
        """Get user's group memberships via Microsoft Graph API.
        
        Args:
            access_token: Valid access token with User.Read scope
            
        Returns:
            List of group display names
        """
        url = f"{self.graph_api_base}/me/memberOf"
        headers = {"Authorization": f"Bearer {access_token}"}
        
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers)
            response.raise_for_status()
            data = response.json()
            
            groups = []
            for item in data.get("value", []):
                if item.get("@odata.type") == "#microsoft.graph.group":
                    groups.append(item.get("displayName", ""))
            
            return [g for g in groups if g]

    def map_groups_to_roles(self, groups: list[str]) -> list[str]:
        """Map Entra ID groups to EVA roles.
        
        Args:
            groups: List of group display names
            
        Returns:
            List of EVA roles
        """
        role_mapping = {
            "EVA-Admins": ["eva:admin", "eva:user"],
            "EVA-Analysts": ["eva:analyst", "eva:user"],
            "EVA-Viewers": ["eva:viewer", "eva:user"],
        }
        
        roles = set()
        for group in groups:
            if group in role_mapping:
                roles.update(role_mapping[group])
        
        # Default role if no groups matched
        return list(roles) if roles else ["eva:user"]

    def get_jwks_uri(self) -> str:
        """Get JWKS URI for token validation.
        
        Returns:
            JWKS endpoint URL
        """
        return self.jwks_uri

    def get_issuer(self) -> str:
        """Get expected token issuer.
        
        Returns:
            Issuer URL
        """
        return f"{self.authority}/v2.0"

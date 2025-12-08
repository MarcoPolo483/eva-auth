"""Azure AD B2C OAuth provider."""

from typing import Optional

import httpx
from authlib.integrations.httpx_client import AsyncOAuth2Client

from eva_auth.models import JWTClaims, UserClaims


class AzureADB2CProvider:
    """OAuth 2.0 provider for Azure AD B2C."""

    def __init__(
        self,
        tenant_name: str,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        user_flow: str = "B2C_1_signin",
    ):
        """Initialize Azure AD B2C provider.
        
        Args:
            tenant_name: B2C tenant name (e.g., "your-tenant")
            tenant_id: B2C tenant ID
            client_id: Application (client) ID
            client_secret: Client secret
            user_flow: User flow name (default: B2C_1_signin)
        """
        self.tenant_name = tenant_name
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.user_flow = user_flow
        
        # Build authority URL
        self.authority = (
            f"https://{tenant_name}.b2clogin.com/{tenant_id}/{user_flow}"
        )
        
        # OAuth endpoints
        self.token_endpoint = f"{self.authority}/oauth2/v2.0/token"
        self.authorization_endpoint = f"{self.authority}/oauth2/v2.0/authorize"
        self.jwks_uri = f"{self.authority}/discovery/v2.0/keys"
        
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
            scope: OAuth scopes (default: "openid profile email offline_access")
            
        Returns:
            Tuple of (authorization_url, state)
        """
        if scope is None:
            scope = "openid profile email offline_access"
            
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

    async def revoke_token(self, token: str) -> None:
        """Revoke access or refresh token.
        
        Args:
            token: Token to revoke
        """
        # Azure AD B2C doesn't have a standard revoke endpoint
        # Token revocation is handled via session management
        pass

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
        return self.authority

"""Mock authentication provider for testing."""

import jwt

from eva_auth.models import JWTClaims, UserClaims


class MockAuthProvider:
    """Mock authentication provider for testing without Azure AD dependencies."""

    def __init__(self, secret: str = "test-secret-key-12345"):
        """Initialize mock provider.
        
        Args:
            secret: Secret key for signing tokens (HS256)
        """
        self.secret = secret
        self.algorithm = "HS256"

    def generate_token(
        self,
        user_id: str = "test-user-1234",
        email: str = "test@example.com",
        name: str = "Test User",
        tenant_id: str = "test-tenant-5678",
        roles: list[str] | None = None,
        groups: list[str] | None = None,
        expires_in: int = 3600,
    ) -> str:
        """Generate mock JWT token for testing.
        
        Args:
            user_id: User identifier
            email: User email address
            name: User full name
            tenant_id: Tenant identifier
            roles: User roles (defaults to ["eva:user"])
            groups: User groups (defaults to [])
            expires_in: Token expiration in seconds (default 1 hour)
            
        Returns:
            Signed JWT token string
        """
        if roles is None:
            roles = ["eva:user"]
        if groups is None:
            groups = []

        import time
        now = int(time.time())
        exp = now + expires_in

        payload = {
            "sub": user_id,
            "email": email,
            "name": name,
            "tid": tenant_id,
            "roles": roles,
            "groups": groups,
            "iss": "https://mock.auth.eva.ai",
            "aud": "mock-client-id",
            "exp": exp,
            "iat": now,
            "nbf": now,
        }

        return jwt.encode(payload, self.secret, algorithm=self.algorithm)

    def validate_token(self, token: str) -> JWTClaims:
        """Validate mock JWT token.
        
        Args:
            token: JWT token string
            
        Returns:
            Decoded JWT claims
            
        Raises:
            jwt.ExpiredSignatureError: If token is expired
            jwt.InvalidTokenError: If token is invalid
        """
        payload = jwt.decode(
            token,
            self.secret,
            algorithms=[self.algorithm],
            options={
                "verify_signature": True,
                "verify_exp": True,
                "verify_nbf": False,  # Don't verify nbf for mock tokens
                "verify_iat": False,  # Don't verify iat for mock tokens
                "verify_aud": False,  # Don't verify aud for mock tokens
            },
        )

        return JWTClaims(
            sub=payload["sub"],
            email=payload.get("email"),
            name=payload.get("name"),
            tenant_id=payload["tid"],
            roles=payload.get("roles", ["eva:user"]),
            groups=payload.get("groups", []),
            expires_at=payload["exp"],
            iss=payload.get("iss"),
            aud=payload.get("aud"),
        )

    def generate_expired_token(
        self,
        user_id: str = "test-user-1234",
        email: str = "test@example.com",
        tenant_id: str = "test-tenant-5678",
    ) -> str:
        """Generate expired token for testing.
        
        Args:
            user_id: User identifier
            email: User email address
            tenant_id: Tenant identifier
            
        Returns:
            Expired JWT token string
        """
        return self.generate_token(
            user_id=user_id,
            email=email,
            tenant_id=tenant_id,
            expires_in=-3600,  # Expired 1 hour ago
        )

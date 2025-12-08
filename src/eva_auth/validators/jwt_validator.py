"""JWT token validator."""

import jwt
from jwt import PyJWKClient
from typing import Any

from eva_auth.models import JWTClaims, ValidationError


class JWTValidator:
    """Validates JWT tokens from Azure AD B2C/Entra ID."""

    def __init__(
        self,
        jwks_uri: str,
        issuer: str,
        audience: str,
        algorithms: list[str] | None = None,
    ):
        """Initialize JWT validator.
        
        Args:
            jwks_uri: JWKS endpoint URL for fetching public keys
            issuer: Expected token issuer
            audience: Expected token audience (client ID)
            algorithms: Allowed signing algorithms (default: ["RS256"])
        """
        self.jwks_uri = jwks_uri
        self.issuer = issuer
        self.audience = audience
        self.algorithms = algorithms or ["RS256"]
        self.jwks_client = PyJWKClient(jwks_uri, cache_keys=True, max_cached_keys=16)

    async def validate_token(self, token: str) -> JWTClaims:
        """Validate JWT token and return claims.
        
        Args:
            token: JWT token string
            
        Returns:
            Decoded and validated JWT claims
            
        Raises:
            ValidationError: If token validation fails
        """
        try:
            # Get signing key from JWKS
            signing_key = self.jwks_client.get_signing_key_from_jwt(token)

            # Decode and validate token
            payload = jwt.decode(
                token,
                signing_key.key,
                algorithms=self.algorithms,
                issuer=self.issuer,
                audience=self.audience,
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_iat": True,
                    "verify_aud": True,
                    "verify_iss": True,
                },
            )

            return self._extract_claims(payload)

        except jwt.ExpiredSignatureError:
            raise ValidationError("Token has expired", error_code="TOKEN_EXPIRED")
        except jwt.InvalidAudienceError:
            raise ValidationError("Invalid audience", error_code="INVALID_AUDIENCE")
        except jwt.InvalidIssuerError:
            raise ValidationError("Invalid issuer", error_code="INVALID_ISSUER")
        except jwt.InvalidTokenError as e:
            raise ValidationError(f"Invalid token: {e}", error_code="INVALID_TOKEN")
        except Exception as e:
            raise ValidationError(f"Token validation failed: {e}", error_code="VALIDATION_FAILED")

    def _extract_claims(self, payload: dict[str, Any]) -> JWTClaims:
        """Extract claims from JWT payload.
        
        Args:
            payload: Decoded JWT payload
            
        Returns:
            Structured JWT claims
        """
        return JWTClaims(
            sub=payload["sub"],
            email=payload.get("email"),
            name=payload.get("name"),
            tenant_id=payload.get("tid", payload.get("tenant_id", "")),
            roles=payload.get("roles", ["eva:user"]),
            groups=payload.get("groups", []),
            expires_at=payload["exp"],
            iss=payload.get("iss"),
            aud=payload.get("aud"),
        )


class MockJWTValidator:
    """Mock JWT validator for testing (validates HS256 tokens)."""

    def __init__(self, secret: str = "test-secret-key-12345"):
        """Initialize mock validator.
        
        Args:
            secret: Secret key for validating HS256 tokens
        """
        self.secret = secret
        self.algorithm = "HS256"

    async def validate_token(self, token: str) -> JWTClaims:
        """Validate mock JWT token.
        
        Args:
            token: JWT token string
            
        Returns:
            Decoded JWT claims
            
        Raises:
            ValidationError: If token validation fails
        """
        try:
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
                tenant_id=payload.get("tid", ""),
                roles=payload.get("roles", ["eva:user"]),
                groups=payload.get("groups", []),
                expires_at=payload["exp"],
                iss=payload.get("iss"),
                aud=payload.get("aud"),
            )

        except jwt.ExpiredSignatureError:
            raise ValidationError("Token has expired", error_code="TOKEN_EXPIRED")
        except (jwt.InvalidTokenError, KeyError) as e:
            raise ValidationError(f"Invalid token: {e}", error_code="INVALID_TOKEN")

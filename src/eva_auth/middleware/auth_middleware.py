"""FastAPI authentication middleware."""

from fastapi import Request, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware

from eva_auth.config import settings
from eva_auth.validators import MockJWTValidator
from eva_auth.models import ValidationError


class AuthMiddleware(BaseHTTPMiddleware):
    """Middleware for authenticating requests via JWT tokens."""

    def __init__(self, app, validator=None):
        """Initialize authentication middleware.
        
        Args:
            app: FastAPI application
            validator: JWT validator instance (defaults to MockJWTValidator for dev)
        """
        super().__init__(app)
        self.validator = validator or MockJWTValidator(settings.mock_auth_secret)
        
        # Public endpoints that don't require authentication
        self.public_paths = [
            "/health",
            "/docs",
            "/redoc",
            "/openapi.json",
            "/auth/b2c/authorize",
            "/auth/b2c/callback",
            "/auth/entra/authorize",
            "/auth/entra/callback",
        ]

    async def dispatch(self, request: Request, call_next):
        """Process request and validate authentication.
        
        Args:
            request: Incoming HTTP request
            call_next: Next middleware/route handler
            
        Returns:
            HTTP response
        """
        # Skip authentication for public endpoints
        if any(request.url.path.startswith(path) for path in self.public_paths):
            return await call_next(request)

        # Extract Bearer token from Authorization header
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing or invalid Authorization header",
                headers={"WWW-Authenticate": "Bearer"},
            )

        token = auth_header[7:]  # Remove "Bearer " prefix

        # Validate JWT token
        try:
            claims = await self.validator.validate_token(token)
            request.state.user = claims
        except ValidationError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"{e.message} (code: {e.error_code})",
                headers={"WWW-Authenticate": "Bearer"},
            )
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Token validation failed: {str(e)}",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Continue to next middleware/route handler
        response = await call_next(request)
        return response

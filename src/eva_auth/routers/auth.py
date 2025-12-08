"""Authentication router."""

import secrets
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status, Header
from fastapi.responses import RedirectResponse

from eva_auth.config import settings
from eva_auth.models import TokenResponse, TokenValidationResponse
from eva_auth.providers import AzureADB2CProvider, MicrosoftEntraIDProvider
from eva_auth.session import SessionManager
from eva_auth.testing import MockAuthProvider
from eva_auth.validators import MockJWTValidator

router = APIRouter()


# Dependency for Redis client
async def get_redis_client():
    """Get Redis client from app state."""
    import redis.asyncio as redis
    from eva_auth.config import settings
    
    client = redis.from_url(
        settings.redis_url,
        password=settings.redis_password if settings.redis_password else None,
        db=settings.redis_db,
        encoding="utf-8",
        decode_responses=True,
    )
    try:
        yield client
    finally:
        await client.close()


# Initialize providers (lazy initialization in production)
def get_b2c_provider():
    """Get Azure AD B2C provider."""
    if not settings.azure_b2c_tenant_name:
        raise HTTPException(
            status_code=503,
            detail="Azure AD B2C not configured",
        )
    return AzureADB2CProvider(
        tenant_name=settings.azure_b2c_tenant_name,
        tenant_id=settings.azure_b2c_tenant_id,
        client_id=settings.azure_b2c_client_id,
        client_secret=settings.azure_b2c_client_secret,
        user_flow=settings.azure_b2c_user_flow,
    )


def get_entra_provider():
    """Get Microsoft Entra ID provider."""
    if not settings.azure_entra_tenant_id:
        raise HTTPException(
            status_code=503,
            detail="Microsoft Entra ID not configured",
        )
    return MicrosoftEntraIDProvider(
        tenant_id=settings.azure_entra_tenant_id,
        client_id=settings.azure_entra_client_id,
        client_secret=settings.azure_entra_client_secret,
    )


# Mock authentication endpoints (development only)
@router.post("/mock/token", include_in_schema=True)
async def mock_generate_token(
    user_id: str = "test-user-1234",
    email: str = "test@example.com",
    tenant_id: str = "test-tenant-5678",
    roles: list[str] | None = None,
):
    """Generate mock JWT token for testing (development only)."""
    
    if roles is None:
        roles = ["eva:user"]
    
    mock_provider = MockAuthProvider(settings.mock_auth_secret)
    token = mock_provider.generate_token(
        user_id=user_id,
        email=email,
        tenant_id=tenant_id,
        roles=roles,
    )
    
    return TokenResponse(
        access_token=token,
        token_type="Bearer",
        expires_in=3600,
    )


@router.post("/validate")
async def validate_token(
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
):
    """Validate JWT token and return claims."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid Authorization header",
        )
    
    token = authorization[7:]
    
    # Use mock validator in development
    validator = MockJWTValidator(settings.mock_auth_secret)
    
    try:
        claims = await validator.validate_token(token)
        return TokenValidationResponse(
            valid=True,
            claims=claims,
        )
    except Exception as e:
        return TokenValidationResponse(
            valid=False,
            error=str(e),
        )


# Azure AD B2C endpoints
@router.get("/b2c/authorize")
async def b2c_authorize(
    redirect_uri: str | None = None,
    provider: AzureADB2CProvider = Depends(get_b2c_provider),
):
    """Start Azure AD B2C OAuth flow."""
    redirect_uri = redirect_uri or settings.azure_b2c_redirect_uri
    state = secrets.token_urlsafe(32)
    
    auth_url, _ = await provider.get_authorization_url(
        redirect_uri=redirect_uri,
        state=state,
    )
    
    return {
        "authorization_url": auth_url,
        "state": state,
    }


@router.get("/b2c/callback")
async def b2c_callback(
    code: str,
    state: str,
    provider: AzureADB2CProvider = Depends(get_b2c_provider),
    redis_client=Depends(get_redis_client),
):
    """Handle Azure AD B2C OAuth callback."""
    # Exchange code for tokens
    tokens = await provider.exchange_code_for_tokens(
        code=code,
        redirect_uri=settings.azure_b2c_redirect_uri,
    )
    
    # Create session
    session_manager = SessionManager(redis_client)
    session_id = secrets.token_urlsafe(32)
    
    # TODO: Validate ID token and extract claims
    # For now, return tokens directly
    
    return TokenResponse(
        access_token=tokens.get("access_token", ""),
        token_type="Bearer",
        expires_in=tokens.get("expires_in", 3600),
        refresh_token=tokens.get("refresh_token"),
        id_token=tokens.get("id_token"),
    )


# Microsoft Entra ID endpoints
@router.get("/entra/authorize")
async def entra_authorize(
    redirect_uri: str | None = None,
    provider: MicrosoftEntraIDProvider = Depends(get_entra_provider),
):
    """Start Microsoft Entra ID OAuth flow."""
    redirect_uri = redirect_uri or settings.azure_entra_redirect_uri
    state = secrets.token_urlsafe(32)
    
    auth_url, _ = await provider.get_authorization_url(
        redirect_uri=redirect_uri,
        state=state,
    )
    
    return {
        "authorization_url": auth_url,
        "state": state,
    }


@router.get("/entra/callback")
async def entra_callback(
    code: str,
    state: str,
    provider: MicrosoftEntraIDProvider = Depends(get_entra_provider),
    redis_client=Depends(get_redis_client),
):
    """Handle Microsoft Entra ID OAuth callback."""
    # Exchange code for tokens
    tokens = await provider.exchange_code_for_tokens(
        code=code,
        redirect_uri=settings.azure_entra_redirect_uri,
    )
    
    # Create session
    session_manager = SessionManager(redis_client)
    session_id = secrets.token_urlsafe(32)
    
    # TODO: Validate ID token and extract claims
    # TODO: Fetch user groups from Microsoft Graph
    # For now, return tokens directly
    
    return TokenResponse(
        access_token=tokens.get("access_token", ""),
        token_type="Bearer",
        expires_in=tokens.get("expires_in", 3600),
        refresh_token=tokens.get("refresh_token"),
        id_token=tokens.get("id_token"),
    )

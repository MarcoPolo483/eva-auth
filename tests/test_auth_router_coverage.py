"""Tests for auth.py router to achieve 100% coverage."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient
from fakeredis import aioredis as fakeredis

from eva_auth.main import app


@pytest.fixture
async def fake_redis():
    """Create fake Redis client."""
    client = await fakeredis.FakeRedis()
    yield client
    await client.aclose()


def test_b2c_authorize_endpoint():
    """Test Azure AD B2C authorize endpoint."""
    # These endpoints require Azure credentials, so they return 503
    # This is expected behavior when not configured
    client = TestClient(app, raise_server_exceptions=False)
    response = client.get("/auth/b2c/authorize")
    assert response.status_code == 503
    assert "not configured" in response.json()["detail"]


def test_b2c_callback_endpoint():
    """Test Azure AD B2C callback endpoint."""
    # Callback also requires Azure credentials
    client = TestClient(app, raise_server_exceptions=False)
    response = client.get("/auth/b2c/callback?code=test-code&state=test-state")
    assert response.status_code == 503
    assert "not configured" in response.json()["detail"]


def test_entra_authorize_endpoint():
    """Test Microsoft Entra ID authorize endpoint."""
    # Entra endpoints also require Azure credentials
    client = TestClient(app, raise_server_exceptions=False)
    response = client.get("/auth/entra/authorize")
    assert response.status_code == 503
    assert "not configured" in response.json()["detail"]


def test_entra_callback_endpoint():
    """Test Microsoft Entra ID callback endpoint."""
    # Entra callback also requires Azure credentials
    client = TestClient(app, raise_server_exceptions=False)
    response = client.get("/auth/entra/callback?code=test-code&state=test-state")
    assert response.status_code == 503
    assert "not configured" in response.json()["detail"]


def test_get_b2c_provider_raises_error():
    """Test get_b2c_provider raises 503 when not configured."""
    from eva_auth.routers.auth import get_b2c_provider
    from eva_auth.config import settings
    
    # Without configuration, should raise HTTPException
    original_tenant = settings.azure_b2c_tenant_name
    try:
        settings.azure_b2c_tenant_name = None
        with pytest.raises(Exception):  # HTTPException
            get_b2c_provider()
    finally:
        settings.azure_b2c_tenant_name = original_tenant


def test_get_entra_provider_raises_error():
    """Test get_entra_provider raises 503 when not configured."""
    from eva_auth.routers.auth import get_entra_provider
    from eva_auth.config import settings
    
    # Without configuration, should raise HTTPException
    original_tenant = settings.azure_entra_tenant_id
    try:
        settings.azure_entra_tenant_id = None
        with pytest.raises(Exception):  # HTTPException
            get_entra_provider()
    finally:
        settings.azure_entra_tenant_id = original_tenant

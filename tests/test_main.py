"""Tests for FastAPI application."""

import pytest
from fastapi.testclient import TestClient

from eva_auth.main import app
from eva_auth.testing import MockAuthProvider


class TestMainApp:
    """Test suite for main FastAPI application."""

    @pytest.fixture
    def client(self):
        """Create test client."""
        return TestClient(app)

    @pytest.fixture
    def mock_provider(self):
        """Create mock auth provider."""
        return MockAuthProvider(secret="test-secret-key-12345")

    def test_health_endpoint(self, client):
        """Test health check endpoint."""
        response = client.get("/health")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["service"] == "eva-auth"

    def test_ready_endpoint(self, client):
        """Test readiness check endpoint."""
        response = client.get("/ready")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ready"

    def test_mock_token_generation(self, client):
        """Test mock token generation endpoint."""
        response = client.post(
            "/auth/mock/token",
            params={
                "user_id": "test-user",
                "email": "test@example.com",
                "tenant_id": "test-tenant",
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "Bearer"
        assert data["expires_in"] == 3600

    def test_validate_token_with_valid_token(self, client, mock_provider):
        """Test token validation with valid token."""
        token = mock_provider.generate_token()
        
        response = client.post(
            "/auth/validate",
            headers={"Authorization": f"Bearer {token}"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is True
        assert data["claims"] is not None

    def test_validate_token_with_expired_token(self, client, mock_provider):
        """Test token validation with expired token."""
        expired_token = mock_provider.generate_expired_token()
        
        response = client.post(
            "/auth/validate",
            headers={"Authorization": f"Bearer {expired_token}"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is False
        assert data["error"] is not None

    def test_validate_token_without_auth_header(self, client):
        """Test token validation without authorization header."""
        response = client.post("/auth/validate")
        
        assert response.status_code == 401

    def test_validate_token_with_malformed_header(self, client):
        """Test token validation with malformed authorization header."""
        response = client.post(
            "/auth/validate",
            headers={"Authorization": "NotBearer token"}
        )
        
        assert response.status_code == 401

    def test_b2c_authorize_without_config(self, client):
        """Test B2C authorize endpoint without configuration."""
        response = client.get("/auth/b2c/authorize")
        
        # Should return 503 if B2C is not configured
        assert response.status_code == 503

    def test_entra_authorize_without_config(self, client):
        """Test Entra authorize endpoint without configuration."""
        response = client.get("/auth/entra/authorize")
        
        # Should return 503 if Entra ID is not configured
        assert response.status_code == 503

    def test_openapi_docs(self, client):
        """Test OpenAPI documentation is accessible."""
        response = client.get("/docs")
        
        assert response.status_code == 200

    def test_openapi_schema(self, client):
        """Test OpenAPI schema is accessible."""
        response = client.get("/openapi.json")
        
        assert response.status_code == 200
        data = response.json()
        assert data["info"]["title"] == "EVA Authentication & Authorization Service"

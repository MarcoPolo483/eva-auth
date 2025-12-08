"""Tests for configuration settings."""

import pytest
import os
from eva_auth.config import Settings


class TestSettings:
    """Test suite for Settings."""

    def test_default_settings(self):
        """Test default settings values."""
        settings = Settings()
        
        assert settings.environment == "development"
        assert settings.jwt_algorithm == "RS256"
        assert settings.session_cookie_name == "eva_session_id"
        assert settings.session_cookie_httponly is True
        assert settings.session_cookie_secure is True

    def test_cors_origins_list(self):
        """Test CORS origins parsing."""
        settings = Settings(cors_origins="http://localhost:3000,http://localhost:8000")
        
        origins = settings.cors_origins_list
        assert len(origins) == 2
        assert "http://localhost:3000" in origins
        assert "http://localhost:8000" in origins

    def test_azure_b2c_authority(self):
        """Test Azure AD B2C authority URL."""
        settings = Settings(
            azure_b2c_tenant_name="test-tenant",
            azure_b2c_tenant_id="test-tenant-id",
            azure_b2c_user_flow="B2C_1_signin"
        )
        
        expected = "https://test-tenant.b2clogin.com/test-tenant-id/B2C_1_signin"
        assert settings.azure_b2c_authority == expected

    def test_azure_entra_authority(self):
        """Test Microsoft Entra ID authority URL."""
        settings = Settings(azure_entra_tenant_id="entra-tenant-id")
        
        expected = "https://login.microsoftonline.com/entra-tenant-id"
        assert settings.azure_entra_authority == expected

    def test_enable_mock_auth_default(self):
        """Test mock auth is disabled by default."""
        settings = Settings()
        assert settings.enable_mock_auth is False

    def test_enable_mock_auth_development(self):
        """Test mock auth can be enabled."""
        settings = Settings(enable_mock_auth=True)
        assert settings.enable_mock_auth is True

    def test_redis_configuration(self):
        """Test Redis configuration."""
        settings = Settings(
            redis_url="redis://localhost:6379",
            redis_password="test-password",
            redis_db=1
        )
        
        assert settings.redis_url == "redis://localhost:6379"
        assert settings.redis_password == "test-password"
        assert settings.redis_db == 1

    def test_rate_limiting_defaults(self):
        """Test rate limiting defaults."""
        settings = Settings()
        
        assert settings.rate_limit_requests == 20
        assert settings.rate_limit_window_seconds == 60

    def test_jwt_token_expiration(self):
        """Test JWT token expiration settings."""
        settings = Settings(
            jwt_access_token_expire_minutes=120,
            jwt_refresh_token_expire_days=90
        )
        
        assert settings.jwt_access_token_expire_minutes == 120
        assert settings.jwt_refresh_token_expire_days == 90

    def test_session_cookie_settings(self):
        """Test session cookie settings."""
        settings = Settings(
            session_cookie_secure=False,
            session_cookie_samesite="lax",
            session_max_age_seconds=7200
        )
        
        assert settings.session_cookie_secure is False
        assert settings.session_cookie_samesite == "lax"
        assert settings.session_max_age_seconds == 7200

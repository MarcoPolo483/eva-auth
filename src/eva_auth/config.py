"""Configuration settings for eva-auth service."""

from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Environment
    environment: Literal["development", "staging", "production"] = "development"

    # Azure AD B2C Configuration
    azure_b2c_tenant_name: str = Field(default="")
    azure_b2c_tenant_id: str = Field(default="")
    azure_b2c_client_id: str = Field(default="")
    azure_b2c_client_secret: str = Field(default="")
    azure_b2c_user_flow: str = Field(default="B2C_1_signin")
    azure_b2c_redirect_uri: str = Field(default="http://localhost:8000/auth/b2c/callback")

    # Microsoft Entra ID Configuration
    azure_entra_tenant_id: str = Field(default="")
    azure_entra_client_id: str = Field(default="")
    azure_entra_client_secret: str = Field(default="")
    azure_entra_redirect_uri: str = Field(default="http://localhost:8000/auth/entra/callback")

    # Redis Configuration
    redis_url: str = Field(default="redis://localhost:6379")
    redis_password: str = Field(default="")
    redis_db: int = Field(default=0)

    # Azure Cosmos DB Configuration
    cosmos_endpoint: str = Field(default="https://localhost:8081")
    cosmos_key: str = Field(default="")
    cosmos_database: str = Field(default="eva-auth")
    cosmos_container_audit: str = Field(default="audit-logs")
    cosmos_container_apikeys: str = Field(default="api-keys")

    # Azure Key Vault Configuration
    keyvault_url: str = Field(default="")

    # JWT Configuration
    jwt_algorithm: str = Field(default="RS256")
    jwt_access_token_expire_minutes: int = Field(default=60)
    jwt_refresh_token_expire_days: int = Field(default=30)
    jwt_secret_key: str = Field(default="your-secret-key-for-development")

    # Session Configuration
    session_cookie_name: str = Field(default="eva_session_id")
    session_cookie_secure: bool = Field(default=True)
    session_cookie_httponly: bool = Field(default=True)
    session_cookie_samesite: Literal["strict", "lax", "none"] = Field(default="strict")
    session_max_age_seconds: int = Field(default=3600)

    # Rate Limiting
    rate_limit_requests: int = Field(default=20)
    rate_limit_window_seconds: int = Field(default=60)

    # Logging
    log_level: str = Field(default="INFO")
    log_format: Literal["json", "text"] = Field(default="json")

    # CORS Configuration
    cors_origins: str = Field(default="http://localhost:3000,http://localhost:8000")
    cors_allow_credentials: bool = Field(default=True)

    # Mock Authentication (Development Only)
    enable_mock_auth: bool = Field(default=False)
    mock_auth_secret: str = Field(default="test-secret-key-12345")

    @property
    def cors_origins_list(self) -> list[str]:
        """Parse CORS origins from comma-separated string."""
        return [origin.strip() for origin in self.cors_origins.split(",")]

    @property
    def azure_b2c_authority(self) -> str:
        """Get Azure AD B2C authority URL."""
        return (
            f"https://{self.azure_b2c_tenant_name}.b2clogin.com/"
            f"{self.azure_b2c_tenant_id}/{self.azure_b2c_user_flow}"
        )

    @property
    def azure_entra_authority(self) -> str:
        """Get Microsoft Entra ID authority URL."""
        return f"https://login.microsoftonline.com/{self.azure_entra_tenant_id}"


# Global settings instance
settings = Settings()

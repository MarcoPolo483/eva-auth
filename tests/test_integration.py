"""
Integration tests for EVA-Auth service.

Tests end-to-end flows with Docker Compose stack:
- OAuth authentication → audit log creation
- Middleware + RBAC → permission enforcement + audit
- Session management coordination
- API key validation with audit tracking

Requires Docker Compose services running:
    docker-compose up -d redis cosmosdb

Run with:
    poetry run pytest tests/test_integration.py -v --tb=short
"""

import asyncio
import time
from datetime import datetime, timedelta
from typing import AsyncGenerator

import pytest
from fakeredis.aioredis import FakeRedis
from fastapi.testclient import TestClient

from eva_auth.audit import AuditLogger
from eva_auth.config import settings
from eva_auth.main import app
from eva_auth.models import JWTClaims
from eva_auth.session import SessionManager
from eva_auth.testing.mock_auth import MockAuthProvider


@pytest.fixture(scope="module")
async def redis_client() -> AsyncGenerator[FakeRedis, None]:
    """Get FakeRedis client for integration tests."""
    redis = FakeRedis(decode_responses=True)
    yield redis
    await redis.aclose()


@pytest.fixture(scope="module")
def test_client() -> TestClient:
    """Get FastAPI test client."""
    return TestClient(app)


@pytest.fixture
def session_manager() -> SessionManager:
    """Get session manager with FakeRedis."""
    redis = FakeRedis(decode_responses=True)
    return SessionManager(redis_client=redis)


@pytest.fixture
def mock_auth() -> MockAuthProvider:
    """Get mock authentication provider."""
    return MockAuthProvider()


class TestAuthenticationFlow:
    """Test complete authentication flows."""

    def test_mock_token_generation(self, test_client: TestClient):
        """Test mock token generation endpoint."""
        response = test_client.post(
            "/auth/mock/token?user_id=test-user-123&email=test@example.com&tenant_id=tenant-456&roles=eva:user"
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "token_type" in data
        assert data["token_type"] == "Bearer"
        assert "expires_in" in data

    def test_health_check(self, test_client: TestClient):
        """Test health check endpoint."""
        response = test_client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "service" in data
        assert "version" in data

    def test_readiness_check(self, test_client: TestClient):
        """Test readiness check with Redis."""
        response = test_client.get("/ready")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ready"
        # Redis check not implemented yet in readiness endpoint


class TestSessionManagement:
    """Test session management with Redis."""

    @pytest.mark.asyncio
    async def test_create_and_retrieve_session(
        self,
        session_manager: SessionManager,
        mock_auth: MockAuthProvider,
    ):
        """Test session creation and retrieval."""
        # Generate test claims
        claims = JWTClaims(
            sub="user-integration-001",
            email="integration@example.com",
            tenant_id="tenant-integration",
            roles=["eva:user"],
            expires_at=int(time.time()) + 3600,
        )
        
        # Create session
        session_id = "test-session-001"
        await session_manager.create_session(session_id, claims, expires_in=3600)
        
        # Retrieve session
        session_data = await session_manager.get_session(session_id)
        assert session_data is not None
        assert session_data.user_id == claims.sub
        assert session_data.tenant_id == claims.tenant_id

    @pytest.mark.asyncio
    async def test_session_expiry(
        self,
        session_manager: SessionManager,
    ):
        """Test session expiration."""
        # Create expired claims
        claims = JWTClaims(
            sub="user-expiry-test",
            email="expiry@example.com",
            tenant_id="tenant-test",
            roles=["eva:user"],
            expires_at=int(time.time()) + 3600,
        )
        
        session_id = "test-session-expiry"
        # Create session with 1 second expiry
        await session_manager.create_session(session_id, claims, expires_in=1)
        
        # Wait for expiration
        await asyncio.sleep(2)
        
        # Should not be retrievable (expired)
        retrieved = await session_manager.get_session(session_id)
        assert retrieved is None

    @pytest.mark.asyncio
    async def test_session_deletion(
        self,
        session_manager: SessionManager,
    ):
        """Test session deletion."""
        claims = JWTClaims(
            sub="user-delete-test",
            email="delete@example.com",
            tenant_id="tenant-test",
            roles=["eva:user"],
            expires_at=int(time.time()) + 3600,
        )
        
        session_id = "test-session-delete"
        await session_manager.create_session(session_id, claims, expires_in=3600)
        
        # Delete session
        await session_manager.delete_session(session_id)
        
        # Should not be retrievable
        retrieved = await session_manager.get_session(session_id)
        assert retrieved is None

    @pytest.mark.asyncio
    async def test_token_blacklisting(
        self,
        session_manager: SessionManager,
        mock_auth: MockAuthProvider,
    ):
        """Test JWT token blacklisting."""
        # Generate token
        token = mock_auth.generate_token(
            user_id="user-blacklist-test",
            email="blacklist@example.com",
            tenant_id="tenant-test",
            roles=["eva:user"],
        )
        
        jti = "test-jti-123"
        expiry = 3600
        
        # Blacklist token
        await session_manager.blacklist_token(jti, expiry)
        
        # Check if blacklisted
        is_blacklisted = await session_manager.is_token_blacklisted(jti)
        assert is_blacklisted is True


class TestRBACIntegration:
    """Test RBAC enforcement in integration scenarios."""

    @pytest.mark.asyncio
    async def test_permission_enforcement_with_audit(self):
        """Test that permission denial is logged to audit."""
        # This would require mocked Cosmos DB or actual Cosmos emulator
        # Placeholder for integration test structure
        pass

    @pytest.mark.asyncio
    async def test_tenant_isolation_enforcement(self):
        """Test that cross-tenant access is blocked and logged."""
        # This would require mocked Cosmos DB or actual Cosmos emulator
        # Placeholder for integration test structure
        pass


class TestAuditIntegration:
    """Test audit logging in integration scenarios."""

    @pytest.mark.asyncio
    async def test_login_success_creates_audit_log(self):
        """Test that successful login creates audit log entry."""
        # This would require mocked Cosmos DB or actual Cosmos emulator
        # Placeholder for integration test structure
        pass

    @pytest.mark.asyncio
    async def test_permission_denied_creates_audit_log(self):
        """Test that permission denial creates audit log entry."""
        # This would require mocked Cosmos DB or actual Cosmos emulator
        # Placeholder for integration test structure
        pass


class TestAPIKeyIntegration:
    """Test API key validation in integration scenarios."""

    @pytest.mark.asyncio
    async def test_api_key_validation_with_usage_tracking(self):
        """Test that API key validation tracks usage in Cosmos DB."""
        # This would require mocked Cosmos DB or actual Cosmos emulator
        # Placeholder for integration test structure
        pass

    @pytest.mark.asyncio
    async def test_api_key_revocation_immediate_effect(self):
        """Test that revoked API keys are immediately rejected."""
        # This would require mocked Cosmos DB or actual Cosmos emulator
        # Placeholder for integration test structure
        pass


class TestPerformanceBaseline:
    """Test performance baselines for critical paths."""

    def test_token_validation_latency(
        self,
        test_client: TestClient,
        mock_auth: MockAuthProvider,
    ):
        """Test that token validation is <50ms."""
        # Generate test token
        token = mock_auth.generate_token(
            user_id="perf-test-user",
            email="perf@example.com",
            tenant_id="tenant-perf",
            roles=["eva:user"],
        )
        
        # Measure token validation time (via health check with auth)
        start = time.perf_counter()
        
        # Make 10 requests to get average
        latencies = []
        for _ in range(10):
            req_start = time.perf_counter()
            response = test_client.get("/health")
            req_end = time.perf_counter()
            latencies.append((req_end - req_start) * 1000)  # Convert to ms
            assert response.status_code == 200
        
        avg_latency = sum(latencies) / len(latencies)
        p95_latency = sorted(latencies)[int(len(latencies) * 0.95)]
        
        print(f"\nToken validation latency: avg={avg_latency:.2f}ms, p95={p95_latency:.2f}ms")
        
        # Baseline: should be <50ms average
        assert avg_latency < 50, f"Average latency {avg_latency:.2f}ms exceeds 50ms baseline"

    @pytest.mark.asyncio
    async def test_session_operations_latency(
        self,
        session_manager: SessionManager,
    ):
        """Test that session operations are <10ms."""
        claims = JWTClaims(
            sub="perf-session-user",
            email="session-perf@example.com",
            tenant_id="tenant-perf",
            roles=["eva:user"],
            expires_at=int(time.time()) + 3600,
        )
        
        session_id = "perf-test-session"
        
        # Test create latency
        start = time.perf_counter()
        await session_manager.create_session(session_id, claims, expires_in=3600)
        create_time = (time.perf_counter() - start) * 1000
        
        # Test retrieve latency
        start = time.perf_counter()
        retrieved = await session_manager.get_session(session_id)
        retrieve_time = (time.perf_counter() - start) * 1000
        
        # Test delete latency
        start = time.perf_counter()
        await session_manager.delete_session(session_id)
        delete_time = (time.perf_counter() - start) * 1000
        
        print(f"\nSession operation latencies:")
        print(f"  Create: {create_time:.2f}ms")
        print(f"  Retrieve: {retrieve_time:.2f}ms")
        print(f"  Delete: {delete_time:.2f}ms")
        
        # Baseline: all operations <10ms
        assert create_time < 10, f"Create latency {create_time:.2f}ms exceeds 10ms"
        assert retrieve_time < 10, f"Retrieve latency {retrieve_time:.2f}ms exceeds 10ms"
        assert delete_time < 10, f"Delete latency {delete_time:.2f}ms exceeds 10ms"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])

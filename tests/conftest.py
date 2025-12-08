"""Pytest configuration and fixtures."""

import pytest
import redis.asyncio as redis
from fakeredis import aioredis as fakeredis

from eva_auth.testing import MockAuthProvider


@pytest.fixture
def mock_auth():
    """Mock authentication provider."""
    return MockAuthProvider()


@pytest.fixture
def test_token(mock_auth):
    """Generate test token with user role."""
    return mock_auth.generate_token(
        user_id="test-user-1234",
        email="test@example.com",
        name="Test User",
        tenant_id="test-tenant-5678",
        roles=["eva:user"],
    )


@pytest.fixture
def analyst_token(mock_auth):
    """Generate test token with analyst role."""
    return mock_auth.generate_token(
        user_id="analyst-user-2345",
        email="analyst@example.com",
        name="Analyst User",
        tenant_id="test-tenant-5678",
        roles=["eva:analyst", "eva:user"],
    )


@pytest.fixture
def admin_token(mock_auth):
    """Generate test token with admin role."""
    return mock_auth.generate_token(
        user_id="admin-user-3456",
        email="admin@example.com",
        name="Admin User",
        tenant_id="test-tenant-5678",
        roles=["eva:admin", "eva:user"],
    )


@pytest.fixture
def expired_token(mock_auth):
    """Generate expired test token."""
    return mock_auth.generate_expired_token(
        user_id="test-user-1234",
        email="test@example.com",
        tenant_id="test-tenant-5678",
    )


@pytest.fixture
async def redis_client():
    """Fake Redis client for testing."""
    client = fakeredis.FakeRedis(decode_responses=True)
    yield client
    await client.flushall()
    await client.close()

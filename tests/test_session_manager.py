"""Tests for session manager."""

import pytest
from datetime import datetime, timedelta

from eva_auth.session import SessionManager
from eva_auth.models import JWTClaims, AuthSession


class TestSessionManager:
    """Test suite for SessionManager."""

    @pytest.fixture
    def session_manager(self, redis_client):
        """Create session manager instance."""
        return SessionManager(redis_client)

    @pytest.fixture
    def test_claims(self):
        """Create test JWT claims."""
        return JWTClaims(
            sub="user-123",
            email="test@example.com",
            name="Test User",
            tenant_id="tenant-456",
            roles=["eva:analyst", "eva:user"],
            groups=["group1"],
            expires_at=int((datetime.utcnow() + timedelta(hours=1)).timestamp()),
        )

    @pytest.mark.asyncio
    async def test_create_session(self, session_manager, test_claims):
        """Test session creation."""
        session_id = "session-abc123"
        
        await session_manager.create_session(session_id, test_claims, expires_in=3600)
        
        # Verify session was created
        session = await session_manager.get_session(session_id)
        assert session is not None
        assert session.user_id == "user-123"
        assert session.email == "test@example.com"
        assert session.tenant_id == "tenant-456"

    @pytest.mark.asyncio
    async def test_get_session_not_found(self, session_manager):
        """Test getting non-existent session."""
        session = await session_manager.get_session("nonexistent-session")
        assert session is None

    @pytest.mark.asyncio
    async def test_get_session(self, session_manager, test_claims):
        """Test retrieving existing session."""
        session_id = "session-def456"
        
        await session_manager.create_session(session_id, test_claims)
        session = await session_manager.get_session(session_id)
        
        assert isinstance(session, AuthSession)
        assert session.user_id == test_claims.sub
        assert session.email == test_claims.email
        assert session.tenant_id == test_claims.tenant_id
        assert session.roles == test_claims.roles
        assert session.groups == test_claims.groups

    @pytest.mark.asyncio
    async def test_delete_session(self, session_manager, test_claims):
        """Test session deletion."""
        session_id = "session-ghi789"
        
        await session_manager.create_session(session_id, test_claims)
        await session_manager.delete_session(session_id)
        
        # Verify session was deleted
        session = await session_manager.get_session(session_id)
        assert session is None

    @pytest.mark.asyncio
    async def test_refresh_session(self, session_manager, test_claims):
        """Test session refresh."""
        session_id = "session-jkl012"
        
        await session_manager.create_session(session_id, test_claims, expires_in=60)
        success = await session_manager.refresh_session(session_id, expires_in=3600)
        
        assert success is True
        
        # Session should still exist
        session = await session_manager.get_session(session_id)
        assert session is not None

    @pytest.mark.asyncio
    async def test_refresh_nonexistent_session(self, session_manager):
        """Test refreshing non-existent session."""
        success = await session_manager.refresh_session("nonexistent-session")
        assert success is False

    @pytest.mark.asyncio
    async def test_blacklist_token(self, session_manager):
        """Test token blacklisting."""
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test"
        
        await session_manager.blacklist_token(token, expires_in=3600)
        
        # Verify token is blacklisted
        is_blacklisted = await session_manager.is_token_blacklisted(token)
        assert is_blacklisted is True

    @pytest.mark.asyncio
    async def test_token_not_blacklisted(self, session_manager):
        """Test checking non-blacklisted token."""
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.notblacklisted"
        
        is_blacklisted = await session_manager.is_token_blacklisted(token)
        assert is_blacklisted is False

    @pytest.mark.asyncio
    async def test_session_expiration(self, session_manager, test_claims):
        """Test session expiration."""
        session_id = "session-expire"
        
        # Create session with 1 second expiration
        await session_manager.create_session(session_id, test_claims, expires_in=1)
        
        # Session should exist initially
        session = await session_manager.get_session(session_id)
        assert session is not None
        
        # Wait for expiration
        import asyncio
        await asyncio.sleep(2)
        
        # Session should be expired
        session = await session_manager.get_session(session_id)
        assert session is None

    @pytest.mark.asyncio
    async def test_multiple_sessions(self, session_manager, test_claims):
        """Test managing multiple sessions."""
        session_ids = ["session-1", "session-2", "session-3"]
        
        # Create multiple sessions
        for session_id in session_ids:
            await session_manager.create_session(session_id, test_claims)
        
        # Verify all sessions exist
        for session_id in session_ids:
            session = await session_manager.get_session(session_id)
            assert session is not None
        
        # Delete one session
        await session_manager.delete_session("session-2")
        
        # Verify correct sessions remain
        assert await session_manager.get_session("session-1") is not None
        assert await session_manager.get_session("session-2") is None
        assert await session_manager.get_session("session-3") is not None

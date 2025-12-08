"""Session manager for Redis-based session storage."""

import json
from datetime import datetime, timedelta
from typing import Optional

import redis.asyncio as redis

from eva_auth.models import AuthSession, JWTClaims


class SessionManager:
    """Manages user sessions in Redis."""

    def __init__(self, redis_client: redis.Redis):
        """Initialize session manager.
        
        Args:
            redis_client: Async Redis client instance
        """
        self.redis = redis_client

    async def create_session(
        self,
        session_id: str,
        claims: JWTClaims,
        expires_in: int = 3600,
    ) -> None:
        """Store session in Redis with expiration.
        
        Args:
            session_id: Unique session identifier
            claims: JWT claims from authenticated user
            expires_in: Session expiration in seconds (default 1 hour)
        """
        now = datetime.utcnow()
        session_data = {
            "user_id": claims.sub,
            "email": claims.email,
            "tenant_id": claims.tenant_id,
            "roles": claims.roles,
            "groups": claims.groups,
            "created_at": now.isoformat(),
            "expires_at": (now + timedelta(seconds=expires_in)).isoformat(),
        }

        await self.redis.setex(
            f"session:{session_id}",
            timedelta(seconds=expires_in),
            json.dumps(session_data),
        )

    async def get_session(self, session_id: str) -> Optional[AuthSession]:
        """Retrieve session from Redis.
        
        Args:
            session_id: Session identifier
            
        Returns:
            Session data if found, None otherwise
        """
        data = await self.redis.get(f"session:{session_id}")
        if not data:
            return None

        session_dict = json.loads(data)
        return AuthSession(
            user_id=session_dict["user_id"],
            email=session_dict.get("email"),
            tenant_id=session_dict["tenant_id"],
            roles=session_dict["roles"],
            groups=session_dict.get("groups", []),
            created_at=datetime.fromisoformat(session_dict["created_at"]),
            expires_at=datetime.fromisoformat(session_dict["expires_at"]),
        )

    async def delete_session(self, session_id: str) -> None:
        """Delete session from Redis (logout).
        
        Args:
            session_id: Session identifier
        """
        await self.redis.delete(f"session:{session_id}")

    async def refresh_session(self, session_id: str, expires_in: int = 3600) -> bool:
        """Extend session expiration.
        
        Args:
            session_id: Session identifier
            expires_in: New expiration time in seconds
            
        Returns:
            True if session was refreshed, False if not found
        """
        exists = await self.redis.exists(f"session:{session_id}")
        if not exists:
            return False

        await self.redis.expire(f"session:{session_id}", timedelta(seconds=expires_in))
        return True

    async def blacklist_token(self, token: str, expires_in: int) -> None:
        """Add token to blacklist (prevent replay after logout).
        
        Args:
            token: JWT token string
            expires_in: Blacklist expiration (should match token's remaining lifetime)
        """
        await self.redis.setex(
            f"blacklist:{token}",
            timedelta(seconds=expires_in),
            "1",
        )

    async def is_token_blacklisted(self, token: str) -> bool:
        """Check if token is blacklisted.
        
        Args:
            token: JWT token string
            
        Returns:
            True if blacklisted, False otherwise
        """
        exists = await self.redis.exists(f"blacklist:{token}")
        return exists > 0

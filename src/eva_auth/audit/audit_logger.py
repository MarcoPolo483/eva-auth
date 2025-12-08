"""Audit logging module for tracking authentication events."""

from azure.cosmos import CosmosClient, PartitionKey
from azure.cosmos.exceptions import CosmosHttpResponseError
from datetime import datetime, timezone
import uuid
from typing import Optional

from eva_auth.config import settings


class AuditLogger:
    """Audit logger for tracking authentication events in Cosmos DB."""

    def __init__(
        self,
        cosmos_client: Optional[CosmosClient] = None,
        database_name: str = "eva-auth",
        container_name: str = "audit-logs",
    ):
        """Initialize audit logger.

        Args:
            cosmos_client: Azure Cosmos DB client instance
            database_name: Cosmos DB database name
            container_name: Container name for audit logs
        """
        self.client = cosmos_client or CosmosClient(
            settings.cosmos_endpoint, credential=settings.cosmos_key
        )
        self.database_name = database_name
        self.container_name = container_name
        self._container = None

    async def _get_container(self):
        """Get or create Cosmos DB container."""
        if self._container is None:
            database = self.client.get_database_client(self.database_name)
            try:
                self._container = database.get_container_client(self.container_name)
            except CosmosHttpResponseError:
                # Create container if doesn't exist
                database.create_container(
                    id=self.container_name,
                    partition_key=PartitionKey(path="/tenant_id"),
                )
                self._container = database.get_container_client(self.container_name)
        return self._container

    async def log_event(
        self,
        event_type: str,
        user_id: str,
        tenant_id: str,
        ip_address: str,
        user_agent: str,
        session_id: Optional[str] = None,
        auth_method: Optional[str] = None,
        metadata: Optional[dict] = None,
        success: bool = True,
        error_message: Optional[str] = None,
    ) -> str:
        """Log authentication event to Cosmos DB.

        Args:
            event_type: Type of event (auth.login.success, auth.login.failure, etc.)
            user_id: User identifier
            tenant_id: Tenant identifier (partition key)
            ip_address: Client IP address
            user_agent: Client User-Agent string
            session_id: Session identifier (if applicable)
            auth_method: Authentication method used (azure_b2c, entra_id, api_key)
            metadata: Additional event metadata (roles, groups, organization, etc.)
            success: Whether the event was successful
            error_message: Error message (if success=False)

        Returns:
            Event ID (UUID)
        """
        container = await self._get_container()

        event_id = str(uuid.uuid4())
        log_entry = {
            "id": event_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "user_id": user_id,
            "tenant_id": tenant_id,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "session_id": session_id,
            "auth_method": auth_method,
            "success": success,
            "error_message": error_message,
            "metadata": metadata or {},
        }

        container.create_item(body=log_entry)
        return event_id

    async def log_login_success(
        self,
        user_id: str,
        tenant_id: str,
        ip_address: str,
        user_agent: str,
        session_id: str,
        auth_method: str,
        roles: list[str],
        groups: Optional[list[str]] = None,
        organization: Optional[str] = None,
    ) -> str:
        """Log successful login event.

        Args:
            user_id: User identifier
            tenant_id: Tenant identifier
            ip_address: Client IP address
            user_agent: Client User-Agent
            session_id: Session ID created
            auth_method: Authentication method (azure_b2c, microsoft_entra)
            roles: User roles
            groups: User groups (for Entra ID)
            organization: Organization name (for Entra ID)

        Returns:
            Event ID
        """
        return await self.log_event(
            event_type="auth.login.success",
            user_id=user_id,
            tenant_id=tenant_id,
            ip_address=ip_address,
            user_agent=user_agent,
            session_id=session_id,
            auth_method=auth_method,
            metadata={
                "roles": roles,
                "groups": groups or [],
                "organization": organization,
            },
            success=True,
        )

    async def log_login_failure(
        self,
        user_id: str,
        tenant_id: str,
        ip_address: str,
        user_agent: str,
        auth_method: str,
        error_message: str,
        reason: Optional[str] = None,
    ) -> str:
        """Log failed login attempt.

        Args:
            user_id: User identifier (if available)
            tenant_id: Tenant identifier
            ip_address: Client IP address
            user_agent: Client User-Agent
            auth_method: Authentication method attempted
            error_message: Error message
            reason: Failure reason (expired_token, invalid_credentials, etc.)

        Returns:
            Event ID
        """
        return await self.log_event(
            event_type="auth.login.failure",
            user_id=user_id,
            tenant_id=tenant_id,
            ip_address=ip_address,
            user_agent=user_agent,
            auth_method=auth_method,
            metadata={"reason": reason},
            success=False,
            error_message=error_message,
        )

    async def log_token_refresh(
        self,
        user_id: str,
        tenant_id: str,
        ip_address: str,
        user_agent: str,
        session_id: str,
        auth_method: str,
    ) -> str:
        """Log token refresh event.

        Args:
            user_id: User identifier
            tenant_id: Tenant identifier
            ip_address: Client IP address
            user_agent: Client User-Agent
            session_id: Session ID
            auth_method: Authentication method

        Returns:
            Event ID
        """
        return await self.log_event(
            event_type="auth.token.refreshed",
            user_id=user_id,
            tenant_id=tenant_id,
            ip_address=ip_address,
            user_agent=user_agent,
            session_id=session_id,
            auth_method=auth_method,
            success=True,
        )

    async def log_logout(
        self,
        user_id: str,
        tenant_id: str,
        ip_address: str,
        user_agent: str,
        session_id: str,
        auth_method: str,
    ) -> str:
        """Log logout event.

        Args:
            user_id: User identifier
            tenant_id: Tenant identifier
            ip_address: Client IP address
            user_agent: Client User-Agent
            session_id: Session ID terminated
            auth_method: Authentication method

        Returns:
            Event ID
        """
        return await self.log_event(
            event_type="auth.logout.success",
            user_id=user_id,
            tenant_id=tenant_id,
            ip_address=ip_address,
            user_agent=user_agent,
            session_id=session_id,
            auth_method=auth_method,
            success=True,
        )

    async def log_permission_denied(
        self,
        user_id: str,
        tenant_id: str,
        ip_address: str,
        user_agent: str,
        session_id: str,
        resource: str,
        action: str,
        required_permission: str,
        user_roles: list[str],
    ) -> str:
        """Log permission denied event.

        Args:
            user_id: User identifier
            tenant_id: Tenant identifier
            ip_address: Client IP address
            user_agent: Client User-Agent
            session_id: Session ID
            resource: Resource attempted to access
            action: Action attempted
            required_permission: Permission required
            user_roles: User's current roles

        Returns:
            Event ID
        """
        return await self.log_event(
            event_type="auth.permission.denied",
            user_id=user_id,
            tenant_id=tenant_id,
            ip_address=ip_address,
            user_agent=user_agent,
            session_id=session_id,
            metadata={
                "resource": resource,
                "action": action,
                "required_permission": required_permission,
                "user_roles": user_roles,
            },
            success=False,
            error_message=f"Missing permission: {required_permission}",
        )

    async def log_api_key_created(
        self,
        user_id: str,
        tenant_id: str,
        ip_address: str,
        user_agent: str,
        api_key_id: str,
        api_key_name: str,
        permissions: list[str],
        expires_at: str,
    ) -> str:
        """Log API key creation event.

        Args:
            user_id: User who created the key
            tenant_id: Tenant identifier
            ip_address: Client IP address
            user_agent: Client User-Agent
            api_key_id: API key ID (hashed)
            api_key_name: API key name
            permissions: Permissions granted
            expires_at: Expiration timestamp

        Returns:
            Event ID
        """
        return await self.log_event(
            event_type="auth.apikey.created",
            user_id=user_id,
            tenant_id=tenant_id,
            ip_address=ip_address,
            user_agent=user_agent,
            metadata={
                "api_key_id": api_key_id,
                "api_key_name": api_key_name,
                "permissions": permissions,
                "expires_at": expires_at,
            },
            success=True,
        )

    async def log_api_key_revoked(
        self,
        user_id: str,
        tenant_id: str,
        ip_address: str,
        user_agent: str,
        api_key_id: str,
        api_key_name: str,
    ) -> str:
        """Log API key revocation event.

        Args:
            user_id: User who revoked the key
            tenant_id: Tenant identifier
            ip_address: Client IP address
            user_agent: Client User-Agent
            api_key_id: API key ID (hashed)
            api_key_name: API key name

        Returns:
            Event ID
        """
        return await self.log_event(
            event_type="auth.apikey.revoked",
            user_id=user_id,
            tenant_id=tenant_id,
            ip_address=ip_address,
            user_agent=user_agent,
            metadata={
                "api_key_id": api_key_id,
                "api_key_name": api_key_name,
            },
            success=True,
        )

    async def query_events_by_user(
        self,
        user_id: str,
        tenant_id: str,
        limit: int = 100,
    ) -> list[dict]:
        """Query audit events for specific user.

        Args:
            user_id: User identifier
            tenant_id: Tenant identifier (partition key)
            limit: Maximum number of events to return

        Returns:
            List of audit log entries
        """
        container = await self._get_container()

        query = "SELECT * FROM c WHERE c.user_id = @user_id AND c.tenant_id = @tenant_id ORDER BY c.timestamp DESC OFFSET 0 LIMIT @limit"
        parameters = [
            {"name": "@user_id", "value": user_id},
            {"name": "@tenant_id", "value": tenant_id},
            {"name": "@limit", "value": limit},
        ]

        items = list(
            container.query_items(
                query=query,
                parameters=parameters,
                partition_key=tenant_id,
            )
        )
        return items

    async def query_failed_logins(
        self,
        tenant_id: str,
        since_timestamp: str,
        limit: int = 100,
    ) -> list[dict]:
        """Query failed login attempts.

        Args:
            tenant_id: Tenant identifier
            since_timestamp: ISO timestamp to query from
            limit: Maximum number of events

        Returns:
            List of failed login events
        """
        container = await self._get_container()

        query = """
            SELECT * FROM c 
            WHERE c.tenant_id = @tenant_id 
            AND c.event_type = 'auth.login.failure'
            AND c.timestamp >= @since_timestamp
            ORDER BY c.timestamp DESC 
            OFFSET 0 LIMIT @limit
        """
        parameters = [
            {"name": "@tenant_id", "value": tenant_id},
            {"name": "@since_timestamp", "value": since_timestamp},
            {"name": "@limit", "value": limit},
        ]

        items = list(
            container.query_items(
                query=query,
                parameters=parameters,
                partition_key=tenant_id,
            )
        )
        return items

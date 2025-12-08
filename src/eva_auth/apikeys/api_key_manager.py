"""API key management for programmatic access."""

import secrets
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional

from azure.cosmos import CosmosClient, PartitionKey
from azure.cosmos.exceptions import CosmosHttpResponseError

from eva_auth.config import settings
from eva_auth.models import APIKey


class APIKeyManager:
    """Manager for API key CRUD operations."""

    def __init__(
        self,
        cosmos_client: Optional[CosmosClient] = None,
        database_name: str = "eva-auth",
        container_name: str = "api-keys",
    ):
        """Initialize API key manager.

        Args:
            cosmos_client: Azure Cosmos DB client instance
            database_name: Cosmos DB database name
            container_name: Container name for API keys
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

    async def generate_api_key(
        self,
        name: str,
        tenant_id: str,
        permissions: list[str],
        expires_in_days: int = 365,
        created_by: str = "system",
    ) -> tuple[str, APIKey]:
        """Generate new API key.

        Args:
            name: Human-readable name for the key
            tenant_id: Tenant identifier (partition key)
            permissions: List of permissions (e.g., ["spaces:read", "documents:write"])
            expires_in_days: Number of days until expiration
            created_by: User ID who created the key

        Returns:
            Tuple of (plaintext_key, APIKey metadata)
            WARNING: Plaintext key is only returned once!
        """
        container = await self._get_container()

        # Generate cryptographically secure random key
        random_part = secrets.token_urlsafe(36)  # 48 chars
        api_key_plaintext = f"sk_eva_live_{random_part}"

        # Hash for storage (SHA-256)
        key_hash = hashlib.sha256(api_key_plaintext.encode()).hexdigest()

        # Create metadata document
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(days=expires_in_days)

        api_key_doc = {
            "id": key_hash,
            "tenant_id": tenant_id,
            "name": name,
            "key_prefix": api_key_plaintext[:12],  # For identification: "sk_eva_live_"
            "permissions": permissions,
            "created_at": now.isoformat(),
            "created_by": created_by,
            "expires_at": expires_at.isoformat(),
            "revoked": False,
            "last_used_at": None,
            "usage_count": 0,
        }

        container.create_item(body=api_key_doc)

        # Return both plaintext (one-time) and metadata
        api_key_metadata = APIKey(
            id=key_hash,
            tenant_id=tenant_id,
            name=name,
            key_prefix=api_key_doc["key_prefix"],
            permissions=permissions,
            created_at=api_key_doc["created_at"],
            expires_at=api_key_doc["expires_at"],
            revoked=False,
        )

        return api_key_plaintext, api_key_metadata

    async def validate_api_key(self, api_key: str) -> Optional[APIKey]:
        """Validate API key and return metadata.

        Args:
            api_key: Plaintext API key to validate

        Returns:
            APIKey metadata if valid, None if invalid/expired/revoked
        """
        container = await self._get_container()

        # Hash the key
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()

        try:
            # Query by ID (primary key)
            query = "SELECT * FROM c WHERE c.id = @key_hash"
            parameters = [{"name": "@key_hash", "value": key_hash}]

            items = list(
                container.query_items(
                    query=query,
                    parameters=parameters,
                    enable_cross_partition_query=True,
                )
            )

            if not items:
                return None

            doc = items[0]

            # Check if revoked
            if doc["revoked"]:
                return None

            # Check expiration
            expires_at = datetime.fromisoformat(doc["expires_at"])
            if expires_at < datetime.now(timezone.utc):
                return None

            # Update last_used_at and usage_count
            doc["last_used_at"] = datetime.now(timezone.utc).isoformat()
            doc["usage_count"] = doc.get("usage_count", 0) + 1

            container.replace_item(item=doc["id"], body=doc)

            return APIKey(
                id=doc["id"],
                tenant_id=doc["tenant_id"],
                name=doc["name"],
                key_prefix=doc["key_prefix"],
                permissions=doc["permissions"],
                created_at=doc["created_at"],
                expires_at=doc["expires_at"],
                revoked=False,
            )

        except CosmosHttpResponseError:
            return None

    async def revoke_api_key(self, api_key_id: str, tenant_id: str) -> bool:
        """Revoke API key.

        Args:
            api_key_id: API key ID (hashed)
            tenant_id: Tenant identifier (partition key)

        Returns:
            True if revoked, False if not found
        """
        container = await self._get_container()

        try:
            doc = container.read_item(item=api_key_id, partition_key=tenant_id)
            doc["revoked"] = True
            doc["revoked_at"] = datetime.now(timezone.utc).isoformat()

            container.replace_item(item=api_key_id, body=doc)
            return True

        except CosmosHttpResponseError:
            return False

    async def list_api_keys(
        self, tenant_id: str, include_revoked: bool = False
    ) -> list[APIKey]:
        """List all API keys for a tenant.

        Args:
            tenant_id: Tenant identifier
            include_revoked: Whether to include revoked keys

        Returns:
            List of APIKey metadata
        """
        container = await self._get_container()

        if include_revoked:
            query = "SELECT * FROM c WHERE c.tenant_id = @tenant_id"
        else:
            query = "SELECT * FROM c WHERE c.tenant_id = @tenant_id AND c.revoked = false"

        parameters = [{"name": "@tenant_id", "value": tenant_id}]

        items = list(
            container.query_items(
                query=query,
                parameters=parameters,
                partition_key=tenant_id,
            )
        )

        return [
            APIKey(
                id=item["id"],
                tenant_id=item["tenant_id"],
                name=item["name"],
                key_prefix=item["key_prefix"],
                permissions=item["permissions"],
                created_at=item["created_at"],
                expires_at=item["expires_at"],
                revoked=item["revoked"],
            )
            for item in items
        ]

    async def get_api_key_by_id(
        self, api_key_id: str, tenant_id: str
    ) -> Optional[APIKey]:
        """Get API key metadata by ID.

        Args:
            api_key_id: API key ID (hashed)
            tenant_id: Tenant identifier (partition key)

        Returns:
            APIKey metadata if found, None otherwise
        """
        container = await self._get_container()

        try:
            doc = container.read_item(item=api_key_id, partition_key=tenant_id)

            return APIKey(
                id=doc["id"],
                tenant_id=doc["tenant_id"],
                name=doc["name"],
                key_prefix=doc["key_prefix"],
                permissions=doc["permissions"],
                created_at=doc["created_at"],
                expires_at=doc["expires_at"],
                revoked=doc["revoked"],
            )

        except CosmosHttpResponseError:
            return None

    async def update_api_key_permissions(
        self, api_key_id: str, tenant_id: str, permissions: list[str]
    ) -> bool:
        """Update API key permissions.

        Args:
            api_key_id: API key ID (hashed)
            tenant_id: Tenant identifier (partition key)
            permissions: New list of permissions

        Returns:
            True if updated, False if not found
        """
        container = await self._get_container()

        try:
            doc = container.read_item(item=api_key_id, partition_key=tenant_id)
            doc["permissions"] = permissions
            doc["updated_at"] = datetime.now(timezone.utc).isoformat()

            container.replace_item(item=api_key_id, body=doc)
            return True

        except CosmosHttpResponseError:
            return False

    async def rotate_api_key(
        self, old_api_key_id: str, tenant_id: str, name: str, permissions: list[str]
    ) -> Optional[tuple[str, APIKey]]:
        """Rotate API key (revoke old, create new).

        Args:
            old_api_key_id: Existing API key ID to revoke
            tenant_id: Tenant identifier
            name: Name for new key
            permissions: Permissions for new key

        Returns:
            Tuple of (new_plaintext_key, APIKey metadata) if successful, None if old key not found
        """
        # Revoke old key
        revoked = await self.revoke_api_key(old_api_key_id, tenant_id)
        if not revoked:
            return None

        # Generate new key with same permissions
        new_key, new_metadata = await self.generate_api_key(
            name=name, tenant_id=tenant_id, permissions=permissions
        )

        return new_key, new_metadata

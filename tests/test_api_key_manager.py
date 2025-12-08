"""Tests for API key manager."""

import pytest
from unittest.mock import AsyncMock, MagicMock
from datetime import datetime, timezone, timedelta
import hashlib

from eva_auth.apikeys.api_key_manager import APIKeyManager
from eva_auth.models import APIKey


@pytest.fixture
def mock_cosmos_client():
    """Create a mock Cosmos DB client."""
    client = MagicMock()
    database = MagicMock()
    container = MagicMock()

    client.get_database_client.return_value = database
    database.get_container_client.return_value = container

    return client, container


class TestAPIKeyManager:
    """Tests for APIKeyManager."""

    @pytest.mark.asyncio
    async def test_generate_api_key(self, mock_cosmos_client):
        """Test generating new API key."""
        client, container = mock_cosmos_client

        manager = APIKeyManager(cosmos_client=client)
        container.create_item = MagicMock()

        plaintext_key, metadata = await manager.generate_api_key(
            name="Test API Key",
            tenant_id="tenant-123",
            permissions=["spaces:read", "documents:read"],
            expires_in_days=90,
            created_by="user-456",
        )

        # Verify plaintext key format
        assert plaintext_key.startswith("sk_eva_live_")
        assert len(plaintext_key) > 20

        # Verify metadata
        assert metadata.name == "Test API Key"
        assert metadata.tenant_id == "tenant-123"
        assert metadata.permissions == ["spaces:read", "documents:read"]
        assert metadata.revoked is False

        # Verify key was stored
        container.create_item.assert_called_once()
        call_args = container.create_item.call_args[1]
        doc = call_args["body"]

        assert doc["name"] == "Test API Key"
        assert doc["key_prefix"] == "sk_eva_live_"
        assert doc["revoked"] is False

    @pytest.mark.asyncio
    async def test_validate_api_key_success(self, mock_cosmos_client):
        """Test validating valid API key."""
        client, container = mock_cosmos_client

        manager = APIKeyManager(cosmos_client=client)

        # Mock a valid key document
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(days=365)

        test_key = "sk_eva_live_test123456789"
        key_hash = hashlib.sha256(test_key.encode()).hexdigest()

        mock_doc = {
            "id": key_hash,
            "tenant_id": "tenant-123",
            "name": "Valid Key",
            "key_prefix": "sk_eva_live_",
            "permissions": ["spaces:read"],
            "created_at": now.isoformat(),
            "expires_at": expires_at.isoformat(),
            "revoked": False,
            "usage_count": 0,
        }

        container.query_items = MagicMock(return_value=iter([mock_doc]))
        container.replace_item = MagicMock()

        result = await manager.validate_api_key(test_key)

        assert result is not None
        assert result.name == "Valid Key"
        assert result.permissions == ["spaces:read"]
        assert result.revoked is False

        # Verify usage was updated
        container.replace_item.assert_called_once()

    @pytest.mark.asyncio
    async def test_validate_api_key_revoked(self, mock_cosmos_client):
        """Test validating revoked API key returns None."""
        client, container = mock_cosmos_client

        manager = APIKeyManager(cosmos_client=client)

        test_key = "sk_eva_live_revoked123"
        key_hash = hashlib.sha256(test_key.encode()).hexdigest()

        mock_doc = {
            "id": key_hash,
            "tenant_id": "tenant-123",
            "name": "Revoked Key",
            "key_prefix": "sk_eva_live_",
            "permissions": ["spaces:read"],
            "created_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": (datetime.now(timezone.utc) + timedelta(days=365)).isoformat(),
            "revoked": True,  # Key is revoked
        }

        container.query_items = MagicMock(return_value=iter([mock_doc]))

        result = await manager.validate_api_key(test_key)

        assert result is None

    @pytest.mark.asyncio
    async def test_validate_api_key_expired(self, mock_cosmos_client):
        """Test validating expired API key returns None."""
        client, container = mock_cosmos_client

        manager = APIKeyManager(cosmos_client=client)

        test_key = "sk_eva_live_expired123"
        key_hash = hashlib.sha256(test_key.encode()).hexdigest()

        # Expired 1 day ago
        expired_at = datetime.now(timezone.utc) - timedelta(days=1)

        mock_doc = {
            "id": key_hash,
            "tenant_id": "tenant-123",
            "name": "Expired Key",
            "key_prefix": "sk_eva_live_",
            "permissions": ["spaces:read"],
            "created_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": expired_at.isoformat(),
            "revoked": False,
        }

        container.query_items = MagicMock(return_value=iter([mock_doc]))

        result = await manager.validate_api_key(test_key)

        assert result is None

    @pytest.mark.asyncio
    async def test_validate_api_key_not_found(self, mock_cosmos_client):
        """Test validating non-existent API key returns None."""
        client, container = mock_cosmos_client

        manager = APIKeyManager(cosmos_client=client)

        # No matching key
        container.query_items = MagicMock(return_value=iter([]))

        result = await manager.validate_api_key("sk_eva_live_nonexistent123")

        assert result is None

    @pytest.mark.asyncio
    async def test_revoke_api_key(self, mock_cosmos_client):
        """Test revoking API key."""
        client, container = mock_cosmos_client

        manager = APIKeyManager(cosmos_client=client)

        mock_doc = {
            "id": "key-hash-123",
            "tenant_id": "tenant-456",
            "name": "Key to Revoke",
            "revoked": False,
        }

        container.read_item = MagicMock(return_value=mock_doc)
        container.replace_item = MagicMock()

        success = await manager.revoke_api_key("key-hash-123", "tenant-456")

        assert success is True
        container.replace_item.assert_called_once()

        # Verify revoked flag was set
        call_args = container.replace_item.call_args[1]
        updated_doc = call_args["body"]
        assert updated_doc["revoked"] is True

    @pytest.mark.asyncio
    async def test_revoke_api_key_not_found(self, mock_cosmos_client):
        """Test revoking non-existent key returns False."""
        client, container = mock_cosmos_client

        manager = APIKeyManager(cosmos_client=client)

        from azure.cosmos.exceptions import CosmosHttpResponseError

        container.read_item = MagicMock(side_effect=CosmosHttpResponseError(status_code=404, message="Not found"))

        success = await manager.revoke_api_key("nonexistent-key", "tenant-123")

        assert success is False

    @pytest.mark.asyncio
    async def test_list_api_keys(self, mock_cosmos_client):
        """Test listing API keys for tenant."""
        client, container = mock_cosmos_client

        manager = APIKeyManager(cosmos_client=client)

        mock_keys = [
            {
                "id": "key-1",
                "tenant_id": "tenant-123",
                "name": "Key 1",
                "key_prefix": "sk_eva_live_",
                "permissions": ["spaces:read"],
                "created_at": datetime.now(timezone.utc).isoformat(),
                "expires_at": (datetime.now(timezone.utc) + timedelta(days=365)).isoformat(),
                "revoked": False,
            },
            {
                "id": "key-2",
                "tenant_id": "tenant-123",
                "name": "Key 2",
                "key_prefix": "sk_eva_live_",
                "permissions": ["documents:read"],
                "created_at": datetime.now(timezone.utc).isoformat(),
                "expires_at": (datetime.now(timezone.utc) + timedelta(days=365)).isoformat(),
                "revoked": False,
            },
        ]

        container.query_items = MagicMock(return_value=iter(mock_keys))

        keys = await manager.list_api_keys("tenant-123")

        assert len(keys) == 2
        assert keys[0].name == "Key 1"
        assert keys[1].name == "Key 2"

    @pytest.mark.asyncio
    async def test_list_api_keys_exclude_revoked(self, mock_cosmos_client):
        """Test listing API keys excludes revoked by default."""
        client, container = mock_cosmos_client

        manager = APIKeyManager(cosmos_client=client)

        mock_keys = [
            {
                "id": "key-1",
                "tenant_id": "tenant-123",
                "name": "Active Key",
                "key_prefix": "sk_eva_live_",
                "permissions": ["spaces:read"],
                "created_at": datetime.now(timezone.utc).isoformat(),
                "expires_at": (datetime.now(timezone.utc) + timedelta(days=365)).isoformat(),
                "revoked": False,
            },
        ]

        container.query_items = MagicMock(return_value=iter(mock_keys))

        keys = await manager.list_api_keys("tenant-123", include_revoked=False)

        assert len(keys) == 1
        assert keys[0].name == "Active Key"

        # Verify query excludes revoked
        call_args = container.query_items.call_args[1]
        query = call_args["query"]
        assert "revoked = false" in query

    @pytest.mark.asyncio
    async def test_get_api_key_by_id(self, mock_cosmos_client):
        """Test getting API key by ID."""
        client, container = mock_cosmos_client

        manager = APIKeyManager(cosmos_client=client)

        mock_doc = {
            "id": "key-hash-123",
            "tenant_id": "tenant-456",
            "name": "Specific Key",
            "key_prefix": "sk_eva_live_",
            "permissions": ["spaces:read"],
            "created_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": (datetime.now(timezone.utc) + timedelta(days=365)).isoformat(),
            "revoked": False,
        }

        container.read_item = MagicMock(return_value=mock_doc)

        key = await manager.get_api_key_by_id("key-hash-123", "tenant-456")

        assert key is not None
        assert key.name == "Specific Key"
        assert key.id == "key-hash-123"

    @pytest.mark.asyncio
    async def test_update_api_key_permissions(self, mock_cosmos_client):
        """Test updating API key permissions."""
        client, container = mock_cosmos_client

        manager = APIKeyManager(cosmos_client=client)

        mock_doc = {
            "id": "key-hash-123",
            "tenant_id": "tenant-456",
            "name": "Key to Update",
            "permissions": ["spaces:read"],
        }

        container.read_item = MagicMock(return_value=mock_doc)
        container.replace_item = MagicMock()

        success = await manager.update_api_key_permissions(
            "key-hash-123",
            "tenant-456",
            ["spaces:read", "spaces:write", "documents:read"],
        )

        assert success is True
        container.replace_item.assert_called_once()

        # Verify permissions were updated
        call_args = container.replace_item.call_args[1]
        updated_doc = call_args["body"]
        assert updated_doc["permissions"] == [
            "spaces:read",
            "spaces:write",
            "documents:read",
        ]

    @pytest.mark.asyncio
    async def test_rotate_api_key(self, mock_cosmos_client):
        """Test rotating API key (revoke old, create new)."""
        client, container = mock_cosmos_client

        manager = APIKeyManager(cosmos_client=client)

        # Mock revoke
        old_doc = {
            "id": "old-key-hash",
            "tenant_id": "tenant-123",
            "revoked": False,
        }
        container.read_item = MagicMock(return_value=old_doc)
        container.replace_item = MagicMock()

        # Mock create
        container.create_item = MagicMock()

        result = await manager.rotate_api_key(
            old_api_key_id="old-key-hash",
            tenant_id="tenant-123",
            name="Rotated Key",
            permissions=["spaces:read"],
        )

        assert result is not None
        new_key, new_metadata = result

        # Verify new key was created
        assert new_key.startswith("sk_eva_live_")
        assert new_metadata.name == "Rotated Key"

        # Verify old key was revoked
        assert container.replace_item.called

    @pytest.mark.asyncio
    async def test_rotate_api_key_old_not_found(self, mock_cosmos_client):
        """Test rotating non-existent key returns None."""
        client, container = mock_cosmos_client

        manager = APIKeyManager(cosmos_client=client)

        from azure.cosmos.exceptions import CosmosHttpResponseError

        container.read_item = MagicMock(side_effect=CosmosHttpResponseError(status_code=404, message="Not found"))

        result = await manager.rotate_api_key(
            old_api_key_id="nonexistent-key",
            tenant_id="tenant-123",
            name="New Key",
            permissions=["spaces:read"],
        )

        assert result is None

    @pytest.mark.asyncio
    async def test_api_key_usage_tracking(self, mock_cosmos_client):
        """Test API key usage count is incremented."""
        client, container = mock_cosmos_client

        manager = APIKeyManager(cosmos_client=client)

        test_key = "sk_eva_live_usage123"
        key_hash = hashlib.sha256(test_key.encode()).hexdigest()

        mock_doc = {
            "id": key_hash,
            "tenant_id": "tenant-123",
            "name": "Usage Key",
            "key_prefix": "sk_eva_live_",
            "permissions": ["spaces:read"],
            "created_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": (datetime.now(timezone.utc) + timedelta(days=365)).isoformat(),
            "revoked": False,
            "usage_count": 5,
        }

        container.query_items = MagicMock(return_value=iter([mock_doc]))
        container.replace_item = MagicMock()

        await manager.validate_api_key(test_key)

        # Verify usage_count was incremented
        call_args = container.replace_item.call_args[1]
        updated_doc = call_args["body"]
        assert updated_doc["usage_count"] == 6

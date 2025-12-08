"""Tests for audit logger."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timezone

from eva_auth.audit.audit_logger import AuditLogger


@pytest.fixture
def mock_cosmos_client():
    """Create a mock Cosmos DB client."""
    client = MagicMock()
    database = MagicMock()
    container = MagicMock()

    client.get_database_client.return_value = database
    database.get_container_client.return_value = container

    return client, container


class TestAuditLogger:
    """Tests for AuditLogger."""

    @pytest.mark.asyncio
    async def test_init_with_custom_client(self, mock_cosmos_client):
        """Test AuditLogger initialization with custom client."""
        client, _ = mock_cosmos_client

        logger = AuditLogger(
            cosmos_client=client,
            database_name="test-db",
            container_name="test-container",
        )

        assert logger.database_name == "test-db"
        assert logger.container_name == "test-container"
        assert logger.client == client

    @pytest.mark.asyncio
    async def test_log_event(self, mock_cosmos_client):
        """Test logging generic event."""
        client, container = mock_cosmos_client

        logger = AuditLogger(cosmos_client=client)
        container.create_item = MagicMock()

        event_id = await logger.log_event(
            event_type="test.event",
            user_id="user-123",
            tenant_id="tenant-456",
            ip_address="192.168.1.1",
            user_agent="TestAgent/1.0",
            session_id="session-789",
            auth_method="test_method",
            metadata={"key": "value"},
            success=True,
        )

        assert event_id is not None
        container.create_item.assert_called_once()

        # Verify event structure
        call_args = container.create_item.call_args[1]
        event = call_args["body"]

        assert event["event_type"] == "test.event"
        assert event["user_id"] == "user-123"
        assert event["tenant_id"] == "tenant-456"
        assert event["ip_address"] == "192.168.1.1"
        assert event["user_agent"] == "TestAgent/1.0"
        assert event["session_id"] == "session-789"
        assert event["auth_method"] == "test_method"
        assert event["success"] is True
        assert event["metadata"] == {"key": "value"}

    @pytest.mark.asyncio
    async def test_log_login_success(self, mock_cosmos_client):
        """Test logging successful login."""
        client, container = mock_cosmos_client

        logger = AuditLogger(cosmos_client=client)
        container.create_item = MagicMock()

        event_id = await logger.log_login_success(
            user_id="user-123",
            tenant_id="tenant-456",
            ip_address="203.0.113.42",
            user_agent="Mozilla/5.0",
            session_id="session-abc",
            auth_method="azure_b2c",
            roles=["eva:user"],
            groups=["citizens"],
            organization="Public Services",
        )

        assert event_id is not None
        container.create_item.assert_called_once()

        call_args = container.create_item.call_args[1]
        event = call_args["body"]

        assert event["event_type"] == "auth.login.success"
        assert event["auth_method"] == "azure_b2c"
        assert event["success"] is True
        assert event["metadata"]["roles"] == ["eva:user"]
        assert event["metadata"]["groups"] == ["citizens"]
        assert event["metadata"]["organization"] == "Public Services"

    @pytest.mark.asyncio
    async def test_log_login_failure(self, mock_cosmos_client):
        """Test logging failed login attempt."""
        client, container = mock_cosmos_client

        logger = AuditLogger(cosmos_client=client)
        container.create_item = MagicMock()

        event_id = await logger.log_login_failure(
            user_id="user-789",
            tenant_id="tenant-456",
            ip_address="198.51.100.1",
            user_agent="BadActor/1.0",
            auth_method="azure_b2c",
            error_message="Invalid credentials",
            reason="invalid_password",
        )

        assert event_id is not None
        container.create_item.assert_called_once()

        call_args = container.create_item.call_args[1]
        event = call_args["body"]

        assert event["event_type"] == "auth.login.failure"
        assert event["success"] is False
        assert event["error_message"] == "Invalid credentials"
        assert event["metadata"]["reason"] == "invalid_password"

    @pytest.mark.asyncio
    async def test_log_token_refresh(self, mock_cosmos_client):
        """Test logging token refresh."""
        client, container = mock_cosmos_client

        logger = AuditLogger(cosmos_client=client)
        container.create_item = MagicMock()

        event_id = await logger.log_token_refresh(
            user_id="user-123",
            tenant_id="tenant-456",
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0",
            session_id="session-abc",
            auth_method="microsoft_entra",
        )

        assert event_id is not None
        container.create_item.assert_called_once()

        call_args = container.create_item.call_args[1]
        event = call_args["body"]

        assert event["event_type"] == "auth.token.refreshed"
        assert event["success"] is True

    @pytest.mark.asyncio
    async def test_log_logout(self, mock_cosmos_client):
        """Test logging logout."""
        client, container = mock_cosmos_client

        logger = AuditLogger(cosmos_client=client)
        container.create_item = MagicMock()

        event_id = await logger.log_logout(
            user_id="user-123",
            tenant_id="tenant-456",
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0",
            session_id="session-abc",
            auth_method="azure_b2c",
        )

        assert event_id is not None
        container.create_item.assert_called_once()

        call_args = container.create_item.call_args[1]
        event = call_args["body"]

        assert event["event_type"] == "auth.logout.success"
        assert event["success"] is True

    @pytest.mark.asyncio
    async def test_log_permission_denied(self, mock_cosmos_client):
        """Test logging permission denied event."""
        client, container = mock_cosmos_client

        logger = AuditLogger(cosmos_client=client)
        container.create_item = MagicMock()

        event_id = await logger.log_permission_denied(
            user_id="user-123",
            tenant_id="tenant-456",
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0",
            session_id="session-abc",
            resource="/api/spaces/123",
            action="delete",
            required_permission="spaces:delete",
            user_roles=["eva:viewer"],
        )

        assert event_id is not None
        container.create_item.assert_called_once()

        call_args = container.create_item.call_args[1]
        event = call_args["body"]

        assert event["event_type"] == "auth.permission.denied"
        assert event["success"] is False
        assert event["error_message"] == "Missing permission: spaces:delete"
        assert event["metadata"]["resource"] == "/api/spaces/123"
        assert event["metadata"]["action"] == "delete"
        assert event["metadata"]["user_roles"] == ["eva:viewer"]

    @pytest.mark.asyncio
    async def test_log_api_key_created(self, mock_cosmos_client):
        """Test logging API key creation."""
        client, container = mock_cosmos_client

        logger = AuditLogger(cosmos_client=client)
        container.create_item = MagicMock()

        event_id = await logger.log_api_key_created(
            user_id="admin-123",
            tenant_id="tenant-456",
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0",
            api_key_id="key-hash-abc",
            api_key_name="Production API Key",
            permissions=["spaces:read", "documents:read"],
            expires_at="2026-12-07T00:00:00Z",
        )

        assert event_id is not None
        container.create_item.assert_called_once()

        call_args = container.create_item.call_args[1]
        event = call_args["body"]

        assert event["event_type"] == "auth.apikey.created"
        assert event["success"] is True
        assert event["metadata"]["api_key_name"] == "Production API Key"
        assert event["metadata"]["permissions"] == ["spaces:read", "documents:read"]

    @pytest.mark.asyncio
    async def test_log_api_key_revoked(self, mock_cosmos_client):
        """Test logging API key revocation."""
        client, container = mock_cosmos_client

        logger = AuditLogger(cosmos_client=client)
        container.create_item = MagicMock()

        event_id = await logger.log_api_key_revoked(
            user_id="admin-123",
            tenant_id="tenant-456",
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0",
            api_key_id="key-hash-abc",
            api_key_name="Old API Key",
        )

        assert event_id is not None
        container.create_item.assert_called_once()

        call_args = container.create_item.call_args[1]
        event = call_args["body"]

        assert event["event_type"] == "auth.apikey.revoked"
        assert event["success"] is True
        assert event["metadata"]["api_key_name"] == "Old API Key"

    @pytest.mark.asyncio
    async def test_query_events_by_user(self, mock_cosmos_client):
        """Test querying events for specific user."""
        client, container = mock_cosmos_client

        logger = AuditLogger(cosmos_client=client)

        # Mock query results
        mock_events = [
            {
                "id": "event-1",
                "event_type": "auth.login.success",
                "user_id": "user-123",
                "timestamp": "2025-12-07T20:00:00Z",
            },
            {
                "id": "event-2",
                "event_type": "auth.token.refreshed",
                "user_id": "user-123",
                "timestamp": "2025-12-07T21:00:00Z",
            },
        ]
        container.query_items = MagicMock(return_value=iter(mock_events))

        events = await logger.query_events_by_user(
            user_id="user-123", tenant_id="tenant-456", limit=100
        )

        assert len(events) == 2
        assert events[0]["id"] == "event-1"
        assert events[1]["id"] == "event-2"

        container.query_items.assert_called_once()

    @pytest.mark.asyncio
    async def test_query_failed_logins(self, mock_cosmos_client):
        """Test querying failed login attempts."""
        client, container = mock_cosmos_client

        logger = AuditLogger(cosmos_client=client)

        # Mock query results
        mock_failed_logins = [
            {
                "id": "fail-1",
                "event_type": "auth.login.failure",
                "ip_address": "198.51.100.1",
                "error_message": "Invalid password",
            },
            {
                "id": "fail-2",
                "event_type": "auth.login.failure",
                "ip_address": "198.51.100.2",
                "error_message": "Account locked",
            },
        ]
        container.query_items = MagicMock(return_value=iter(mock_failed_logins))

        events = await logger.query_failed_logins(
            tenant_id="tenant-456",
            since_timestamp="2025-12-07T00:00:00Z",
            limit=100,
        )

        assert len(events) == 2
        assert events[0]["event_type"] == "auth.login.failure"
        assert events[1]["event_type"] == "auth.login.failure"

        container.query_items.assert_called_once()

    @pytest.mark.asyncio
    async def test_event_includes_timestamp(self, mock_cosmos_client):
        """Test that all events include ISO 8601 timestamps."""
        client, container = mock_cosmos_client

        logger = AuditLogger(cosmos_client=client)
        container.create_item = MagicMock()

        await logger.log_event(
            event_type="test.event",
            user_id="user-123",
            tenant_id="tenant-456",
            ip_address="192.168.1.1",
            user_agent="Test/1.0",
        )

        call_args = container.create_item.call_args[1]
        event = call_args["body"]

        # Verify timestamp is ISO 8601 format
        assert "timestamp" in event
        datetime.fromisoformat(event["timestamp"])  # Should not raise

    @pytest.mark.asyncio
    async def test_event_includes_unique_id(self, mock_cosmos_client):
        """Test that all events have unique IDs."""
        client, container = mock_cosmos_client

        logger = AuditLogger(cosmos_client=client)
        container.create_item = MagicMock()

        event_id1 = await logger.log_event(
            event_type="test.event",
            user_id="user-123",
            tenant_id="tenant-456",
            ip_address="192.168.1.1",
            user_agent="Test/1.0",
        )

        event_id2 = await logger.log_event(
            event_type="test.event",
            user_id="user-123",
            tenant_id="tenant-456",
            ip_address="192.168.1.1",
            user_agent="Test/1.0",
        )

        assert event_id1 != event_id2

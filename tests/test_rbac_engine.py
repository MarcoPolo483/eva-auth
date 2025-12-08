"""Tests for RBAC engine."""

import pytest

from eva_auth.rbac.rbac_engine import RBACEngine
from eva_auth.models import JWTClaims, RBACPolicy


@pytest.fixture
def rbac_engine():
    """Create RBAC engine instance."""
    return RBACEngine()


@pytest.fixture
def admin_claims():
    """JWT claims for admin user."""
    return JWTClaims(
        sub="admin-123",
        email="admin@example.com",
        tenant_id="tenant-456",
        roles=["eva:admin"],
        expires_at=1234567890,
    )


@pytest.fixture
def analyst_claims():
    """JWT claims for analyst user."""
    return JWTClaims(
        sub="analyst-789",
        email="analyst@example.com",
        tenant_id="tenant-456",
        roles=["eva:analyst"],
        expires_at=1234567890,
    )


@pytest.fixture
def user_claims():
    """JWT claims for regular user."""
    return JWTClaims(
        sub="user-abc",
        email="user@example.com",
        tenant_id="tenant-456",
        roles=["eva:user"],
        expires_at=1234567890,
    )


@pytest.fixture
def viewer_claims():
    """JWT claims for viewer user."""
    return JWTClaims(
        sub="viewer-def",
        email="viewer@example.com",
        tenant_id="tenant-456",
        roles=["eva:viewer"],
        expires_at=1234567890,
    )


class TestRBACEngine:
    """Tests for RBACEngine."""

    def test_admin_has_all_permissions(self, rbac_engine, admin_claims):
        """Test admin has all permissions."""
        assert rbac_engine.has_permission(admin_claims, "spaces:read")
        assert rbac_engine.has_permission(admin_claims, "spaces:write")
        assert rbac_engine.has_permission(admin_claims, "spaces:delete")
        assert rbac_engine.has_permission(admin_claims, "documents:manage")
        assert rbac_engine.has_permission(admin_claims, "users:manage")
        assert rbac_engine.has_permission(admin_claims, "audit:read")
        assert rbac_engine.has_permission(admin_claims, "system:config")

    def test_analyst_has_limited_permissions(self, rbac_engine, analyst_claims):
        """Test analyst has limited permissions."""
        # Analyst can read/write spaces and documents
        assert rbac_engine.has_permission(analyst_claims, "spaces:read")
        assert rbac_engine.has_permission(analyst_claims, "spaces:write")
        assert rbac_engine.has_permission(analyst_claims, "documents:read")
        assert rbac_engine.has_permission(analyst_claims, "documents:write")
        assert rbac_engine.has_permission(analyst_claims, "queries:execute")

        # Analyst cannot manage users or access system config
        assert not rbac_engine.has_permission(analyst_claims, "users:manage")
        assert not rbac_engine.has_permission(analyst_claims, "system:config")
        assert not rbac_engine.has_permission(analyst_claims, "audit:read")

    def test_user_has_basic_permissions(self, rbac_engine, user_claims):
        """Test regular user has basic permissions."""
        # User can read spaces and documents
        assert rbac_engine.has_permission(user_claims, "spaces:read")
        assert rbac_engine.has_permission(user_claims, "documents:read")
        assert rbac_engine.has_permission(user_claims, "documents:write")
        assert rbac_engine.has_permission(user_claims, "queries:execute")

        # User cannot delete or manage
        assert not rbac_engine.has_permission(user_claims, "spaces:delete")
        assert not rbac_engine.has_permission(user_claims, "documents:delete")
        assert not rbac_engine.has_permission(user_claims, "users:manage")

    def test_viewer_has_readonly_permissions(self, rbac_engine, viewer_claims):
        """Test viewer has read-only permissions."""
        # Viewer can only read
        assert rbac_engine.has_permission(viewer_claims, "spaces:read")
        assert rbac_engine.has_permission(viewer_claims, "documents:read")

        # Viewer cannot write or execute queries
        assert not rbac_engine.has_permission(viewer_claims, "spaces:write")
        assert not rbac_engine.has_permission(viewer_claims, "documents:write")
        assert not rbac_engine.has_permission(viewer_claims, "queries:execute")

    def test_has_any_permission(self, rbac_engine, analyst_claims):
        """Test has_any_permission returns True if user has at least one."""
        assert rbac_engine.has_any_permission(
            analyst_claims, ["spaces:read", "users:manage"]
        )

        assert not rbac_engine.has_any_permission(
            analyst_claims, ["users:manage", "system:config"]
        )

    def test_has_all_permissions(self, rbac_engine, admin_claims):
        """Test has_all_permissions returns True only if user has all."""
        assert rbac_engine.has_all_permissions(
            admin_claims, ["spaces:read", "spaces:write", "users:manage"]
        )

        assert not rbac_engine.has_all_permissions(
            admin_claims, ["spaces:read", "nonexistent:permission"]
        )

    def test_get_user_permissions(self, rbac_engine, analyst_claims):
        """Test get_user_permissions returns all permissions."""
        permissions = rbac_engine.get_user_permissions(analyst_claims)

        assert "spaces:read" in permissions
        assert "spaces:write" in permissions
        assert "documents:read" in permissions
        assert "queries:execute" in permissions
        assert "users:manage" not in permissions

    def test_has_role(self, rbac_engine, admin_claims):
        """Test has_role checks for specific role."""
        assert rbac_engine.has_role(admin_claims, "eva:admin")
        assert not rbac_engine.has_role(admin_claims, "eva:analyst")

    def test_role_hierarchy_admin(self, rbac_engine, admin_claims):
        """Test admin is higher than all other roles."""
        assert rbac_engine.has_higher_or_equal_role(admin_claims, "eva:admin")
        assert rbac_engine.has_higher_or_equal_role(admin_claims, "eva:analyst")
        assert rbac_engine.has_higher_or_equal_role(admin_claims, "eva:user")
        assert rbac_engine.has_higher_or_equal_role(admin_claims, "eva:viewer")

    def test_role_hierarchy_analyst(self, rbac_engine, analyst_claims):
        """Test analyst is higher than user and viewer."""
        assert not rbac_engine.has_higher_or_equal_role(analyst_claims, "eva:admin")
        assert rbac_engine.has_higher_or_equal_role(analyst_claims, "eva:analyst")
        assert rbac_engine.has_higher_or_equal_role(analyst_claims, "eva:user")
        assert rbac_engine.has_higher_or_equal_role(analyst_claims, "eva:viewer")

    def test_role_hierarchy_user(self, rbac_engine, user_claims):
        """Test user is higher than viewer only."""
        assert not rbac_engine.has_higher_or_equal_role(user_claims, "eva:admin")
        assert not rbac_engine.has_higher_or_equal_role(user_claims, "eva:analyst")
        assert rbac_engine.has_higher_or_equal_role(user_claims, "eva:user")
        assert rbac_engine.has_higher_or_equal_role(user_claims, "eva:viewer")

    def test_role_hierarchy_viewer(self, rbac_engine, viewer_claims):
        """Test viewer is lowest role."""
        assert not rbac_engine.has_higher_or_equal_role(viewer_claims, "eva:admin")
        assert not rbac_engine.has_higher_or_equal_role(viewer_claims, "eva:analyst")
        assert not rbac_engine.has_higher_or_equal_role(viewer_claims, "eva:user")
        assert rbac_engine.has_higher_or_equal_role(viewer_claims, "eva:viewer")

    def test_enforce_permission_success(self, rbac_engine, admin_claims):
        """Test enforce_permission succeeds when user has permission."""
        # Should not raise exception
        rbac_engine.enforce_permission(admin_claims, "spaces:read")

    def test_enforce_permission_failure(self, rbac_engine, viewer_claims):
        """Test enforce_permission raises exception when user lacks permission."""
        with pytest.raises(PermissionError, match="User lacks required permission"):
            rbac_engine.enforce_permission(viewer_claims, "spaces:delete")

    def test_enforce_role_success(self, rbac_engine, admin_claims):
        """Test enforce_role succeeds when user has required role."""
        # Should not raise exception
        rbac_engine.enforce_role(admin_claims, "eva:analyst")

    def test_enforce_role_failure(self, rbac_engine, user_claims):
        """Test enforce_role raises exception when user lacks role."""
        with pytest.raises(PermissionError, match="User lacks required role"):
            rbac_engine.enforce_role(user_claims, "eva:admin")

    def test_enforce_tenant_isolation_success(self, rbac_engine, admin_claims):
        """Test tenant isolation allows same-tenant access."""
        # Should not raise exception
        rbac_engine.enforce_tenant_isolation(admin_claims, "tenant-456")

    def test_enforce_tenant_isolation_failure(self, rbac_engine, admin_claims):
        """Test tenant isolation blocks cross-tenant access."""
        with pytest.raises(PermissionError, match="cannot access resource from tenant"):
            rbac_engine.enforce_tenant_isolation(admin_claims, "different-tenant-789")

    def test_can_manage_user_admin(self, rbac_engine, admin_claims):
        """Test admin can manage all users."""
        assert rbac_engine.can_manage_user(admin_claims, ["eva:admin"])
        assert rbac_engine.can_manage_user(admin_claims, ["eva:analyst"])
        assert rbac_engine.can_manage_user(admin_claims, ["eva:user"])
        assert rbac_engine.can_manage_user(admin_claims, ["eva:viewer"])

    def test_can_manage_user_analyst(self, rbac_engine, analyst_claims):
        """Test analyst can manage users and viewers only."""
        assert not rbac_engine.can_manage_user(analyst_claims, ["eva:admin"])
        assert not rbac_engine.can_manage_user(analyst_claims, ["eva:analyst"])
        assert rbac_engine.can_manage_user(analyst_claims, ["eva:user"])
        assert rbac_engine.can_manage_user(analyst_claims, ["eva:viewer"])

    def test_can_manage_user_regular(self, rbac_engine, user_claims):
        """Test regular user can only manage viewers."""
        assert not rbac_engine.can_manage_user(user_claims, ["eva:admin"])
        assert not rbac_engine.can_manage_user(user_claims, ["eva:analyst"])
        assert not rbac_engine.can_manage_user(user_claims, ["eva:user"])
        assert rbac_engine.can_manage_user(user_claims, ["eva:viewer"])

    def test_add_custom_policy(self, rbac_engine):
        """Test adding custom RBAC policy."""
        rbac_engine.add_custom_policy(
            "eva:researcher", ["documents:read", "queries:execute"]
        )

        researcher_claims = JWTClaims(
            sub="researcher-123",
            email="researcher@example.com",
            tenant_id="tenant-456",
            roles=["eva:researcher"],
            expires_at=1234567890,
        )

        assert rbac_engine.has_permission(researcher_claims, "documents:read")
        assert rbac_engine.has_permission(researcher_claims, "queries:execute")
        assert not rbac_engine.has_permission(researcher_claims, "documents:write")

    def test_remove_policy(self, rbac_engine):
        """Test removing RBAC policy."""
        rbac_engine.add_custom_policy("eva:temp", ["spaces:read"])
        assert rbac_engine.get_policy("eva:temp") is not None

        success = rbac_engine.remove_policy("eva:temp")
        assert success is True
        assert rbac_engine.get_policy("eva:temp") is None

    def test_remove_nonexistent_policy(self, rbac_engine):
        """Test removing non-existent policy returns False."""
        success = rbac_engine.remove_policy("eva:nonexistent")
        assert success is False

    def test_get_policy(self, rbac_engine):
        """Test getting RBAC policy."""
        policy = rbac_engine.get_policy("eva:admin")
        assert policy is not None
        assert policy.role == "eva:admin"
        assert "users:manage" in policy.permissions

    def test_list_roles(self, rbac_engine):
        """Test listing all roles."""
        roles = rbac_engine.list_roles()
        assert "eva:admin" in roles
        assert "eva:analyst" in roles
        assert "eva:user" in roles
        assert "eva:viewer" in roles

    def test_multiple_roles(self, rbac_engine):
        """Test user with multiple roles gets combined permissions."""
        multi_role_claims = JWTClaims(
            sub="multi-user-123",
            email="multi@example.com",
            tenant_id="tenant-456",
            roles=["eva:user", "eva:analyst"],
            expires_at=1234567890,
        )

        # Should have permissions from both roles
        assert rbac_engine.has_permission(multi_role_claims, "documents:read")
        assert rbac_engine.has_permission(multi_role_claims, "documents:write")
        assert rbac_engine.has_permission(multi_role_claims, "queries:execute")

        # Should have highest role for hierarchy checks
        assert rbac_engine.has_higher_or_equal_role(multi_role_claims, "eva:analyst")
        assert rbac_engine.has_higher_or_equal_role(multi_role_claims, "eva:user")

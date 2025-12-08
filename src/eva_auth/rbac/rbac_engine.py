"""RBAC (Role-Based Access Control) policy engine."""

from typing import Optional

from eva_auth.models import JWTClaims, RBACPolicy


class RBACEngine:
    """Engine for enforcing role-based access control policies."""

    # Role hierarchy: higher roles inherit permissions from lower roles
    ROLE_HIERARCHY = {
        "eva:admin": 3,
        "eva:analyst": 2,
        "eva:user": 1,
        "eva:viewer": 0,
    }

    def __init__(self):
        """Initialize RBAC engine with default policies."""
        self.policies = self._load_default_policies()

    def _load_default_policies(self) -> dict[str, RBACPolicy]:
        """Load default RBAC policies.

        Returns:
            Dictionary mapping role names to RBACPolicy objects
        """
        return {
            "eva:admin": RBACPolicy(
                role="eva:admin",
                permissions=[
                    # Space permissions
                    "spaces:read",
                    "spaces:write",
                    "spaces:delete",
                    "spaces:manage",
                    # Document permissions
                    "documents:read",
                    "documents:write",
                    "documents:delete",
                    "documents:manage",
                    # Query permissions
                    "queries:execute",
                    "queries:manage",
                    # User management
                    "users:read",
                    "users:write",
                    "users:delete",
                    "users:manage",
                    # Audit logs
                    "audit:read",
                    "audit:export",
                    # API keys
                    "apikeys:read",
                    "apikeys:create",
                    "apikeys:revoke",
                    # System
                    "system:config",
                ],
            ),
            "eva:analyst": RBACPolicy(
                role="eva:analyst",
                permissions=[
                    # Space permissions
                    "spaces:read",
                    "spaces:write",
                    # Document permissions
                    "documents:read",
                    "documents:write",
                    "documents:delete",
                    # Query permissions
                    "queries:execute",
                    # API keys (own only)
                    "apikeys:read",
                    "apikeys:create",
                ],
            ),
            "eva:user": RBACPolicy(
                role="eva:user",
                permissions=[
                    # Space permissions
                    "spaces:read",
                    # Document permissions
                    "documents:read",
                    "documents:write",
                    # Query permissions
                    "queries:execute",
                ],
            ),
            "eva:viewer": RBACPolicy(
                role="eva:viewer",
                permissions=[
                    # Read-only access
                    "spaces:read",
                    "documents:read",
                ],
            ),
        }

    def has_permission(self, claims: JWTClaims, permission: str) -> bool:
        """Check if user has specific permission.

        Args:
            claims: JWT claims containing user roles
            permission: Permission to check (e.g., "spaces:write")

        Returns:
            True if user has the permission, False otherwise
        """
        for role in claims.roles:
            policy = self.policies.get(role)
            if policy and permission in policy.permissions:
                return True
        return False

    def has_any_permission(self, claims: JWTClaims, permissions: list[str]) -> bool:
        """Check if user has any of the specified permissions.

        Args:
            claims: JWT claims containing user roles
            permissions: List of permissions to check

        Returns:
            True if user has at least one permission, False otherwise
        """
        return any(self.has_permission(claims, perm) for perm in permissions)

    def has_all_permissions(self, claims: JWTClaims, permissions: list[str]) -> bool:
        """Check if user has all specified permissions.

        Args:
            claims: JWT claims containing user roles
            permissions: List of permissions to check

        Returns:
            True if user has all permissions, False otherwise
        """
        return all(self.has_permission(claims, perm) for perm in permissions)

    def get_user_permissions(self, claims: JWTClaims) -> set[str]:
        """Get all permissions for user based on their roles.

        Args:
            claims: JWT claims containing user roles

        Returns:
            Set of all permissions user has
        """
        permissions = set()
        for role in claims.roles:
            policy = self.policies.get(role)
            if policy:
                permissions.update(policy.permissions)
        return permissions

    def has_role(self, claims: JWTClaims, role: str) -> bool:
        """Check if user has specific role.

        Args:
            claims: JWT claims containing user roles
            role: Role to check

        Returns:
            True if user has the role, False otherwise
        """
        return role in claims.roles

    def has_higher_or_equal_role(self, claims: JWTClaims, required_role: str) -> bool:
        """Check if user has a role higher than or equal to required role.

        Uses role hierarchy: eva:admin > eva:analyst > eva:user > eva:viewer

        Args:
            claims: JWT claims containing user roles
            required_role: Minimum required role

        Returns:
            True if user has sufficient role, False otherwise
        """
        required_level = self.ROLE_HIERARCHY.get(required_role, -1)
        if required_level == -1:
            return False

        for role in claims.roles:
            user_level = self.ROLE_HIERARCHY.get(role, -1)
            if user_level >= required_level:
                return True

        return False

    def enforce_permission(self, claims: JWTClaims, permission: str) -> None:
        """Enforce that user has permission, raise exception if not.

        Args:
            claims: JWT claims containing user roles
            permission: Required permission

        Raises:
            PermissionError: If user lacks the required permission
        """
        if not self.has_permission(claims, permission):
            raise PermissionError(
                f"User lacks required permission: {permission}. "
                f"User roles: {claims.roles}"
            )

    def enforce_role(self, claims: JWTClaims, required_role: str) -> None:
        """Enforce that user has required role, raise exception if not.

        Args:
            claims: JWT claims containing user roles
            required_role: Required role

        Raises:
            PermissionError: If user lacks the required role
        """
        if not self.has_higher_or_equal_role(claims, required_role):
            raise PermissionError(
                f"User lacks required role: {required_role}. "
                f"User roles: {claims.roles}"
            )

    def enforce_tenant_isolation(
        self, claims: JWTClaims, resource_tenant_id: str
    ) -> None:
        """Ensure user can only access resources in their tenant.

        Args:
            claims: JWT claims containing tenant_id
            resource_tenant_id: Tenant ID of the resource being accessed

        Raises:
            PermissionError: If user's tenant doesn't match resource tenant
        """
        if claims.tenant_id != resource_tenant_id:
            raise PermissionError(
                f"User from tenant {claims.tenant_id} cannot access "
                f"resource from tenant {resource_tenant_id}"
            )

    def can_manage_user(
        self, actor_claims: JWTClaims, target_user_roles: list[str]
    ) -> bool:
        """Check if actor can manage target user based on role hierarchy.

        Users can only manage users with lower or equal role.

        Args:
            actor_claims: JWT claims of the user performing the action
            target_user_roles: Roles of the user being managed

        Returns:
            True if actor can manage target user, False otherwise
        """
        # Admin can manage everyone
        if self.has_role(actor_claims, "eva:admin"):
            return True

        # Get actor's highest role level
        actor_max_level = max(
            (self.ROLE_HIERARCHY.get(role, -1) for role in actor_claims.roles),
            default=-1,
        )

        # Get target's highest role level
        target_max_level = max(
            (self.ROLE_HIERARCHY.get(role, -1) for role in target_user_roles),
            default=-1,
        )

        # Actor can manage users with lower role
        return actor_max_level > target_max_level

    def add_custom_policy(self, role: str, permissions: list[str]) -> None:
        """Add or update custom RBAC policy.

        Args:
            role: Role name
            permissions: List of permissions for the role
        """
        self.policies[role] = RBACPolicy(role=role, permissions=permissions)

    def remove_policy(self, role: str) -> bool:
        """Remove RBAC policy.

        Args:
            role: Role name to remove

        Returns:
            True if policy was removed, False if not found
        """
        if role in self.policies:
            del self.policies[role]
            return True
        return False

    def get_policy(self, role: str) -> Optional[RBACPolicy]:
        """Get RBAC policy for specific role.

        Args:
            role: Role name

        Returns:
            RBACPolicy if found, None otherwise
        """
        return self.policies.get(role)

    def list_roles(self) -> list[str]:
        """List all available roles.

        Returns:
            List of role names
        """
        return list(self.policies.keys())

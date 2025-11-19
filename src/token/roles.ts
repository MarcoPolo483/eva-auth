export type RoleMapping = {
  claimKey?: string; // Claim to read roles from (default: "roles")
  allowed?: string[]; // All present roles must be in this allowlist (strict)
  requiredAny?: string[]; // At least one of these must be present
  requiredAll?: string[]; // All of these must be present
};

export function extractRoles(payload: Record<string, any>, mapping: RoleMapping = {}): string[] {
  const key = mapping.claimKey ?? "roles";
  const raw = payload[key];
  if (!raw) return [];
  if (Array.isArray(raw)) return raw.filter((r) => typeof r === "string");
  if (typeof raw === "string") {
    return raw
      .split(/[;,]/)
      .map((s) => s.trim())
      .filter(Boolean);
  }
  return [];
}

export function authorizeRoles(roles: string[], mapping: RoleMapping): boolean {
  // Strict allowlist: every present role must be allowed if allowlist is given
  if (mapping.allowed && roles.some((r) => !mapping.allowed!.includes(r))) {
    return false;
  }

  // requiredAny: at least one must be present
  if (mapping.requiredAny && !roles.some((r) => mapping.requiredAny!.includes(r))) {
    return false;
  }

  // requiredAll: all must be present
  if (mapping.requiredAll && !mapping.requiredAll.every((req) => roles.includes(req))) {
    return false;
  }

  return true;
}

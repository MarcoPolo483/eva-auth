export type RoleMapping = {
  claimKey?: string;
  allowed?: string[];
  requiredAny?: string[];
};

export function extractRoles(payload: Record<string, any>, mapping: RoleMapping = {}): string[] {
  const key = mapping.claimKey ?? "roles";
  const raw = payload[key];
  if (!raw) return [];
  if (Array.isArray(raw)) return raw.filter(r => typeof r === "string");
  if (typeof raw === "string") return raw.split(/[;,]/).map(s => s.trim()).filter(Boolean);
  return [];
}

export function authorizeRoles(roles: string[], mapping: RoleMapping): boolean {
  if (mapping.allowed && !roles.every(r => mapping.allowed!.includes(r))) return false;
  if (mapping.requiredAny && !roles.some(r => mapping.requiredAny!.includes(r))) return false;
  return true;
}
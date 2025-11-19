import type { JWTPayload } from "jose";
import { decodeJwt, createRemoteJWKSet, jwtVerify } from "jose";

import {
  AuthError,
  TokenValidationError,
  TokenExpiredError,
  AudienceMismatchError,
  UnauthorizedRoleError,
} from "../util/errors.js";

import type { RoleMapping } from "./roles.js";
import { extractRoles, authorizeRoles } from "./roles.js";

export type ValidationOptions = {
  tenantId: string;
  clientId: string; // expected audience
  jwksBaseUrl?: string;
  roleMapping?: RoleMapping;
  allowedTenants?: string[]; // optional multi-tenant allowlist
  clockTolerance?: number; // seconds of leeway
};

export type ValidatedToken = {
  payload: JWTPayload & { roles?: string[] };
  raw: string;
};

export async function validateToken(raw: string, opts: ValidationOptions): Promise<ValidatedToken> {
  if (!raw) throw new TokenValidationError("Empty token");

  const decoded = safeDecode(raw);

  // Audience check (supports string or array audiences)
  if (!isAudienceOk(decoded.aud, opts.clientId)) {
    throw new AudienceMismatchError("Audience mismatch");
  }

  // Tenant enforcement from iss or fallback to tid
  const issTenant = tenantFromIss(decoded.iss) || (decoded as any).tid || (decoded as any).tenantId;
  if (!issTenant || issTenant !== opts.tenantId) {
    throw new TokenValidationError("Tenant mismatch");
  }
  if (opts.allowedTenants && !opts.allowedTenants.includes(issTenant)) {
    throw new TokenValidationError("Tenant not allowed");
  }

  // Build JWKS
  const jwksUrl =
    opts.jwksBaseUrl ?? `https://login.microsoftonline.com/${opts.tenantId}/discovery/v2.0/keys`;
  const JWKS = createRemoteJWKSet(new URL(jwksUrl));

  try {
    const { payload } = await jwtVerify(raw, JWKS, {
      audience: opts.clientId,
      issuer: decoded.iss,
      clockTolerance: opts.clockTolerance ?? 5,
    });

    if (payload.exp && payload.exp * 1000 < Date.now()) {
      throw new TokenExpiredError("Token expired");
    }

    const roles = extractRoles(payload, opts.roleMapping);
    if (opts.roleMapping && !authorizeRoles(roles, opts.roleMapping)) {
      throw new UnauthorizedRoleError("Role authorization failed");
    }

    return { payload: { ...payload, roles }, raw };
  } catch (e: any) {
    if (e instanceof AuthError) throw e;
    throw new TokenValidationError(e?.message || "Token verification failed");
  }
}

function safeDecode(raw: string) {
  try {
    return decodeJwt(raw);
  } catch {
    throw new TokenValidationError("Malformed token");
  }
}

function isAudienceOk(aud: unknown, expected: string): boolean {
  if (!aud) return false;
  if (typeof aud === "string") return aud === expected;
  if (Array.isArray(aud)) return aud.includes(expected);
  return false;
}

// Supports both sts.windows.net/<tenant>/ and login.microsoftonline.com/<tenant>/v2.0
function tenantFromIss(iss?: string): string | undefined {
  if (!iss) return undefined;
  const m1 = iss.match(/^https:\/\/login\.microsoftonline\.com\/([^/]+)(?:\/v2\.0)?\/?$/i);
  if (m1) return m1[1];
  const m2 = iss.match(/^https:\/\/sts\.windows\.net\/([^/]+)\/?$/i);
  if (m2) return m2[1];
  return undefined;
}

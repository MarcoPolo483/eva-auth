import type { JWTPayload } from "jose";
import { decodeJwt, createRemoteJWKSet, jwtVerify } from "jose";

import {
  AuthError,
  TokenValidationError,
  TokenExpiredError,
  AudienceMismatchError,
  UnauthorizedRoleError
} from "../util/errors.js";

import type { RoleMapping } from "./roles.js";
import { extractRoles, authorizeRoles } from "./roles.js";

export type ValidationOptions = {
  tenantId: string;
  clientId: string;
  jwksBaseUrl?: string;
  roleMapping?: RoleMapping;
  allowedTenants?: string[];
  clockTolerance?: number;
};

export type ValidatedToken = {
  payload: JWTPayload & { roles?: string[] };
  raw: string;
};

export async function validateToken(raw: string, opts: ValidationOptions): Promise<ValidatedToken> {
  if (!raw) throw new TokenValidationError("Empty token");
  const decoded = safeDecode(raw);
  const aud = decoded.aud;
  if (!aud || (typeof aud === "string" ? aud !== opts.clientId : !aud.includes(opts.clientId))) {
    throw new AudienceMismatchError("Audience mismatch");
  }

  const issTenant =
    decoded.iss?.match(/https:\/\/sts\.windows\.net\/([^/]+)\/?/i)?.[1] ||
    decoded.tid ||
    decoded.tenantId;

  if (!issTenant || issTenant !== opts.tenantId) {
    throw new TokenValidationError("Tenant mismatch");
  }
  if (opts.allowedTenants && !opts.allowedTenants.includes(issTenant)) {
    throw new TokenValidationError("Tenant not allowed");
  }

  const jwksUrl =
    opts.jwksBaseUrl ?? `https://login.microsoftonline.com/${opts.tenantId}/discovery/v2.0/keys`;
  const JWKS = createRemoteJWKSet(new URL(jwksUrl));

  try {
    const { payload } = await jwtVerify(raw, JWKS, {
      audience: opts.clientId,
      issuer: decoded.iss,
      clockTolerance: opts.clockTolerance ?? 5
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
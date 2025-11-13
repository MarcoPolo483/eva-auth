export enum AuthErrorCode {
  INVALID_TOKEN = "INVALID_TOKEN",
  EXPIRED_TOKEN = "EXPIRED_TOKEN",
  INVALID_AUDIENCE = "INVALID_AUDIENCE",
  INVALID_ISSUER = "INVALID_ISSUER",
  MISSING_ROLES = "MISSING_ROLES",
  FORBIDDEN = "FORBIDDEN",
  JWKS_FETCH_FAILED = "JWKS_FETCH_FAILED",
}

export class AuthError extends Error {
  constructor(
    public readonly code: AuthErrorCode,
    message: string,
    public readonly details?: unknown
  ) {
    super(message);
    this.name = "AuthError";
  }
}

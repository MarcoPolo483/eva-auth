export class AuthError extends Error {
  constructor(message: string, public code: string = "AUTH_ERROR") {
    super(message);
  }
}
export class TokenValidationError extends AuthError {
  constructor(message: string) {
    super(message, "TOKEN_INVALID");
  }
}
export class TokenExpiredError extends AuthError {
  constructor(message: string) {
    super(message, "TOKEN_EXPIRED");
  }
}
export class UnauthorizedRoleError extends AuthError {
  constructor(message: string) {
    super(message, "ROLE_UNAUTHORIZED");
  }
}
export class AudienceMismatchError extends AuthError {
  constructor(message: string) {
    super(message, "AUDIENCE_MISMATCH");
  }
}
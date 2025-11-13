export interface TokenPayload {
  sub: string;
  aud: string;
  iss: string;
  exp: number;
  iat: number;
  roles?: string[];
  [key: string]: unknown;
}

export interface RoleMapping {
  allowed?: string[];
  requiredAny?: string[];
  requiredAll?: string[];
}

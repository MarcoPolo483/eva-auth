import { describe, it, expect, vi } from "vitest";

let currentPayload: any = {};

vi.mock("jose", () => {
  return {
    decodeJwt: () => currentPayload,
    createRemoteJWKSet: () => ({}) as any,
    jwtVerify: async () => ({ payload: currentPayload }),
  };
});

import { validateToken } from "../token/validator.js";

describe("validator allowedTenants success", () => {
  it("accepts token when tenant is in allowedTenants array", async () => {
    currentPayload = {
      aud: "client-ok",
      // use login.microsoftonline issuer variant
      iss: "https://login.microsoftonline.com/tenant-allowed/v2.0",
      tid: "tenant-allowed",
      exp: Math.floor(Date.now() / 1000) + 3600,
      roles: ["user"],
      sub: "user-123",
    };

    const res = await validateToken("any.jwt", {
      tenantId: "tenant-allowed",
      clientId: "client-ok",
      allowedTenants: ["tenant-allowed", "tenant-other"],
      roleMapping: { allowed: ["user", "admin"] },
    });

    expect(res.payload.sub).toBe("user-123");
    expect(res.payload.roles).toEqual(["user"]);
  });
});

import { describe, it, expect, vi } from "vitest";

// We dynamically control the jose responses via this variable
let currentPayload: any = {};

vi.mock("jose", () => {
  return {
    decodeJwt: () => currentPayload,
    createRemoteJWKSet: () => ({}) as any,
    jwtVerify: async () => ({ payload: currentPayload }),
  };
});

import { validateToken } from "../token/validator.js";
import { UnauthorizedRoleError } from "../util/errors.js";

describe("validateToken success scenarios (mocked jose)", () => {
  it("accepts login.microsoftonline.com issuer with array audience and roles array", async () => {
    currentPayload = {
      aud: ["client-a", "client-b"],
      iss: "https://login.microsoftonline.com/my-tenant-guid/v2.0",
      tid: "my-tenant-guid",
      exp: Math.floor(Date.now() / 1000) + 3600,
      roles: ["admin", "user"],
      sub: "abc",
    };

    const res = await validateToken("any", {
      tenantId: "my-tenant-guid",
      clientId: "client-b",
      roleMapping: { allowed: ["admin", "user"], requiredAny: ["admin"] },
    });

    expect(res.payload.sub).toBe("abc");
    expect(res.payload.roles).toContain("admin");
  });

  it("accepts sts.windows.net issuer with string audience and delimited roles", async () => {
    currentPayload = {
      aud: "client-x",
      iss: "https://sts.windows.net/my-tenant-guid/",
      tid: "my-tenant-guid",
      exp: Math.floor(Date.now() / 1000) + 3600,
      roles: "user,admin",
      sub: "xyz",
    };

    const res = await validateToken("any", {
      tenantId: "my-tenant-guid",
      clientId: "client-x",
      roleMapping: { allowed: ["admin", "user"], requiredAll: ["admin", "user"] },
    });

    expect(res.payload.sub).toBe("xyz");
    expect(res.payload.roles).toEqual(expect.arrayContaining(["admin", "user"]));
  });

  it("fails role authorization when requiredAll not satisfied", async () => {
    currentPayload = {
      aud: "client-y",
      iss: "https://login.microsoftonline.com/my-tenant-guid/v2.0",
      tid: "my-tenant-guid",
      exp: Math.floor(Date.now() / 1000) + 3600,
      roles: ["admin"],
    };

    await expect(
      validateToken("any", {
        tenantId: "my-tenant-guid",
        clientId: "client-y",
        roleMapping: { requiredAll: ["admin", "ops"] },
      }),
    ).rejects.toBeInstanceOf(UnauthorizedRoleError);
  });
});

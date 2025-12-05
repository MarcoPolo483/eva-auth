import { describe, it, expect, vi } from "vitest";

// Controlled jose mocks
let currentPayload: any = {};

vi.mock("jose", () => {
  return {
    decodeJwt: () => currentPayload,
    createRemoteJWKSet: () => ({}) as any,
    jwtVerify: async () => ({ payload: currentPayload }),
  };
});

import { validateToken } from "../token/validator.js";
import { TokenExpiredError } from "../util/errors.js";

describe("validateToken edge cases (mocked jose)", () => {
  it("rejects when tenant is not in allowedTenants", async () => {
    currentPayload = {
      aud: "client-1",
      iss: "https://login.microsoftonline.com/tenant-abc/v2.0",
      tid: "tenant-abc",
      exp: Math.floor(Date.now() / 1000) + 3600,
    };

    await expect(
      validateToken("any", {
        tenantId: "tenant-abc",
        clientId: "client-1",
        allowedTenants: ["tenant-other"],
      }),
    ).rejects.toThrow(/Tenant not allowed/);
  });

  it("rejects expired tokens", async () => {
    currentPayload = {
      aud: "client-2",
      iss: "https://sts.windows.net/tenant-exp/",
      tid: "tenant-exp",
      exp: Math.floor(Date.now() / 1000) - 10, // past
    };

    await expect(
      validateToken("any", {
        tenantId: "tenant-exp",
        clientId: "client-2",
      }),
    ).rejects.toBeInstanceOf(TokenExpiredError);
  });
});

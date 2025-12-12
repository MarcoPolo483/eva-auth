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

describe("validator audience invalid type", () => {
  it("rejects when aud is not string or array (e.g., number)", async () => {
    currentPayload = {
      aud: 12345, // invalid type triggers isAudienceOk() fallback path
      iss: "https://login.microsoftonline.com/tenant-x/v2.0",
      tid: "tenant-x",
      exp: Math.floor(Date.now() / 1000) + 3600,
    };

    await expect(
      validateToken("any.jwt", {
        tenantId: "tenant-x",
        clientId: "client-y",
      }),
    ).rejects.toThrow(/Audience mismatch/);
  });
});

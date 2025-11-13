import { describe, it, expect } from "vitest";

import { validateToken } from "../token/validator.js";

describe("validateToken basic failures", () => {
  it("empty token", async () => {
    await expect(validateToken("", { tenantId: "t", clientId: "c" })).rejects.toThrow(/Empty token/);
  });

  it("malformed token", async () => {
    await expect(validateToken("not-a-jwt", { tenantId: "t", clientId: "c" })).rejects.toThrow(/Malformed token/);
  });

  it("audience mismatch", async () => {
    // Fake header & payload (base64) with aud=other
    const fake = "eyJhbGciOiJub25lIn0." + Buffer.from(JSON.stringify({ aud: "other", iss: "https://sts.windows.net/t/" })).toString("base64url") + ".sig";
    await expect(validateToken(fake, { tenantId: "t", clientId: "expected" })).rejects.toThrow(/Audience mismatch/);
  });

  it("tenant mismatch", async () => {
    const fake = "eyJhbGciOiJub25lIn0." + Buffer.from(JSON.stringify({ aud: "expected", iss: "https://sts.windows.net/OTHER/" })).toString("base64url") + ".sig";
    await expect(validateToken(fake, { tenantId: "t", clientId: "expected" })).rejects.toThrow(/Tenant mismatch/);
  });
});
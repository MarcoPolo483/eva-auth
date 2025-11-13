import { describe, it, expect } from "vitest";

import { TokenExpiredError, AudienceMismatchError } from "../util/errors.js";

describe("error classes", () => {
  it("expired error code", () => {
    const e = new TokenExpiredError("expired");
    expect(e.code).toBe("TOKEN_EXPIRED");
  });
  it("audience mismatch code", () => {
    const e = new AudienceMismatchError("aud");
    expect(e.code).toBe("AUDIENCE_MISMATCH");
  });
});
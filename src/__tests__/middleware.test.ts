import { describe, it, expect } from "vitest";

import { authMiddleware } from "../token/middleware.js";

describe("authMiddleware", () => {
  it("rejects missing bearer", async () => {
    const req: any = { headers: {} };
    const res: any = { end: (b: any) => { res.body = b; } };
    let nextCalled = false;
    await authMiddleware({ tenantId: "tid", clientId: "cid" })(req, res, () => { nextCalled = true; });
    expect(res.statusCode).toBe(401);
    expect(nextCalled).toBe(false);
    expect(JSON.parse(res.body).error).toBe("AUTH_ERROR");
  });
});
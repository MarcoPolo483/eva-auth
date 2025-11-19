import { describe, it, expect, vi } from "vitest";

// Mock validateToken to simulate a verified token
vi.mock("../token/validator.js", () => {
  return {
    validateToken: async () => ({
      payload: { sub: "user-123", roles: ["admin"] },
      raw: "t",
    }),
  };
});

import { authMiddleware } from "../token/middleware.js";

describe("authMiddleware success path", () => {
  it("sets req.user and calls next()", async () => {
    const req: any = { headers: { authorization: "Bearer abc.def.ghi" } };
    const res: any = {
      end: (b: any) => {
        res.body = b;
      },
    };
    let nextCalled = false;

    const mw = authMiddleware({ tenantId: "tid", clientId: "cid" });
    await mw(req, res, () => {
      nextCalled = true;
    });

    expect(nextCalled).toBe(true);
    expect(req.user).toEqual({ sub: "user-123", roles: ["admin"] });
    expect(res.statusCode).toBeUndefined();
  });
});

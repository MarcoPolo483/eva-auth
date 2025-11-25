import { describe, it, expect } from "vitest";

import { authMiddleware } from "../token/middleware.js";

describe("authMiddleware error cases", () => {
  it("returns 401 when Authorization header is missing", async () => {
    const req: any = { headers: {} };
    const res: any = {
      end: (b: any) => {
        res.body = b;
      },
    };
    let nextCalled = false;

    const mw = authMiddleware({ tenantId: "t", clientId: "c" });
    await mw(req, res, () => {
      nextCalled = true;
    });

    expect(nextCalled).toBe(false);
    expect(res.statusCode).toBe(401);
    const body = JSON.parse(res.body);
    expect(body.error).toBeTruthy();
    expect(body.message).toMatch(/bearer/i);
  });

  it("returns 401 when Authorization header doesn't start with Bearer", async () => {
    const req: any = { headers: { authorization: "Basic abc123" } };
    const res: any = {
      end: (b: any) => {
        res.body = b;
      },
    };
    let nextCalled = false;

    const mw = authMiddleware({ tenantId: "t", clientId: "c" });
    await mw(req, res, () => {
      nextCalled = true;
    });

    expect(nextCalled).toBe(false);
    expect(res.statusCode).toBe(401);
  });

  it("handles lowercase authorization header", async () => {
    const req: any = { headers: { authorization: "Bearer token" } };
    const res: any = {
      end: (b: any) => {
        res.body = b;
      },
    };

    const mw = authMiddleware({ tenantId: "t", clientId: "c" });
    await mw(req, res, () => {});

    expect(res.statusCode).toBe(401);
  });
});

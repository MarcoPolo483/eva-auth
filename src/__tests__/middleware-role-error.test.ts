import { describe, it, expect, vi } from "vitest";

import { UnauthorizedRoleError } from "../util/errors.js";

/* eslint-disable import/order */
import { describe, it, expect, vi } from "vitest";

import { UnauthorizedRoleError } from "../util/errors.js";

// Mock validateToken to throw a role error to exercise middleware catch path with code
vi.mock("../token/validator.js", () => {
  return {
    validateToken: async () => {
      throw new UnauthorizedRoleError("Role authorization failed");
    },
  };
});

import { authMiddleware } from "../token/middleware.js";
/* eslint-enable import/order */

describe("authMiddleware role error", () => {
  it("returns 401 with ROLE_UNAUTHORIZED when validator throws", async () => {
    const req: any = { headers: { authorization: "Bearer token" } };
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
    expect(body.error).toBe("ROLE_UNAUTHORIZED");
    expect(body.message).toMatch(/Role authorization failed/);
  });
});

import { describe, it, expect } from "vitest";

import { extractRoles, authorizeRoles } from "../token/roles.js";

describe("extractRoles edge cases", () => {
  it("returns empty array when roles claim is missing", () => {
    const roles = extractRoles({}, {});
    expect(roles).toEqual([]);
  });

  it("handles comma-separated roles string", () => {
    const roles = extractRoles({ roles: "Admin,User,Guest" }, {});
    expect(roles).toEqual(["Admin", "User", "Guest"]);
  });

  it("handles semicolon-separated roles string", () => {
    const roles = extractRoles({ roles: "Admin;User;Guest" }, {});
    expect(roles).toEqual(["Admin", "User", "Guest"]);
  });

  it("handles custom claim key", () => {
    const roles = extractRoles({ app_roles: ["Admin"] }, { claimKey: "app_roles" });
    expect(roles).toEqual(["Admin"]);
  });

  it("filters out non-string array elements", () => {
    const roles = extractRoles({ roles: ["Admin", 123, null, "User"] }, {});
    expect(roles).toEqual(["Admin", "User"]);
  });

  it("handles string with extra whitespace", () => {
    const roles = extractRoles({ roles: " Admin , User , Guest " }, {});
    expect(roles).toEqual(["Admin", "User", "Guest"]);
  });
});

describe("authorizeRoles strictness", () => {
  it("passes when no mapping restrictions", () => {
    expect(authorizeRoles(["Admin"], {})).toBe(true);
    expect(authorizeRoles(["UnknownRole"], {})).toBe(true);
  });

  it("fails when role not in allowed list", () => {
    expect(authorizeRoles(["Hacker"], { allowed: ["Admin", "User"] })).toBe(false);
  });

  it("passes when all roles in allowed list", () => {
    expect(authorizeRoles(["Admin", "User"], { allowed: ["Admin", "User", "Guest"] })).toBe(true);
  });

  it("passes with requiredAny when one role matches", () => {
    expect(authorizeRoles(["User", "Guest"], { requiredAny: ["Admin", "User"] })).toBe(true);
  });

  it("fails with requiredAny when no roles match", () => {
    expect(authorizeRoles(["Guest"], { requiredAny: ["Admin", "User"] })).toBe(false);
  });

  it("passes with requiredAll when all required roles present", () => {
    expect(authorizeRoles(["Admin", "User", "Guest"], { requiredAll: ["Admin", "User"] })).toBe(
      true,
    );
  });

  it("fails with requiredAll when missing a required role", () => {
    expect(authorizeRoles(["Admin"], { requiredAll: ["Admin", "User"] })).toBe(false);
  });

  it("handles combined restrictions", () => {
    const result = authorizeRoles(["Admin", "User"], {
      allowed: ["Admin", "User", "Guest"],
      requiredAny: ["Admin", "Moderator"],
      requiredAll: ["User"],
    });
    expect(result).toBe(true);
  });
});

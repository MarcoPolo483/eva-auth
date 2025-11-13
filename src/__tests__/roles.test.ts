import { describe, it, expect } from "vitest";

import { extractRoles, authorizeRoles } from "../token/roles.js";

describe("roles", () => {
  it("extracts array", () => {
    expect(extractRoles({ roles: ["a", "b"] })).toEqual(["a", "b"]);
  });
  it("extracts delimited string", () => {
    expect(extractRoles({ roles: "a,b;c" })).toEqual(["a", "b", "c"]);
  });
  it("authorize allowed passes", () => {
    expect(authorizeRoles(["admin"], { allowed: ["admin", "user"] })).toBe(true);
  });
  it("authorize allowed fails", () => {
    expect(authorizeRoles(["guest"], { allowed: ["admin"] })).toBe(false);
  });
  it("requiredAny passes", () => {
    expect(authorizeRoles(["billing","admin"], { requiredAny: ["admin","ops"] })).toBe(true);
  });
  it("requiredAny fails", () => {
    expect(authorizeRoles(["billing"], { requiredAny: ["admin","ops"] })).toBe(false);
  });
});
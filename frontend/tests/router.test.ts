import { describe, expect, it } from "vitest";
import { appHref } from "../src/router";

describe("app addresses", () => {
  it("put the basepath before the router's href (the stale-build reload's target)", () => {
    expect(appHref("/design")).toBe("/app/design");
    expect(appHref("/")).toBe("/app/");
    expect(appHref("/design?tab=2#x")).toBe("/app/design?tab=2#x");
    expect(appHref("design")).toBe("/app/design");
  });
});

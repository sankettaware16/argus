// What a person reads when a request fails (lib/failure.ts): the error matrix's words.
import { describe, expect, it } from "vitest";
import { failureText, retryable } from "../src/lib/failure";

describe("failureText", () => {
  it("says each kind of failure in plain words", () => {
    expect(failureText(0, null, null)).toBe("ARGUS could not be reached. Check your connection and try again.");
    expect(failureText(401, "unauthenticated", "sign in first")).toBe("Your session ended. Sign in again to continue.");
    expect(failureText(403, "csrf", "missing or wrong X-CSRF-Token")).toMatch(/refreshed\. Nothing was changed: try again\.$/);
    expect(failureText(403, "forbidden", "your account may not do this: it needs the review capability")).toBe("your account may not do this: it needs the review capability");
    expect(failureText(403, "forbidden", null)).toBe("Your account may not do this. Ask an ARGUS admin.");
    expect(failureText(403, "origin", "x")).toMatch(/did not come from this site's own page/);
    expect(failureText(404, "not_found", "no such investigation")).toBe("no such investigation");
    expect(failureText(404, null, null)).toBe("That no longer exists, or the link is wrong.");
    expect(failureText(409, "conflict", "someone else reviewed it")).toBe("someone else reviewed it");
    expect(failureText(409, "conflict", null)).toMatch(/nothing was saved/);
    expect(failureText(422, "invalid", "body.outcome: must be one of")).toBe("ARGUS did not accept that: body.outcome: must be one of");
    expect(failureText(400, "invalid", null)).toBe("ARGUS did not accept that.");
    expect(failureText(429, null, "slow down")).toBe("Too many requests just now; wait a minute and try again.");
    expect(failureText(503, "unavailable", "ARGUS cannot reach its database")).toBe("ARGUS cannot reach its database");
    expect(failureText(503, null, null)).toBe("ARGUS cannot answer just now; try again in a minute.");
    expect(failureText(500, "internal", "stack trace here")).toBe("Something went wrong in ARGUS; it has been logged. Try again, or tell an ARGUS admin.");
    expect(failureText(418, null, null)).toBe("The request was refused (418).");
  });

  it("keeps the server's sentence short, and ignores an empty one", () => {
    expect(failureText(404, null, "x".repeat(500))).toHaveLength(300);
    expect(failureText(404, null, "   ")).toBe("That no longer exists, or the link is wrong.");
  });

  it("offers a second try only where it can help", () => {
    for (const status of [0, 429, 500, 502, 503]) expect(retryable(status)).toBe(true);
    for (const status of [400, 401, 403, 404, 409, 422]) expect(retryable(status)).toBe(false);
  });
});

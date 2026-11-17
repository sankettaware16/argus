// The wait for a password confirmed in another tab: only a new, still valid confirmation counts.
import { describe, expect, it } from "vitest";
import { stepUpConfirmed } from "../src/lib/stepup";
import { opensSetup } from "../src/lib/setup";

const NOW = Date.parse("2026-11-17T10:00:00Z");

describe("a password confirmed in another tab", () => {
  it("counts when the session holds a confirmation still valid that was not there before", () => {
    expect(stepUpConfirmed(null, "2026-11-17T10:04:00Z", NOW)).toBe(true);
    expect(stepUpConfirmed("2026-11-17T09:50:00Z", "2026-11-17T10:04:00Z", NOW)).toBe(true);
    expect(stepUpConfirmed(null, null, NOW)).toBe(false);
    expect(stepUpConfirmed(null, "2026-11-17T09:59:00Z", NOW)).toBe(false); // ran out
    expect(stepUpConfirmed("2026-11-17T10:04:00Z", "2026-11-17T10:04:00Z", NOW)).toBe(false); // the old one
  });
  it("the page the step-up tab lands on never opens the setup", () => {
    expect(opensSetup(true, true, "/confirmed", false)).toBe(false);
  });
});

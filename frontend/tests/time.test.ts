import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { ago, hourWords, ist, parse, utc } from "../src/lib/time";

describe("times", () => {
  it("are IST in 12-hour form, with UTC beside in the same form", () => {
    const d = new Date("2026-10-23T09:30:00Z");
    expect(ist(d)).toBe("23 Oct 2026, 3:00 PM IST");
    expect(utc(d)).toBe("23 Oct 2026, 9:30:00 AM UTC");
  });

  it("write the user's own example, 7:20 PM IST", () => {
    expect(ist(new Date("2026-10-29T13:50:00Z"))).toBe("29 Oct 2026, 7:20 PM IST");
  });

  it("call midnight 12 AM and noon 12 PM, never 0 or 24, and cross the date at IST midnight", () => {
    expect(ist(new Date("2026-10-23T18:30:00Z"))).toBe("24 Oct 2026, 12:00 AM IST"); // 00:00 IST on the 24th
    expect(ist(new Date("2026-10-23T06:30:00Z"))).toBe("23 Oct 2026, 12:00 PM IST");
    expect(ist(new Date("2026-10-23T18:29:00Z"))).toBe("23 Oct 2026, 11:59 PM IST");
    expect(ist(new Date("2026-10-23T00:05:00Z"))).toBe("23 Oct 2026, 5:35 AM IST");
  });

  it("are always a day, a month, a year, a 12-hour clock with AM or PM and the zone, whatever the instant", () => {
    fc.assert(
      fc.property(fc.date({ min: new Date("2000-01-01T00:00:00Z"), max: new Date("2099-12-31T00:00:00Z"), noInvalidDate: true }), (d) => {
        expect(ist(d)).toMatch(/^\d{1,2} [A-Z][a-z]{2} \d{4}, (1[0-2]|[1-9]):[0-5]\d (AM|PM) IST$/);
        expect(utc(d)).toMatch(/^\d{1,2} [A-Z][a-z]{2} \d{4}, (1[0-2]|[1-9]):[0-5]\d:[0-5]\d (AM|PM) UTC$/);
      }),
    );
  });

  it("name an hour of the day for a chart's tick", () => {
    expect([0, 1, 11, 12, 13, 23].map(hourWords)).toEqual(["12 AM", "1 AM", "11 AM", "12 PM", "1 PM", "11 PM"]);
  });

  it("parse what the API sends, and nothing else", () => {
    expect(parse("2026-10-23T09:30:00Z")?.toISOString()).toBe("2026-10-23T09:30:00.000Z");
    expect(parse(null)).toBeNull();
    expect(parse(undefined)).toBeNull();
    expect(parse("yesterday")).toBeNull();
    const d = new Date(0);
    expect(parse(d)).toBe(d);
  });

  it("say how long ago in plain words", () => {
    const now = new Date("2026-10-23T12:00:00Z");
    const at = (s: number) => new Date(now.getTime() - s * 1000);
    expect(ago(at(-120), now)).toBe("in the future");
    expect(ago(at(-30), now)).toBe("just now");
    expect(ago(at(59), now)).toBe("just now");
    expect(ago(at(60), now)).toBe("1 min ago");
    expect(ago(at(3599), now)).toBe("59 min ago");
    expect(ago(at(3600), now)).toBe("1 h ago");
    expect(ago(at(47 * 3600), now)).toBe("47 h ago");
    expect(ago(at(48 * 3600), now)).toBe("2 d ago");
  });
});

// Numbers and spans as the classic dashboard writes them (lib/format.ts); the expected words come
// from src/argus/web/dashboard.py `duration` run on the same inputs.
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { capped, count, duration, percent, plural, serverTime, versusBefore } from "../src/lib/format";

describe("duration", () => {
  it("says what the classic page says", () => {
    const cases: [number | null, string][] = [
      [null, "—"], [0, "0 min"], [59, "0 min"], [60, "1 min"], [3599, "59 min"], [3600, "1 h"], [3660, "1 h 1 min"],
      [12000, "3 h 20 min"], [172799, "47 h 59 min"], [172800, "2 days"], [176400, "2 days 1 h"], [500000, "5 days 18 h"],
    ];
    for (const [seconds, words] of cases) expect(duration(seconds)).toBe(words);
    expect(duration(undefined)).toBe("—");
  });

  it("never goes backwards as the time grows", () => {
    const rank = (text: string) => {
      const n = (re: RegExp) => Number(re.exec(text)?.[1] ?? 0);
      return n(/(\d+) days/) * 1440 + n(/(\d+) h/) * 60 + n(/(\d+) min/);
    };
    fc.assert(fc.property(fc.integer({ min: 0, max: 5_000_000 }), fc.integer({ min: 0, max: 5_000_000 }), (a, b) => {
      const [low, high] = a <= b ? [a, b] : [b, a];
      expect(rank(duration(low))).toBeLessThanOrEqual(rank(duration(high)));
    }));
  });
});

describe("the small words", () => {
  it("compares with the span before", () => {
    expect(versusBefore(10, 0)).toBe("none in the span before");
    expect(versusBefore(150, 100)).toBe("+50% vs the span before (100)");
    expect(versusBefore(50, 100)).toBe("−50% vs the span before (100)");
    expect(versusBefore(100, 100)).toBe("+0% vs the span before (100)");
    expect(versusBefore(1, 3)).toBe("−67% vs the span before (3)");
    expect(versusBefore(2_00_000, 1_00_000)).toBe("+100% vs the span before (1,00,000)");
  });

  it("writes counts with Indian grouping, percentages, plurals and capped counts", () => {
    expect(count(1234567)).toBe("12,34,567");
    expect(percent(1, 3)).toBe("33%");
    expect(percent(1, 3, 1)).toBe("33.3%");
    expect(percent(0, 0)).toBeNull();
    expect(plural(1, "alert")).toBe("alert");
    expect(plural(2, "alert")).toBe("alerts");
    expect(plural(0, "was", "were")).toBe("were");
    expect(capped(9999, 10_000)).toBe("9,999");
    expect(capped(10_000, 10_000)).toBe("10,000 or more");
    expect(serverTime(850)).toBe("850 ms");
    expect(serverTime(2100)).toBe("2.1 s");
    expect(serverTime(999.6)).toBe("1000 ms");
  });
});

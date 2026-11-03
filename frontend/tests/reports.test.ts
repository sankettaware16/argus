// The Reports page's words: a figure said the way the server's text says it, titles and file names.
import { describe, expect, it } from "vitest";
import { asJson, asText, duration, durationMs, escapeHidden, fileName, lastDay, shown, title, validReportId } from "../src/lib/reports";

describe("durations", () => {
  it("are exact, with zero parts left out", () => {
    expect(duration(0)).toBe("0 s");
    expect(duration(59)).toBe("59 s");
    expect(duration(60)).toBe("1 min");
    expect(duration(3903)).toBe("1 h 5 min 3 s");
    expect(duration(86_400)).toBe("24 h");
    expect(duration(-5)).toBe("0 s");
    expect(durationMs(0)).toBe("0 ms");
    expect(durationMs(999)).toBe("999 ms");
    expect(durationMs(1000)).toBe("1 s");
    expect(durationMs(3_903_250)).toBe("1 h 5 min 3 s 250 ms");
  });

  it("give back the number they were made from", () => {
    for (let n = 0; n < 200_000; n += 997) {
      const parts = Object.fromEntries([...duration(n).matchAll(/(\d+) (h|min|s)/g)].map((m) => [m[2], Number(m[1])]));
      expect((parts.h ?? 0) * 3600 + (parts.min ?? 0) * 60 + (parts.s ?? 0)).toBe(n);
    }
  });
});

describe("a figure", () => {
  it("is said by its unit", () => {
    expect(shown({ value: 12, unit: "count" })).toBe("12");
    expect(shown({ value: 1234, unit: "count" })).toBe("1234"); // as the server's text says it: no grouping
    expect(shown({ value: 26, unit: "hours" })).toBe("26 hours");
    expect(shown({ value: 1234, unit: "hours" })).toBe("1234 hours");
    expect(shown({ value: 66.7, unit: "percent" })).toBe("66.7%");
    expect(shown({ value: 0, unit: "percent" })).toBe("0.0%");
    expect(shown({ value: 100, unit: "percent" })).toBe("100.0%");
    expect(shown({ value: 3_903_250, unit: "ms" })).toBe("1 h 5 min 3 s 250 ms");
    expect(shown({ value: 3903, unit: "seconds" })).toBe("1 h 5 min 3 s");
    expect(shown({ value: 1, unit: "hours" })).toBe("1 hour");
    expect(shown({ value: 26, unit: "hours" })).toBe("26 hours");
    expect(shown({ value: "ab12", unit: "text" })).toBe("ab12");
  });

  it("says n/a when there is nothing to say, never 0", () => {
    expect(shown({ value: null, unit: "count" })).toBe("n/a");
    expect(shown({ value: null, unit: "seconds" })).toBe("n/a");
    expect(shown({ value: null, unit: "percent" })).toBe("n/a");
  });
});

describe("a report's name", () => {
  const daily = { kind: "daily" as const, period_start: "2026-10-20T00:00:00Z", period_end: "2026-10-21T00:00:00Z" };
  const weekly = { kind: "weekly" as const, period_start: "2026-10-14T00:00:00Z", period_end: "2026-10-21T00:00:00Z" };

  it("is by the UTC days it covers", () => {
    expect(lastDay(daily)).toBe("2026-10-20");
    expect(lastDay(weekly)).toBe("2026-10-20");
    expect(title(daily)).toBe("Daily report for 20 Oct 2026");
    expect(title(weekly)).toBe("Weekly report, 14 Oct 2026 to 20 Oct 2026");
  });

  it("makes the file names", () => {
    expect(fileName(daily, "txt")).toBe("argus-daily-report-2026-10-20.txt");
    expect(fileName(weekly, "json")).toBe("argus-weekly-report-2026-10-20.json");
  });

  it("downloads the server's own text, with the prose first when there is some", () => {
    const base = { id: 1, ...daily, generated_at: "2026-10-21T06:00:00Z", as_at: "2026-10-21T06:00:00Z", sections: [], text: "FIGURES\n" };
    expect(asText({ ...base, prose: null })).toBe("FIGURES\n");
    expect(asText({ ...base, prose: "Words." })).toBe("Words.\n\nFIGURES\n");
    expect(JSON.parse(asJson({ ...base, prose: null })).text).toBe("FIGURES\n");
  });

  it("escapes hidden characters of the summary in the text download, as the server does for names", () => {
    const base = { id: 1, ...daily, generated_at: "2026-10-21T06:00:00Z", as_at: "2026-10-21T06:00:00Z", sections: [], text: "FIGURES\n" };
    const hostile = "7 cases.\n\u202eexe\u200b\u{e0041}\u0007 ok\there";
    expect(escapeHidden(hostile)).toBe("7 cases.\n\\u202eexe\\u200b\\U000e0041\\x07 ok\there");
    expect(asText({ ...base, prose: hostile })).toBe(`${escapeHidden(hostile)}\n\nFIGURES\n`);
    for (const hidden of ["\u202e", "\u200b", "\u0007"]) expect(asText({ ...base, prose: hostile })).not.toContain(hidden);
  });
});

describe("a report id", () => {
  it("is any the API accepts: 1 to 2^62, no sign and no leading zero", () => {
    for (const id of ["1", "42", "9007199254740993", "4611686018427387904"]) expect(validReportId(id)).toBe(true);
    for (const id of ["", "0", "01", "-1", "1.5", "abc", "4611686018427387905", "99999999999999999999", " 1", "1 "]) expect(validReportId(id)).toBe(false);
  });
});

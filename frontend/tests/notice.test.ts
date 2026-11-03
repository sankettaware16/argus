// AR4b on the case page: what a form checks before it shows the request, the request bodies, and
// the words of managed or personal.
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { blockBody, blockProblem, HOW, HOW_KEYS, istInstant, istStamp, lineProblem, managedWords, noticeBody, noticeProblem, textProblem, whenProblem, whenWords, withdrawBody, withdrawProblem } from "../src/lib/notice";

const NOW = new Date("2026-10-29T10:00:00Z");
const draft = { told: "Hostel 5 warden", how: "phone", at: "", note: "" };

describe("a line of words", () => {
  it("needs a letter, one line, and not too many", () => {
    expect(lineProblem("Who", "the warden", 200)).toBeNull();
    expect(lineProblem("Who", "", 200)).toBe("Who is needed.");
    expect(lineProblem("Who", "   ", 200)).toBe("Who is needed.");
    expect(lineProblem("Who", "x".repeat(201), 200)).toBe("Who has at most 200 characters.");
    expect(lineProblem("Who", "a\nb", 200)).toBe("Who must be one line, without control characters.");
    expect(lineProblem("Who", "a\u0000b", 200)).toMatch(/one line/);
    expect(lineProblem("Who", "a\u007fb", 200)).toMatch(/one line/);
    expect(lineProblem("Who", "a\u0085b", 200)).toMatch(/one line/);
    expect(lineProblem("Where", "x".repeat(100), 100)).toBeNull();
  });

  it("is judged after the spaces at its ends are cut", () => {
    expect(lineProblem("Who", ` ${"x".repeat(200)} `, 200)).toBeNull();
  });
});

describe("free text", () => {
  it("is optional or required, at most 4,000 characters, and has no NUL", () => {
    expect(textProblem("The note", "", false)).toBeNull();
    expect(textProblem("The reason", "  ", true)).toBe("The reason is needed.");
    expect(textProblem("The note", "x".repeat(4001), false)).toBe("The note has at most 4000 characters.");
    expect(textProblem("The note", "a\u0000", false)).toBe("The note holds a character ARGUS cannot keep.");
    expect(textProblem("The note", "multi\nline", false)).toBeNull();
  });
});

describe("the time", () => {
  it("is a time of the campus clock, whatever the browser's zone", () => {
    expect(istInstant("2026-10-26T09:30")?.toISOString()).toBe("2026-10-26T04:00:00.000Z");
    expect(istInstant("")).toBeNull();
    expect(istInstant("  ")).toBeNull();
    expect(istInstant("yesterday")).toBeUndefined();
    expect(istInstant("2026-10-26")).toBeUndefined();
    expect(istInstant("2026-13-40T99:99")).toBeUndefined();
  });

  it("refuses a day or an hour that does not exist instead of recording the next one (AR4 review)", () => {
    for (const impossible of ["2026-02-31T10:00", "2026-02-30T10:00", "2026-04-31T10:00", "2027-02-29T10:00", "2026-10-26T24:00", "2026-10-26T25:30", "2026-10-26T09:60", "2026-00-10T09:00", "2026-10-00T09:00"]) {
      expect(istInstant(impossible), impossible).toBeUndefined();
      expect(whenProblem(impossible, NOW), impossible).toMatch(/date and a time/);
      expect(istStamp(impossible), impossible).toBeNull();
    }
    expect(istInstant("2028-02-29T10:00")?.toISOString()).toBe("2028-02-29T04:30:00.000Z"); // a leap day is a day
    expect(istInstant("2026-10-26T23:59")?.toISOString()).toBe("2026-10-26T18:29:00.000Z");
    expect(istInstant("2026-10-26T00:00")?.toISOString()).toBe("2026-10-25T18:30:00.000Z");
  });

  it("holds for every date-and-time that comes back as the one typed", () => {
    fc.assert(
      fc.property(fc.date({ min: new Date("2020-01-01T00:00:00Z"), max: new Date("2035-12-31T00:00:00Z"), noInvalidDate: true }), (d) => {
        const wall = new Date(d.getTime() + 5.5 * 3_600_000).toISOString().slice(0, 16); // the IST wall clock of d
        expect(istInstant(wall)?.getTime()).toBe(Math.floor(d.getTime() / 60_000) * 60_000);
        expect(istStamp(wall)).toBe(`${wall}:00+05:30`);
      }),
    );
  });

  it("is written in the request as the person typed it, with its offset, and in the dialog in 12-hour form", () => {
    expect(istStamp("2026-10-26T09:30")).toBe("2026-10-26T09:30:00+05:30");
    expect(istStamp("")).toBeNull();
    expect(whenWords("2026-10-26T19:20")).toBe("It is dated 26 Oct 2026, 7:20 PM IST.");
    expect(whenWords("")).toBe("It is dated when you send it.");
    expect(whenWords("2026-02-31T10:00")).toBe("It is dated when you send it.");
  });

  it("may be now or the past up to a year, never the future", () => {
    expect(whenProblem("", NOW)).toBeNull();
    expect(whenProblem("2026-10-29T15:30", NOW)).toBeNull(); // 10:00 UTC is 3:30 PM IST: now
    expect(whenProblem("2026-10-29T15:34", NOW)).toBeNull(); // inside the server's five minutes of slack
    expect(whenProblem("2026-10-29T15:36", NOW)).toBe("That time is in the future. Leave it empty for now.");
    expect(whenProblem("2025-10-30T00:00", NOW)).toBeNull();
    expect(whenProblem("2025-10-01T00:00", NOW)).toBe("That time is more than a year ago.");
    // a year below 100 is that year (Date.UTC would read it as 19xx): far back, not "no time"
    expect(whenProblem("0050-06-15T09:30", NOW)).toBe("That time is more than a year ago.");
    expect(whenProblem("soon", NOW)).toBe("Write the time as a date and a time (IST).");
  });
});

describe("a notice", () => {
  it("needs who was told and how, and checks the rest", () => {
    expect(noticeProblem(draft, NOW)).toBeNull();
    expect(noticeProblem({ ...draft, how: "" }, NOW)).toBe("Choose how the owner was told.");
    expect(noticeProblem({ ...draft, how: "carrier pigeon" }, NOW)).toBe("Choose how the owner was told.");
    expect(noticeProblem({ ...draft, told: "" }, NOW)).toBe("Who was told is needed.");
    expect(noticeProblem({ ...draft, at: "2030-01-01T00:00" }, NOW)).toMatch(/future/);
    expect(noticeProblem({ ...draft, note: "x".repeat(4001) }, NOW)).toMatch(/at most 4000/);
    for (const how of HOW_KEYS) expect(noticeProblem({ ...draft, how }, NOW)).toBeNull();
    expect(Object.keys(HOW)).toEqual(["email", "phone", "in_person", "through_it", "other"]);
  });

  it("is sent with only what was filled in, the time as an instant, and the version seen", () => {
    expect(noticeBody(7, draft)).toEqual({ expected_version: 7, told: "Hostel 5 warden", how: "phone" });
    expect(noticeBody(7, { told: " the warden ", how: "email", at: "2026-10-26T09:30", note: " she will bring it in " })).toEqual({
      expected_version: 7,
      told: "the warden",
      how: "email",
      at: "2026-10-26T09:30:00+05:30",
      note: "she will bring it in",
    });
  });

  it("is never a problem and a body at once: whatever passes the check makes a body the server's schema takes", () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 260 }), fc.constantFrom(...HOW_KEYS), fc.string({ maxLength: 20 }), (told, how, note) => {
        if (noticeProblem({ told, how, at: "", note }, NOW) !== null) return;
        const body = noticeBody(1, { told, how, at: "", note });
        expect(body.told.length).toBeGreaterThan(0);
        expect(body.told.length).toBeLessThanOrEqual(200);
        expect(body.told).toBe(body.told.trim());
        // eslint-disable-next-line no-control-regex
        expect(/[\u0000-\u001f\u007f-\u009f]/.test(body.told)).toBe(false);
      }),
    );
  });
});

describe("a network block", () => {
  const block = { by: "the network team", where: "DNS", at: "", note: "" };

  it("needs who and where", () => {
    expect(blockProblem(block, NOW)).toBeNull();
    expect(blockProblem({ ...block, by: "" }, NOW)).toBe("Who blocked it is needed.");
    expect(blockProblem({ ...block, where: "" }, NOW)).toBe("Where it was blocked is needed.");
    expect(blockProblem({ ...block, where: "x".repeat(101) }, NOW)).toBe("Where it was blocked has at most 100 characters.");
    expect(blockProblem({ ...block, at: "2031-01-01T00:00" }, NOW)).toMatch(/future/);
  });

  it("is sent with only what was filled in", () => {
    expect(blockBody(3, block)).toEqual({ expected_version: 3, by: "the network team", where: "DNS" });
    expect(blockBody(3, { ...block, at: "2026-10-26T09:30", note: "n" })).toMatchObject({ at: "2026-10-26T09:30:00+05:30", note: "n" });
  });
});

describe("a withdrawal", () => {
  it("needs the reason; who is the person unless named", () => {
    expect(withdrawProblem({ who: "", reason: "wrong case" })).toBeNull();
    expect(withdrawProblem({ who: "", reason: "" })).toBe("The reason is needed.");
    expect(withdrawProblem({ who: "a\nb", reason: "x" })).toMatch(/one line/);
    expect(withdrawProblem({ who: "Mina", reason: "x" })).toBeNull();
    expect(withdrawBody(2, { who: "", reason: " wrong case " })).toEqual({ expected_version: 2, reason: "wrong case" });
    expect(withdrawBody(2, { who: " Mina ", reason: "r" })).toEqual({ expected_version: 2, who: "Mina", reason: "r" });
  });
});

describe("managed or personal", () => {
  it("says which, and what ACME can do about it", () => {
    expect(managedWords(true)).toMatch(/university-managed machines.*ACME can act on them/);
    expect(managedWords(false)).toMatch(/personal devices.*cannot wipe or isolate it/);
    expect(managedWords(null)).toMatch(/Once the owner is told/);
  });
});

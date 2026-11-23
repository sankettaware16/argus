import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { bidiRuns, DEFAULT_LIMITS, HARD_MAX, isMarked, markOf, original, segments, toAscii, type Segment } from "../src/lib/untrusted";

const SPECIAL = [
  0x00, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x1b, 0x1f, 0x7f, 0x80, 0x85, 0x9f, 0xa0, 0xad, 0x34f, 0x61c, 0x115f,
  0x180e, 0x200b, 0x200c, 0x200d, 0x200e, 0x200f, 0x2028, 0x2029, 0x202a, 0x202e, 0x2060, 0x2063, 0x2066, 0x2069,
  0x206f, 0x2800, 0x3164, 0xfeff, 0xfff9, 0xfffb, 0xe0001, 0xe0041, 0xe007f, 0xe0100, 0xe01ef, 0x430, 0xff45, 0x3002,
  0xff0e, 0x2e, 0x2d, 0x61, 0x5d0, 0x627, 0x1f600,
];
// text built from ordinary characters, every special one, lone surrogates and dots
const piece = fc.oneof(
  fc.string({ maxLength: 8 }),
  fc.constantFrom(...SPECIAL).map((c) => String.fromCodePoint(c)),
  fc.constantFrom("\uD800", "\uDFFF", "\uD83D", ".", "\r\n", "\n", "example.com", "\u0430pple.com", "b\u00fccher.de"),
  fc.string({ unit: "binary", maxLength: 6 }),
);
const text = fc.array(piece, { maxLength: 40 }).map((parts) => parts.join(""));

function points(s: string): number {
  return Array.from(s).length;
}

describe("segments", () => {
  it("keeps every character within the caps, CRLF read as one break", () => {
    fc.assert(
      fc.property(text, (s) => {
        const parts = segments(s, { maxChars: HARD_MAX, maxLines: HARD_MAX });
        expect(original(parts)).toBe(s.replace(/\r\n/g, "\n"));
        expect(parts.some((p) => p.kind === "cut")).toBe(false);
      }),
    );
  });

  it("never lets a marked character through as text", () => {
    fc.assert(
      fc.property(text, (s) => {
        for (const part of segments(s, { maxChars: HARD_MAX, maxLines: HARD_MAX })) {
          if (part.kind === "text" || part.kind === "idn") {
            for (const ch of part.text) expect(isMarked(ch.codePointAt(0) as number)).toBe(false);
          }
          if (part.kind === "mark") {
            expect(isMarked(part.code)).toBe(true);
            expect(part.label.length).toBeGreaterThan(0);
            expect(part.name).toMatch(/^U\+[0-9A-F]{4,5} /);
          }
        }
      }),
    );
  });

  it("shows at most the caps, and says how much is hidden", () => {
    fc.assert(
      fc.property(text, fc.integer({ min: 0, max: 60 }), fc.integer({ min: 1, max: 8 }), (s, maxChars, maxLines) => {
        const parts = segments(s, { maxChars, maxLines });
        const shown = original(parts);
        const cut = parts.filter((p): p is Extract<Segment, { kind: "cut" }> => p.kind === "cut");
        expect(cut.length).toBeLessThanOrEqual(1);
        expect(points(shown)).toBeLessThanOrEqual(maxChars);
        expect(shown.split("\n").length).toBeLessThanOrEqual(maxLines);
        const total = points(s);
        const crlf = s.split("\r\n").length - 1;
        if (cut.length === 0) {
          expect(shown).toBe(s.replace(/\r\n/g, "\n"));
        } else {
          const hidden = cut[0]?.hidden ?? 0;
          expect(hidden).toBeGreaterThan(0);
          expect(hidden + points(shown)).toBeLessThanOrEqual(total);
          expect(hidden + points(shown) + crlf).toBeGreaterThanOrEqual(total);
          // what is shown is the start of the value (a CR before a shown LF dropped)
          expect(s.replace(/\r\n/g, "\n").startsWith(shown) || s.startsWith(shown) || shown.endsWith("\r")).toBe(true);
        }
      }),
    );
  });

  it("puts the ASCII form beside every non-ASCII domain, and only beside those", () => {
    fc.assert(
      fc.property(text, (s) => {
        for (const part of segments(s, { maxChars: HARD_MAX, maxLines: HARD_MAX })) {
          if (part.kind !== "idn") continue;
          expect(/[^\x20-\x7e]/.test(part.text)).toBe(true);
          if (part.ascii !== null) expect(part.ascii).toMatch(/^[\x21-\x7e]+$/);
        }
      }),
    );
  });

  it("caps a long value in linear time", () => {
    const long = `${"a".repeat(50_000)}\u00e9${"-".repeat(50_000)}\u00e9.${"b".repeat(50_000)}`;
    const started = performance.now();
    const parts = segments(long, { maxChars: HARD_MAX, maxLines: HARD_MAX });
    expect(performance.now() - started).toBeLessThan(2_000);
    expect(parts.at(-1)).toEqual({ kind: "cut", hidden: points(long) - HARD_MAX, lines: false });
  });

  it("shows the cases the gate names", () => {
    expect(segments("invoice_\u202efdp.exe")).toEqual([
      { kind: "text", text: "invoice_" },
      { kind: "mark", code: 0x202e, label: "RLO", name: "U+202E right-to-left override" },
      { kind: "text", text: "fdp.exe" },
    ]);
    expect(segments("at \u0430pple.com.")).toEqual([
      { kind: "text", text: "at " },
      { kind: "idn", text: "\u0430pple.com", ascii: "xn--pple-43d.com" },
      { kind: "text", text: "." },
    ]);
    expect(segments("\uff45\uff58\uff41\uff4d\uff50\uff4c\uff45\uff0ecom")).toEqual([
      { kind: "idn", text: "\uff45\uff58\uff41\uff4d\uff50\uff4c\uff45\uff0ecom", ascii: "example.com" },
    ]);
    expect(segments("x\u{E0068}\u{E0069}")).toEqual([
      { kind: "text", text: "x" },
      { kind: "mark", code: 0xe0068, label: "TAG h", name: 'U+E0068 tag character, hidden "h"' },
      { kind: "mark", code: 0xe0069, label: "TAG i", name: 'U+E0069 tag character, hidden "i"' },
    ]);
    expect(segments("a\u0001b")[1]).toMatchObject({ kind: "mark", label: "^A" });
    expect(segments("\uD800")[0]).toMatchObject({ kind: "mark", label: "BAD" });
    expect(segments("<script>alert(1)</script>")).toEqual([{ kind: "text", text: "<script>alert(1)</script>" }]);
    expect(segments("tab\there\nnext\u00a0line")).toEqual([{ kind: "text", text: "tab\there\nnext\u00a0line" }]);
    expect(segments("a\r\nb\rc")).toEqual([
      { kind: "text", text: "a\nb" },
      { kind: "mark", code: 0x0d, label: "CR", name: "U+000D carriage return" },
      { kind: "text", text: "c" },
    ]);
    expect(segments(null)).toEqual([]);
    expect(segments(undefined)).toEqual([]);
    expect(segments(42)).toEqual([{ kind: "text", text: "42" }]);
    expect(segments({ toString: () => "<b>" })).toEqual([{ kind: "text", text: "<b>" }]);
  });

  it("caps by characters and by lines, with the defaults", () => {
    const many = Array.from({ length: 60 }, (_, i) => `line ${i}`).join("\n");
    const cut = segments(many).at(-1);
    expect(cut).toMatchObject({ kind: "cut", lines: true });
    expect(original(segments(many)).split("\n")).toHaveLength(DEFAULT_LIMITS.maxLines);
    const long = "x".repeat(DEFAULT_LIMITS.maxChars + 5);
    expect(segments(long).at(-1)).toEqual({ kind: "cut", hidden: 5, lines: false });
    expect(segments("abc", { maxChars: 0, maxLines: 1 })).toEqual([{ kind: "cut", hidden: 3, lines: false }]);
    expect(segments("a\nb", { maxChars: 10, maxLines: 0 })).toEqual([
      { kind: "text", text: "a" },
      { kind: "cut", hidden: 2, lines: true },
    ]);
    expect(segments("abc", { maxChars: 2.9, maxLines: 1 })).toEqual([
      { kind: "text", text: "ab" },
      { kind: "cut", hidden: 1, lines: false },
    ]);
    expect(segments("x".repeat(10), { maxChars: HARD_MAX * 2, maxLines: 1 })).toEqual([{ kind: "text", text: "x".repeat(10) }]);
    // a CR at the very end of what is shown stays visible: its LF is not shown
    expect(segments("ab\r\ncd", { maxChars: 3, maxLines: 5 })).toEqual([
      { kind: "text", text: "ab" },
      { kind: "mark", code: 0x0d, label: "CR", name: "U+000D carriage return" },
      { kind: "cut", hidden: 3, lines: false },
    ]);
  });
});

describe("marks", () => {
  it("names what it knows and spells out the rest", () => {
    expect(markOf(0x200b)).toEqual({ label: "ZWSP", name: "U+200B zero-width space" });
    expect(markOf(0x2061)).toEqual({ label: "U+2061", name: "U+2061 invisible or format character" });
    expect(markOf(0x1b)).toEqual({ label: "ESC", name: "U+001B escape" });
    expect(markOf(0x02)).toEqual({ label: "^B", name: "U+0002 control" });
    expect(markOf(0xdc00)).toEqual({ label: "BAD", name: "U+DC00 broken UTF-16" });
    expect(markOf(0x90)).toEqual({ label: "U+0090", name: "U+0090 invisible or format character" });
    expect(markOf(0xe0001)).toEqual({ label: "U+E0001", name: "U+E0001 invisible or format character" });
    expect(markOf(0xe007f).label).toBe("U+E007F");
  });

  it("marks exactly the invisible and reordering ranges", () => {
    const yes = [0x00, 0x08, 0x0b, 0x0d, 0x1f, 0x7f, 0x80, 0x9f, 0xad, 0x34f, 0x61c, 0x115f, 0x1160, 0x17b4, 0x17b5,
      0x180b, 0x180f, 0x200b, 0x200f, 0x2028, 0x202a, 0x202e, 0x2060, 0x2061, 0x2064, 0x2066, 0x2069, 0x206a, 0x206f,
      0x2800, 0x3164, 0xfeff, 0xffa0, 0xfff9, 0xfffb, 0xd800, 0xdfff, 0xe0000, 0xe007f, 0xe0100, 0xe01ef,
      // review F3: default-ignorable, unassigned or not, and format characters
      0x2065, 0xfff0, 0xfff8, 0xe0080, 0xe00ff, 0xe01f0, 0xe0fff, 0x600, 0x110bd];
    const no = [0x09, 0x0a, 0x20, 0x41, 0x7e, 0xa0, 0xa1, 0x34e, 0x350, 0x61b, 0x61d, 0x180a, 0x1810, 0x2010, 0x2027,
      0x202f, 0x2070, 0x27ff, 0x2801, 0xfefe, 0xff00, 0xfffc, 0xfffd, 0xd7ff, 0xe000, 0xdffff, 0xe1000, 0x1f600,
      0xfe00, 0xfe0f, 0xfdff, 0xfe10];
    for (const c of yes) expect(isMarked(c), c.toString(16)).toBe(true);
    for (const c of no) expect(isMarked(c), c.toString(16)).toBe(false);
  });
});

describe("toAscii", () => {
  it("is the browser's IDNA, or null", () => {
    expect(toAscii("b\u00fccher.example")).toBe("xn--bcher-kva.example");
    expect(toAscii("a b.com")).toBeNull();
    expect(toAscii("x".repeat(1100))).toBeNull();
    expect(toAscii("%41.com")).toBeNull();
  });
});

describe("asText", () => {
  it("shows any value as text, even one that refuses to be text", () => {
    expect(segments({ toString: () => { throw new Error("no"); } })).toEqual([
      { kind: "text", text: "[a value that cannot be shown as text]" },
    ]);
    expect(segments(Symbol("s"))).toEqual([{ kind: "text", text: "Symbol(s)" }]);
    expect(segments(12n)).toEqual([{ kind: "text", text: "12" }]);
    expect(segments(false)).toEqual([{ kind: "text", text: "false" }]);
  });
});

// review F3: every default-ignorable code point (Unicode's "draw as nothing") and every format
// character is a marker; decision 11's exceptions are tab, newline and variation selectors 1-16
describe("hidden characters, all of them", () => {
  const DRAWN_AS_NOTHING = /^[\p{Default_Ignorable_Code_Point}\p{Cf}\p{Cc}\p{Cs}\p{Zl}\p{Zp}]$/u;
  const oracle = (code: number): boolean =>
    code === 0x2800 || (code !== 0x09 && code !== 0x0a && !(code >= 0xfe00 && code <= 0xfe0f) && DRAWN_AS_NOTHING.test(String.fromCodePoint(code)));

  it("marks a code point exactly when it is default-ignorable, a format or control character, a surrogate or a line or paragraph separator (or the Braille blank)", () => {
    const wrong: string[] = [];
    for (let code = 0; code <= 0x10ffff; code++) {
      if (isMarked(code) !== oracle(code)) wrong.push(code.toString(16));
    }
    expect(wrong.slice(0, 20)).toEqual([]);
  });

  it("marks the ones the review found unmarked", () => {
    for (const code of [0x2065, 0xfff0, 0xfff8, 0x1bca0, 0x1bca3, 0x1d173, 0x1d17a, 0xe0080, 0xe00ff, 0xe01f0, 0xe0fff, 0x600, 0x605, 0x6dd, 0x70f, 0x890, 0x891, 0x8e2, 0x110bd, 0x110cd, 0x13430, 0x1343f]) {
      expect(isMarked(code), code.toString(16)).toBe(true);
      expect(segments(`pay${String.fromCodePoint(code)}pal`).filter((p) => p.kind === "mark"), code.toString(16)).toHaveLength(1);
    }
    for (const code of [0x09, 0x0a, 0x20, 0xa0, 0xfe00, 0xfe0f, 0x2000, 0x3000, 0x61, 0x5d0]) {
      expect(isMarked(code), code.toString(16)).toBe(false);
    }
  });

  it("cannot let 8 hidden bits per character ride along unseen", () => {
    const hidden = [..."rm -rf /"].map((c) => String.fromCodePoint(0xe0080 + c.charCodeAt(0))).join("");
    expect(segments(`approved${hidden}`).filter((p) => p.kind === "mark")).toHaveLength(8);
  });
});

// review F11: a huge value shown capped costs what is shown, not the whole value
describe("a huge value", () => {
  it("is cut and counted without walking it whole", () => {
    const huge = "\u00e4.b ".repeat(2_500_000); // 10 million characters
    const parts = segments(huge);
    expect(parts.at(-1)).toEqual({ kind: "cut", hidden: 10_000_000 - 2000, lines: false });
    const best = (run: () => unknown) => {
      let fastest = Infinity;
      for (let i = 0; i < 3; i++) {
        const t = performance.now();
        run();
        fastest = Math.min(fastest, performance.now() - t);
      }
      return fastest;
    };
    // against one plain pass over the value on the same machine, so a slow runner reads the
    // same: about 0.4 of it now, 3.7 before (231 ms, the review's measure)
    const walk = () => {
      let n = 0;
      for (const ch of huge) n += ch.length;
      return n;
    };
    expect(best(() => segments(huge))).toBeLessThan(best(walk));
  });

  it("counts what is hidden in code points, lone surrogates as one each", () => {
    // the surrogate ranges' edges, in the hidden part
    expect(segments("a\uD800\uDC00\uDBFF\uDFFF\uD7FF\uDC00\uD800\uE000", { maxChars: 1, maxLines: 9 }).at(-1)).toEqual({ kind: "cut", hidden: 6, lines: false });
    expect(segments("a\uDBFF\uDBFF\uDFFF\uDC00", { maxChars: 1, maxLines: 9 }).at(-1)).toEqual({ kind: "cut", hidden: 3, lines: false });
    // U+FFFF is one unit, the last before the supplementary planes
    expect(original(segments("\uFFFFx\u{10000}y", { maxChars: 9, maxLines: 9 }))).toBe("\uFFFFx\u{10000}y");
    expect(segments("ab\u{1F600}\u{1F600}\uD800c", { maxChars: 2, maxLines: 9 }).at(-1)).toEqual({ kind: "cut", hidden: 4, lines: false });
    expect(segments("a\u{1F600}b", { maxChars: 1, maxLines: 9 }).at(-1)).toEqual({ kind: "cut", hidden: 2, lines: false });
    expect(segments("a\uDC00\uD800b", { maxChars: 1, maxLines: 9 }).at(-1)).toEqual({ kind: "cut", hidden: 3, lines: false });
    expect(segments("\u{1F600}\n\u{1F600}x", { maxChars: 9, maxLines: 1 }).at(-1)).toEqual({ kind: "cut", hidden: 3, lines: true });
    fc.assert(
      fc.property(fc.string({ unit: "binary", maxLength: 30 }), fc.nat(30), fc.integer({ min: 1, max: 5 }), (raw, maxChars, maxLines) => {
        const s = raw.replace(/\r/g, ""); // no CRLF, which shows as one break
        const parts = segments(s, { maxChars, maxLines });
        const cut = parts.find((p) => p.kind === "cut");
        const shown = Array.from(original(parts)).length;
        const hidden = cut?.kind === "cut" ? cut.hidden : 0;
        expect(shown + hidden).toBe(Array.from(s).length);
        expect(shown).toBeLessThanOrEqual(maxChars);
        expect(cut === undefined).toBe(shown === Array.from(s).length);
      }),
    );
  });
});

// review F4: right-to-left letters sit in their own isolates, so the numbers and words around them
// keep the order they were written in
describe("bidiRuns", () => {
  it("isolates each run of right-to-left letters, and nothing else", () => {
    expect(bidiRuns("from \u05d0 10.0.0.1 \u05d0 192.168.1.1")).toEqual([
      { text: "from ", rtl: false },
      { text: "\u05d0", rtl: true },
      { text: " 10.0.0.1 ", rtl: false },
      { text: "\u05d0", rtl: true },
      { text: " 192.168.1.1", rtl: false },
    ]);
    expect(bidiRuns("plain text 10.0.0.1")).toEqual([{ text: "plain text 10.0.0.1", rtl: false }]);
    expect(bidiRuns("")).toEqual([]);
    // words with spaces between stay one run; marks stay with their letter; digits end a run
    expect(bidiRuns("a \u05e9\u05dc\u05d5\u05dd \u05e2\u05d5\u05dc\u05dd b")).toEqual([
      { text: "a ", rtl: false },
      { text: "\u05e9\u05dc\u05d5\u05dd \u05e2\u05d5\u05dc\u05dd", rtl: true },
      { text: " b", rtl: false },
    ]);
    expect(bidiRuns("\u05e9\u05b8\u05c1 1")).toEqual([{ text: "\u05e9\u05b8\u05c1", rtl: true }, { text: " 1", rtl: false }]);
    expect(bidiRuns("\u0639\u062f\u062f \u0661\u0662 \u0631")).toEqual([
      { text: "\u0639\u062f\u062f", rtl: true },
      { text: " \u0661\u0662 ", rtl: false },
      { text: "\u0631", rtl: true },
    ]);
    // a mark after a space, and a mark with no right-to-left letter before it, stay outside
    expect(bidiRuns("\u05d0 \u0301x")).toEqual([{ text: "\u05d0", rtl: true }, { text: " \u0301x", rtl: false }]);
    expect(bidiRuns("e\u05b8")).toEqual([{ text: "e\u05b8", rtl: false }]);
    // at either end, with spaces after
    expect(bidiRuns("x\u05d0")).toEqual([{ text: "x", rtl: false }, { text: "\u05d0", rtl: true }]);
    expect(bidiRuns("\u05d0 ")).toEqual([{ text: "\u05d0", rtl: true }, { text: " ", rtl: false }]);
    expect(bidiRuns("\u05d0 \u0301 \u05d1")).toEqual([{ text: "\u05d0 \u0301 \u05d1", rtl: true }]);
    expect(bidiRuns("\u05d0\u05b8\u05b8 \u05d1")).toEqual([{ text: "\u05d0\u05b8\u05b8 \u05d1", rtl: true }]);
    // every right-to-left block: Hebrew, Arabic, Syriac, Thaana, NKo, the presentation forms,
    // and the historic scripts of the supplementary planes
    for (const code of [0x590, 0x5d0, 0x627, 0x710, 0x780, 0x7ca, 0x8a0, 0xfb1d, 0xfb50, 0xfdff, 0xfe70, 0xfefc, 0x10800, 0x10fff, 0x1e800, 0x1e900, 0x1efff]) {
      const c = String.fromCodePoint(code);
      expect(bidiRuns(`x${c}y`), code.toString(16)).toEqual([{ text: "x", rtl: false }, { text: c, rtl: true }, { text: "y", rtl: false }]);
    }
    // outside the blocks, and inside them but a mark (0x8ff, with no letter before it) or a digit
    for (const code of [0x58f, 0x900, 0xfb1c, 0xfe6f, 0xfeff, 0x107ff, 0x11000, 0x1e7ff, 0x1f000, 0x8ff, 0x661, 0x6f1, 0x10e60]) {
      expect(bidiRuns(`x${String.fromCodePoint(code)}y`), code.toString(16)).toHaveLength(1);
    }
  });

  it("keeps every character, in order, and never puts a digit or a left-to-right letter in a run", () => {
    const piece = fc.oneof(
      fc.string({ maxLength: 4 }),
      fc.constantFrom("\u05d0", "\u05e9\u05b8", "\u0627", "\u0661", "\u06f1", " ", "  ", "\u0301", "10.0.0.1", "\u{10900}", "\u{1e900}", "\ufb1d"),
    );
    fc.assert(
      fc.property(fc.array(piece, { maxLength: 20 }).map((p) => p.join("")), (s) => {
        const runs = bidiRuns(s);
        expect(runs.map((r) => r.text).join("")).toBe(s);
        for (const [i, r] of runs.entries()) {
          expect(r.text).not.toBe("");
          if (i > 0) expect(r.rtl).not.toBe(runs[i - 1]?.rtl); // neighbours differ
          if (r.rtl) {
            expect(r.text).not.toMatch(/[\p{N}a-zA-Z]/u);
            expect(r.text).not.toMatch(/^\s|\s$/u);
          } else {
            expect(r.text).not.toMatch(/[\u05d0\u0627\u{10900}\u{1e900}\ufb1d]/u);
          }
        }
      }),
    );
  });
});

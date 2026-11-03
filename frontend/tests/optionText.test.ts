import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { optionText } from "../src/lib/optionText";

describe("optionText", () => {
  it("shows plain text as it is, cut at the limit with an ellipsis", () => {
    expect(optionText("A rule")).toBe("A rule");
    expect(optionText("x".repeat(100), 90)).toBe(`${"x".repeat(90)}…`);
    expect(optionText(null)).toBe("");
    expect(optionText("a\nb")).toBe("a…");
  });

  it("writes every invisible or reordering character as a visible marker, never as itself", () => {
    expect(optionText("a\u202eb")).toBe("a‹RLO›b");
    expect(optionText("a\u200bb")).toBe("a‹ZWSP›b");
    fc.assert(fc.property(fc.string({ unit: "binary", maxLength: 80 }), (text) => {
      const shown = optionText(text);
      for (const ch of shown) {
        const code = ch.codePointAt(0) ?? 0;
        const hidden = code < 9 || (code >= 0x0b && code <= 0x1f) || code === 0x7f || (code >= 0x200b && code <= 0x200f) || (code >= 0x202a && code <= 0x202e) || (code >= 0x2066 && code <= 0x2069);
        expect(hidden).toBe(false);
      }
    }));
  });
});

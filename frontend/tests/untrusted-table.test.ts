// Every named hidden character, spelled out (so a changed name or label is caught), and the
// edges a domain is trimmed of.
import { describe, expect, it } from "vitest";
import { markOf, segments, toAscii } from "../src/lib/untrusted";

const NAMED: [number, string, string][] = [
  [0x00, "NUL", "null"],
  [0x07, "BEL", "bell"],
  [0x08, "BS", "backspace"],
  [0x0b, "VT", "vertical tab"],
  [0x0c, "FF", "form feed"],
  [0x0d, "CR", "carriage return"],
  [0x1b, "ESC", "escape"],
  [0x7f, "DEL", "delete"],
  [0x85, "NEL", "next line"],
  [0xad, "SHY", "soft hyphen"],
  [0x34f, "CGJ", "combining grapheme joiner"],
  [0x61c, "ALM", "Arabic letter mark"],
  [0x115f, "HF", "Hangul choseong filler"],
  [0x1160, "HF", "Hangul jungseong filler"],
  [0x17b4, "KIV", "Khmer inherent vowel"],
  [0x17b5, "KIV", "Khmer inherent vowel"],
  [0x180e, "MVS", "Mongolian vowel separator"],
  [0x200b, "ZWSP", "zero-width space"],
  [0x200c, "ZWNJ", "zero-width non-joiner"],
  [0x200d, "ZWJ", "zero-width joiner"],
  [0x200e, "LRM", "left-to-right mark"],
  [0x200f, "RLM", "right-to-left mark"],
  [0x2028, "LSEP", "line separator"],
  [0x2029, "PSEP", "paragraph separator"],
  [0x202a, "LRE", "left-to-right embedding"],
  [0x202b, "RLE", "right-to-left embedding"],
  [0x202c, "PDF", "pop directional formatting"],
  [0x202d, "LRO", "left-to-right override"],
  [0x202e, "RLO", "right-to-left override"],
  [0x2060, "WJ", "word joiner"],
  [0x2066, "LRI", "left-to-right isolate"],
  [0x2067, "RLI", "right-to-left isolate"],
  [0x2068, "FSI", "first strong isolate"],
  [0x2069, "PDI", "pop directional isolate"],
  [0x2800, "BRAILLE", "Braille blank"],
  [0x3164, "HF", "Hangul filler"],
  [0xfeff, "BOM", "zero-width no-break space"],
  [0xffa0, "HF", "halfwidth Hangul filler"],
];

function hex(code: number): string {
  return "U+" + code.toString(16).toUpperCase().padStart(4, "0");
}

describe("named hidden characters", () => {
  it.each(NAMED)("U+%s is named", (code, label, name) => {
    expect(markOf(code)).toEqual({ label, name: `${hex(code)} ${name}` });
    expect(segments(`a${String.fromCodePoint(code)}b`)[1]).toEqual({
      kind: "mark",
      code,
      label,
      name: `${hex(code)} ${name}`,
    });
  });

  it("names a tag character by the ASCII it hides, at both ends of the range", () => {
    expect(markOf(0xe0020)).toEqual({ label: "TAG  ", name: 'U+E0020 tag character, hidden " "' });
    expect(markOf(0xe007e)).toEqual({ label: "TAG ~", name: 'U+E007E tag character, hidden "~"' });
    expect(markOf(0xe001f).label).toBe("U+E001F");
    expect(markOf(0xd7ff).label).toBe("U+D7FF");
    expect(markOf(0xe000).label).toBe("U+E000");
    expect(markOf(0x1f)).toEqual({ label: "^_", name: "U+001F control" });
    expect(markOf(0x20).label).toBe("U+0020");
  });
});

describe("domain edges", () => {
  it.each(["-", ".", "。", "．", "｡"])("trims %s from both ends of a name", (edge) => {
    expect(segments(`${edge}${edge}bücher.de${edge}`)).toEqual([
      { kind: "text", text: `${edge}${edge}` },
      { kind: "idn", text: "bücher.de", ascii: "xn--bcher-kva.de" },
      { kind: "text", text: edge },
    ]);
  });

  it("reads each kind of dot as a dot", () => {
    for (const dot of [".", "。", "．", "｡"]) {
      expect(segments(`bücher${dot}de`)).toEqual([{ kind: "idn", text: `bücher${dot}de`, ascii: "xn--bcher-kva.de" }]);
    }
  });

  it("leaves a name alone that is ASCII once trimmed, or has an empty label, or no dot", () => {
    expect(segments("example.com。")).toEqual([{ kind: "text", text: "example.com。" }]);
    expect(segments("bücher..de")).toEqual([{ kind: "text", text: "bücher..de" }]);
    expect(segments("bücher")).toEqual([{ kind: "text", text: "bücher" }]);
    expect(segments("é")).toEqual([{ kind: "text", text: "é" }]);
  });

  it("annotates every name in a value, with the text between kept", () => {
    expect(segments("a bücher.de, c аpple.com d")).toEqual([
      { kind: "text", text: "a " },
      { kind: "idn", text: "bücher.de", ascii: "xn--bcher-kva.de" },
      { kind: "text", text: ", c " },
      { kind: "idn", text: "аpple.com", ascii: "xn--pple-43d.com" },
      { kind: "text", text: " d" },
    ]);
  });
});

describe("boundaries", () => {
  it("marks the last broken surrogate and the first C1 control, and DEL by name", () => {
    expect(markOf(0xdfff).label).toBe("BAD");
    expect(segments("a\u0080")[1]).toMatchObject({ kind: "mark", label: "U+0080" });
    expect(segments("\u007f")[0]).toMatchObject({ kind: "mark", label: "DEL" });
  });

  it("counts a line cut exactly at the character cap as a character cut", () => {
    expect(segments("ab\ncd", { maxChars: 2, maxLines: 1 })).toEqual([
      { kind: "text", text: "ab" },
      { kind: "cut", hidden: 3, lines: false },
    ]);
  });

  it("refuses over-long names and names the URL parser refuses", () => {
    expect(toAscii(`${"x".repeat(1008)}.com`)).toBe(`${"x".repeat(1008)}.com`);
    expect(toAscii(`${"x".repeat(1009)}.com`)).toBeNull();
    expect(toAscii(`${"x".repeat(100)}.com`)).toBe(`${"x".repeat(100)}.com`);
    expect(toAscii("a<b.com")).toBeNull();
    expect(toAscii("́x.com")).toBeNull();
    expect(segments("́x.com")).toEqual([{ kind: "idn", text: "́x.com", ascii: null }]);
  });
});

describe("a run of edges only", () => {
  it("is left as text", () => {
    expect(segments("。．--｡")).toEqual([{ kind: "text", text: "。．--｡" }]);
    expect(segments("x 。 y")).toEqual([{ kind: "text", text: "x 。 y" }]);
  });
});

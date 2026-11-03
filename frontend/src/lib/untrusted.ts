/**
 * Untrusted text, made safe to show (Q-B1, plan §7.5): text only, never markup and never a
 * link; capped in length and lines; every invisible or reordering character shown as a visible
 * marker (controls, bidi controls, zero-width and other format characters, tag characters,
 * broken UTF-16); a domain name written with non-ASCII letters shown with its ASCII form
 * (punycode) beside it, so a look-alike name cannot pass for the real one.
 *
 * `segments` is pure: the React renderer (UntrustedText) only maps its output to text nodes and
 * spans. Nothing here returns or builds HTML.
 */

export type Segment =
  | { kind: "text"; text: string }
  | { kind: "mark"; code: number; label: string; name: string }
  | { kind: "idn"; text: string; ascii: string | null }
  | { kind: "cut"; hidden: number; lines: boolean };

export interface Limits {
  /** the most code points shown */
  maxChars: number;
  /** the most lines shown */
  maxLines: number;
}

export const DEFAULT_LIMITS: Limits = { maxChars: 2000, maxLines: 40 };
/** what "show all" shows at most: no limit would let one value freeze the page */
export const HARD_MAX = 100_000;

const NAMES: Record<number, [string, string]> = {
  0x00: ["NUL", "null"],
  0x07: ["BEL", "bell"],
  0x08: ["BS", "backspace"],
  0x0b: ["VT", "vertical tab"],
  0x0c: ["FF", "form feed"],
  0x0d: ["CR", "carriage return"],
  0x1b: ["ESC", "escape"],
  0x7f: ["DEL", "delete"],
  0x85: ["NEL", "next line"],
  0xad: ["SHY", "soft hyphen"],
  0x34f: ["CGJ", "combining grapheme joiner"],
  0x61c: ["ALM", "Arabic letter mark"],
  0x115f: ["HF", "Hangul choseong filler"],
  0x1160: ["HF", "Hangul jungseong filler"],
  0x17b4: ["KIV", "Khmer inherent vowel"],
  0x17b5: ["KIV", "Khmer inherent vowel"],
  0x180e: ["MVS", "Mongolian vowel separator"],
  0x200b: ["ZWSP", "zero-width space"],
  0x200c: ["ZWNJ", "zero-width non-joiner"],
  0x200d: ["ZWJ", "zero-width joiner"],
  0x200e: ["LRM", "left-to-right mark"],
  0x200f: ["RLM", "right-to-left mark"],
  0x2028: ["LSEP", "line separator"],
  0x2029: ["PSEP", "paragraph separator"],
  0x202a: ["LRE", "left-to-right embedding"],
  0x202b: ["RLE", "right-to-left embedding"],
  0x202c: ["PDF", "pop directional formatting"],
  0x202d: ["LRO", "left-to-right override"],
  0x202e: ["RLO", "right-to-left override"],
  0x2060: ["WJ", "word joiner"],
  0x2066: ["LRI", "left-to-right isolate"],
  0x2067: ["RLI", "right-to-left isolate"],
  0x2068: ["FSI", "first strong isolate"],
  0x2069: ["PDI", "pop directional isolate"],
  0x2800: ["BRAILLE", "Braille blank"],
  0x3164: ["HF", "Hangul filler"],
  0xfeff: ["BOM", "zero-width no-break space"],
  0xffa0: ["HF", "halfwidth Hangul filler"],
};

function hex(code: number): string {
  return "U+" + code.toString(16).toUpperCase().padStart(4, "0");
}

// What a browser may draw as nothing (Unicode's default-ignorable code points, assigned or not,
// review F3) and every format character (bidi controls, joiners, tags, prepended marks, ...).
const DRAWN_AS_NOTHING = /^[\p{Default_Ignorable_Code_Point}\p{Cf}]$/u;

/** Whether a code point is shown as a marker instead of itself. */
export function isMarked(code: number): boolean {
  if (code in NAMES) return true;
  if (code === 0x09 || code === 0x0a) return false; // tab and newline are kept as they are
  if (code <= 0x1f || (code >= 0x80 && code <= 0x9f)) return true; // C0 and C1 controls (DEL is named)
  if (code >= 0xd800 && code <= 0xdfff) return true; // a lone surrogate: broken UTF-16
  if (code >= 0xfe00 && code <= 0xfe0f) return false; // variation selectors 1-16: emoji use them
  return DRAWN_AS_NOTHING.test(String.fromCodePoint(code)); // tags, selectors 17-256, the rest
}

/** The marker's short text and its full name, for a marked code point. */
export function markOf(code: number): { label: string; name: string } {
  const known = NAMES[code];
  if (known) return { label: known[0], name: `${hex(code)} ${known[1]}` };
  if (code >= 0xe0020 && code <= 0xe007e) {
    const shown = String.fromCodePoint(code - 0xe0000);
    return { label: `TAG ${shown}`, name: `${hex(code)} tag character, hidden "${shown}"` };
  }
  if (code >= 0xd800 && code <= 0xdfff) return { label: "BAD", name: `${hex(code)} broken UTF-16` };
  if (code <= 0x1f) return { label: `^${String.fromCharCode(code + 0x40)}`, name: `${hex(code)} control` };
  return { label: hex(code), name: `${hex(code)} invisible or format character` };
}

/** How many code points `text` has from UTF-16 index `from` on (a lone surrogate is one). */
function countFrom(text: string, from: number): number {
  let n = 0;
  for (let i = from; i < text.length; i++) {
    const unit = text.charCodeAt(i);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const low = text.charCodeAt(i + 1);
      if (low >= 0xdc00 && low <= 0xdfff) i++;
    }
    n++;
  }
  return n;
}

// Characters a domain name may be written with: letters, digits, marks, hyphens and dots (the
// ideographic and fullwidth dots too, which IDNA reads as dots). One flat class with no nested
// quantifier, so a long value is scanned in linear time.
const DOMAIN_RUN = /[\p{L}\p{N}\p{M}\-.\u3002\uff0e\uff61]+/gu;
const DOT = /[.\u3002\uff0e\uff61]/u;
const EDGES = new Set(["-", ".", "\u3002", "\uff0e", "\uff61"]);
const ASCII = /^[\x20-\x7e]*$/;

/** A domain name's ASCII form (IDNA, as browsers read it), or null if it is not a valid name. */
export function toAscii(name: string): string | null {
  if (name.length > 253 * 4 || /[\s/\\?#@:%[\]]/.test(name)) return null; // a name, never a URL
  try {
    return new URL(`http://${name}/`).hostname; // the URL standard's host is ASCII
  } catch {
    return null;
  }
}

function annotate(text: string, out: Segment[]): void {
  let last = 0;
  for (const match of text.matchAll(DOMAIN_RUN)) {
    const run = match[0];
    // trim dots and hyphens from both ends (charAt is "" past either end, which stops a loop;
    // a run of edges only leaves to below from, and slice then gives "")
    let from = 0;
    while (EDGES.has(run.charAt(from))) from++;
    let to = run.length;
    while (EDGES.has(run.charAt(to - 1))) to--;
    const core = run.slice(from, to);
    if (ASCII.test(core)) continue;
    const labels = core.split(DOT);
    if (labels.length < 2 || labels.some((label) => label === "")) continue;
    const start = match.index + from;
    if (start > last) out.push({ kind: "text", text: text.slice(last, start) });
    out.push({ kind: "idn", text: core, ascii: toAscii(core) });
    last = start + core.length;
  }
  if (last < text.length) out.push({ kind: "text", text: text.slice(last) });
}

/** Any value as text: a string as it is, nothing for null or undefined, else String(value), or a
 * note when even that fails (an object whose toString throws). */
export function asText(value: unknown): string {
  if (value == null) return "";
  try {
    return String(value);
  } catch {
    return "[a value that cannot be shown as text]";
  }
}

/** Split untrusted text into what to show, within the limits. */
export function segments(value: unknown, limits: Limits = DEFAULT_LIMITS): Segment[] {
  const text = asText(value);
  const maxChars = Math.max(0, Math.min(Math.floor(limits.maxChars), HARD_MAX));
  const maxLines = Math.max(1, Math.floor(limits.maxLines));
  // walk only what is shown (review F11): a 10-million-character value costs its first 2,000
  const points: number[] = [];
  let at = 0; // UTF-16 index of the next code point
  let byLines = false;
  let lines = 1;
  while (at < text.length && points.length < maxChars) {
    const code = text.codePointAt(at) as number; // a lone surrogate comes back as itself
    if (code === 0x0a) {
      if (lines === maxLines) {
        byLines = true;
        break;
      }
      lines++;
    }
    points.push(code);
    at += code > 0xffff ? 2 : 1;
  }
  const shown = points.length;
  const out: Segment[] = [];
  let run = "";
  const flush = () => {
    annotate(run, out);
    run = "";
  };
  for (let i = 0; i < shown; i++) {
    const code = points[i] as number;
    if (code === 0x0d && i + 1 < shown && points[i + 1] === 0x0a) continue; // CRLF: one break
    if (isMarked(code)) {
      flush();
      out.push({ kind: "mark", code, ...markOf(code) });
    } else {
      run += String.fromCodePoint(code);
    }
  }
  flush();
  if (at < text.length) {
    out.push({ kind: "cut", hidden: countFrom(text, at), lines: byLines });
  }
  return out;
}

/** The text a list of segments stands for (markers back to their characters). */
export function original(parts: readonly Segment[]): string {
  let out = "";
  for (const part of parts) {
    if (part.kind === "cut") continue;
    out += part.kind === "mark" ? String.fromCodePoint(part.code) : part.text;
  }
  return out;
}

/** A piece of shown text, and whether it is a run of right-to-left letters. */
export interface Run {
  text: string;
  rtl: boolean;
}

// The blocks whose letters are right to left (Unicode's default bidi classes R and AL): Hebrew,
// Arabic, Syriac, Thaana, NKo, Samaritan, Mandaic and their extensions; the Hebrew and Arabic
// presentation forms; the historic right-to-left scripts of the supplementary planes.
function inRtlBlock(code: number): boolean {
  return (
    (code >= 0x590 && code <= 0x8e2) || // past U+08E2 to U+08FF only marks, which follow their letter
    (code >= 0xfb1d && code <= 0xfdff) ||
    (code >= 0xfe70 && code <= 0xfefe) ||
    (code >= 0x10800 && code <= 0x10fff) ||
    (code >= 0x1e800 && code <= 0x1efff)
  );
}
const MARK = /^\p{M}$/u;
const NUMBER_OR_MARK = /^[\p{N}\p{M}]$/u;
const SPACE = /^\p{Zs}$/u;

/**
 * Text split into runs of right-to-left letters and the rest (review F4). UntrustedText puts
 * each run in its own right-to-left isolate inside the left-to-right one, so the numbers and
 * words around it keep the order they were written in: "from \u05d0 10.0.0.1 \u05d0 192.168.1.1"
 * never shows 192.168.1.1 first. A run starts and ends with a right-to-left letter (its combining
 * marks kept with it) and may hold spaces between words; a digit or anything else ends it.
 */
export function bidiRuns(text: string): Run[] {
  const out: Run[] = [];
  let plain = ""; // left-to-right text not yet pushed
  let run = ""; // the open right-to-left run ("" when none)
  let gap = ""; // spaces (and their marks) after the run, kept if another letter follows
  for (const char of text) {
    const code = char.codePointAt(0) as number;
    if (inRtlBlock(code) && !NUMBER_OR_MARK.test(char)) {
      if (plain !== "") {
        // (plain is "" while a run is open)
        out.push({ text: plain, rtl: false });
        plain = "";
      }
      run += gap + char;
      gap = "";
    } else if (run !== "" && gap === "" && MARK.test(char)) {
      run += char; // a mark stays with its letter
    } else if (run !== "" && (SPACE.test(char) || MARK.test(char))) {
      gap += char; // a space, or a mark after one
    } else {
      if (run !== "") {
        out.push({ text: run, rtl: true });
        run = "";
        plain = gap;
        gap = "";
      }
      plain += char;
    }
  }
  if (run !== "") out.push({ text: run, rtl: true });
  plain += gap;
  if (plain !== "") out.push({ text: plain, rtl: false });
  return out;
}

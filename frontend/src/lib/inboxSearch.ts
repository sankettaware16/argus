/**
 * The Inbox's "Find" box, checked before anything is sent (plan §5 Q-B2: validated search).
 * The server refuses a NUL and anything over 300 characters (422); a person gets a plain
 * sentence first. An address is checked as an address and written the way ARGUS stores it
 * (src/argus/normalize/canon.py): dotted for IPv4 (also when typed as an IPv4-mapped IPv6
 * address), compressed lower case for IPv6, a domain in lower case without its trailing dot.
 * Pure (tests/inboxSearch.test.ts).
 */
import { toAscii } from "./untrusted";

export type FindKind = "ip" | "host" | "domain" | "user";
export const FIND_KINDS: readonly FindKind[] = ["ip", "host", "domain", "user"];
export const MAX_FIND = 300;

export type Found = { ok: true; kind: FindKind; value: string } | { ok: false; why: string };


/** Any control character, or a line or paragraph separator: nothing a person can see to search for. */
export function hasControl(text: string): boolean {
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c < 0x20 || (c >= 0x7f && c <= 0x9f) || c === 0x2028 || c === 0x2029) return true;
  }
  return false;
}
const IPV4 = /^(?:0|[1-9]\d{0,2})(?:\.(?:0|[1-9]\d{0,2})){3}$/;
const LABEL = /^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$/;

function ipv4(text: string): string | null {
  if (!IPV4.test(text)) return null;
  return text.split(".").every((part) => Number(part) <= 255) ? text : null;
}

function ipv6(text: string): string | null {
  if (!/^[0-9a-fA-F:.]+$/.test(text) || !text.includes(":")) return null;
  let host: string;
  try {
    host = new URL(`http://[${text}]/`).hostname;
  } catch {
    return null;
  }
  const inner = host.replace(/^\[|\]$/g, "");
  const [, high, low] = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(inner) ?? []; // ARGUS stores an IPv4-mapped address as IPv4
  if (high === undefined || low === undefined) return inner;
  const hi = parseInt(high, 16);
  const lo = parseInt(low, 16);
  return `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;
}

function domain(text: string): { ok: true; value: string } | { ok: false; why: string } {
  const trimmed = text.replace(/\.+$/, "").toLowerCase();
  if (trimmed === "") return { ok: false, why: "Type a domain name, for example example.com." };
  const ascii = toAscii(trimmed); // the URL standard's host: lower case, letters beyond a to z in xn-- form
  if (ascii === null) return { ok: false, why: "That is not a valid domain name. Letters other than a to z are written in their ASCII form (xn--...)." };
  if (ascii.length > 253) return { ok: false, why: "A domain name has at most 253 characters." };
  if (!ascii.split(".").every((label) => LABEL.test(label))) {
    return { ok: false, why: "A domain name is words of letters, digits and hyphens separated by dots, for example example.com." };
  }
  return { ok: true, value: ascii };
}

/** Whether `raw` is something to find as a `kind`, and the value to send. */
export function validateFind(kind: string, raw: string): Found {
  if (!(FIND_KINDS as readonly string[]).includes(kind)) return { ok: false, why: "Choose what to find: an IP address, a host, a domain or a user." };
  const text = raw.trim();
  if (text === "") return { ok: false, why: "Type what to find." };
  if (text.length > MAX_FIND) return { ok: false, why: `Use at most ${MAX_FIND} characters.` };
  if (hasControl(text)) return { ok: false, why: "Remove the control characters: only visible characters can be searched." };
  const k = kind as FindKind;
  if (k === "ip") {
    const value = ipv4(text) ?? ipv6(text);
    return value === null ? { ok: false, why: "That is not an IP address. Write it like 10.8.235.157 (four numbers up to 255) or like 2001:db8::1." } : { ok: true, kind: k, value };
  }
  if (k === "domain") {
    const checked = domain(text);
    return checked.ok ? { ok: true, kind: k, value: checked.value } : checked;
  }
  return { ok: true, kind: k, value: text };
}

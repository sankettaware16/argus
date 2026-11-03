/**
 * The exact payload a change sends (Q-B1, plan §7.5): what the confirm dialog shows is what is
 * sent, byte for byte. `payloadText` serializes the body once; the dialog shows that string and
 * hands it, with the method and path it showed, to the sender (lib/api.ts `sendExact`, which puts
 * that string on the wire as it is).
 */
import { HARD_MAX } from "./untrusted";

export type Method = "POST" | "PUT" | "PATCH" | "DELETE";

export interface PendingRequest {
  method: Method;
  /** the API path, e.g. /api/v1/proposals/confirm */
  path: string;
  /** the JSON body, or undefined for none */
  body?: unknown;
}

export type Payload =
  | { ok: true; text: string; empty: boolean }
  | { ok: false; why: string };

/** What the confirm dialog hands its sender: the method, path and body text it showed. */
export interface ExactRequest {
  method: Method;
  path: string;
  /** the body exactly as shown; "" for no body */
  text: string;
}

/** The server's answer to a sent request. */
export interface Sent {
  status: number;
  data: unknown;
}

/** The body as it will be sent, or why it cannot be shown whole (and so cannot be confirmed). */
export function payloadText(body: unknown): Payload {
  if (body === undefined) return { ok: true, text: "", empty: true };
  let text: string | undefined;
  try {
    text = JSON.stringify(body, null, 2);
  } catch {
    return { ok: false, why: "This request's body cannot be written as JSON (it loops, or holds a big integer)." };
  }
  if (text === undefined) return { ok: false, why: "This request's body has nothing JSON can write." };
  if (codePoints(text, HARD_MAX) > HARD_MAX) {
    return { ok: false, why: "This request is too large to show whole, so it cannot be confirmed here." };
  }
  return { ok: true, text, empty: false };
}

/** How many code points `text` has, counting no further than just past `stop`. */
export function codePoints(text: string, stop: number = Infinity): number {
  let n = 0;
  for (let i = 0; i < text.length && n <= stop; i++) {
    const unit = text.charCodeAt(i);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const low = text.charCodeAt(i + 1);
      if (low >= 0xdc00 && low <= 0xdfff) i++;
    }
    n++;
  }
  return n;
}

/**
 * The API client (Q-B1, plan §7.5): Hey API's generated client for /api/v1, configured once.
 * Same origin, the session cookie sent by the browser (HttpOnly: never read here); the CSRF
 * token kept in memory only and sent as X-CSRF-Token on every change; background requests
 * (polls) marked so they never keep a session alive. Answers: 401 sends the person to /signin
 * and back, told that the session ended; 403 `csrf` reads the session again once (the request
 * itself is not resent: no 4xx is retried); every answer's X-Argus-Build feeds the stale-build
 * check. `sendExact` is the confirm dialog's sender: the method, path and body text it showed,
 * sent as they are.
 */
import { client } from "../client/client.gen";
import { noteServerBuild } from "./build";
import type { ExactRequest, Sent } from "./payload";

export { client };

export const BACKGROUND = { "X-Argus-Background": "1" } as const;
const CSRF_HEADER = "X-CSRF-Token";

let csrf: string | null = null;
let refreshing: Promise<void> | null = null;
let refresh: () => Promise<void> = async () => {};
let leave: (url: string) => void = (url) => window.location.assign(url);

export function setCsrf(token: string | null): void {
  csrf = token;
}

export function csrfToken(): string | null {
  return csrf;
}

/** Where the session is read again after a 403 `csrf` (the session module sets it). */
export function onCsrfRefused(fn: () => Promise<void>): void {
  refresh = fn;
}

/** Tests only: how the page leaves for /signin. */
export function setLeave(fn: (url: string) => void): void {
  leave = fn;
}

/** /signin after the session ended under the app: with a way back to this page of the app, and
 * the reason (the classic pages' "Your session ended. Sign in again to continue."). */
export function signinUrl(location: Pick<Location, "pathname" | "search"> = window.location): string {
  const back = `${location.pathname}${location.search}`;
  const next = back.startsWith("/app") ? back : "/app";
  return `/signin?${new URLSearchParams({ next, why: "ended" }).toString()}`;
}

/** What an ErrorOut answer says, or a plain sentence for its status. */
export function errorText(status: number, body: unknown): string {
  if (body && typeof body === "object" && "detail" in body && typeof body.detail === "string" && body.detail) {
    return body.detail.slice(0, 300);
  }
  if (status === 429) return "Too many requests just now; wait a minute and try again.";
  if (status === 503) return "ARGUS cannot answer just now; try again in a minute.";
  if (status >= 500) return "Something went wrong in ARGUS; it has been logged. Try again, or tell an ARGUS admin.";
  return `The request was refused (${status}).`;
}

async function codeOf(response: Response): Promise<string | null> {
  try {
    const body: unknown = await response.clone().json();
    return body && typeof body === "object" && "code" in body && typeof body.code === "string" ? body.code : null;
  } catch {
    return null;
  }
}

export function configure(): void {
  client.setConfig({
    baseUrl: "",
    credentials: "same-origin",
    cache: "no-store",
    headers: { Accept: "application/json" },
    // the spec's two schemes: the cookie goes by itself; the CSRF token from memory
    auth: (auth) => (auth.name === CSRF_HEADER && csrf ? csrf : undefined),
  });
  client.interceptors.response.use(async (response) => {
    noteServerBuild(response.headers.get("X-Argus-Build"));
    if (response.status === 401) {
      leave(signinUrl());
    } else if (response.status === 403 && (await codeOf(response)) === "csrf") {
      refreshing ??= refresh().finally(() => {
        refreshing = null;
      });
      await refreshing;
    }
    return response;
  });
}

// an /api/v1 path the browser requests exactly as written: segments of URL path characters or
// %XX escapes, no query or fragment, no empty segment and no dot segment (which the URL parser
// would resolve, %2e included), nothing it would escape or change
const API_PATH = /^\/api\/v1(?:\/(?:[A-Za-z0-9\-._~!$&'()*+,;=:@]|%[0-9A-Fa-f]{2})+)+$/;
const DOT_SEGMENT = /^(?:\.|%2e){1,2}$/i;
const NOT_EXACT = "This request's address is not one ARGUS can send exactly as shown, so nothing was sent.";
const NO_ANSWER = "No answer came from ARGUS, so it is not known whether this was done. Look before you try again.";

/** Whether `path` goes on the wire exactly as written (see sendExact). */
export function isExactPath(path: string): boolean {
  return API_PATH.test(path) && !path.split("/").some((segment) => DOT_SEGMENT.test(segment));
}

/**
 * The confirm dialog's sender (review F1): `method` to `path` with `text` as the body, as they
 * are: no path parameters, no query, and the body string never serialized again. The CSRF token
 * from memory; JSON as the type when there is a body. Throws an Error that says why when the
 * address is not exact, no answer came, or the answer is a refusal.
 */
export async function sendExact(request: ExactRequest): Promise<Sent> {
  if (!isExactPath(request.path)) throw new Error(NOT_EXACT);
  const empty = request.text === "";
  const result = await client.request({
    method: request.method,
    url: request.path,
    body: empty ? undefined : request.text,
    bodySerializer: null,
    headers: empty ? {} : { "Content-Type": "application/json" },
    security: [{ name: CSRF_HEADER, type: "apiKey" }],
  });
  const response = result.response as Response | undefined;
  if (response === undefined) throw new Error(NO_ANSWER);
  if (!response.ok) throw new Error(errorText(response.status, result.error));
  return { status: response.status, data: result.data };
}

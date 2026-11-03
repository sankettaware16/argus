/**
 * What a person reads when a request fails (plan §7.5, Q-B2's error matrix): plain words for each
 * kind of refusal. 401 sends the person to /signin before anything is shown (lib/api.ts); 403
 * `csrf` has already read the session again once, so the page tells the person to try again; 4xx
 * are never retried; 429 and 503 are said plainly.
 */

export function failureText(status: number, code: string | null, detail: string | null): string {
  const why = detail && detail.trim() !== "" ? detail.trim().slice(0, 300) : null;
  if (status === 0) return "ARGUS could not be reached. Check your connection and try again.";
  if (status === 401) return "Your session ended. Sign in again to continue.";
  if (status === 403) {
    if (code === "csrf") return "This page was out of date with the server, so it has been refreshed. Nothing was changed: try again.";
    if (code === "origin" || code === "network") return "ARGUS refused this request because it did not come from this site's own page.";
    return why ?? "Your account may not do this. Ask an ARGUS admin.";
  }
  if (status === 404) return why ?? "That no longer exists, or the link is wrong.";
  if (status === 409) return why ?? "It changed while you looked: nothing was saved. Read it again.";
  if (status === 422 || status === 400) return why ? `ARGUS did not accept that: ${why}` : "ARGUS did not accept that.";
  if (status === 429) return "Too many requests just now; wait a minute and try again.";
  if (status === 503) return why ?? "ARGUS cannot answer just now; try again in a minute.";
  if (status >= 500) return "Something went wrong in ARGUS; it has been logged. Try again, or tell an ARGUS admin.";
  return `The request was refused (${status}).`;
}

/** Whether a failed read is worth offering "Try again" for: not a refusal of this person. */
export function retryable(status: number): boolean {
  return status === 0 || status === 429 || status >= 500;
}

import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { client, configure, csrfToken, setCsrf } from "../src/lib/api";
import { ApiError, can, makeQueryClient, sessionQuery, signOut, type Session } from "../src/lib/session";
import { NEUTRAL_SITE, site } from "../src/lib/site";
import { ist } from "../src/lib/time";

const BASE = "http://localhost:3001";
const server = setupServer();
const SESSION = {
  user: { id: 1, username: "asha", display_name: "Asha" },
  mode: "local",
  break_glass: false,
  unverified: null,
  capabilities: [{ name: "view", label: "see" }, { name: "review", label: "review" }],
  csrf_token: "t-1",
  expires_at: "2026-10-23T20:00:00Z",
  idle_expires_at: "2026-10-23T12:30:00Z",
  idle_timeout_s: 1800,
  stepped_up_at: null,
  step_up_valid_until: null,
  since: null,
};

beforeAll(() => {
  configure();
  client.setConfig({ baseUrl: BASE });
  server.listen({ onUnhandledRequest: "error" });
});
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

describe("the session", () => {
  it("is read once into memory, the CSRF token with it", async () => {
    server.use(http.get(`${BASE}/api/v1/session`, () => HttpResponse.json(SESSION)));
    const queries = makeQueryClient();
    const session = await queries.fetchQuery(sessionQuery);
    expect(session.user.username).toBe("asha");
    expect(csrfToken()).toBe("t-1");
    expect(sessionQuery.retry).toBe(false);
  });

  it("keeps the page drawable when the answer carries no site (an older API)", async () => {
    server.use(http.get(`${BASE}/api/v1/session`, () => HttpResponse.json(SESSION)));
    await makeQueryClient().fetchQuery({ ...sessionQuery, staleTime: 0 });
    expect(site()).toEqual(NEUTRAL_SITE);
    expect(ist(new Date("2026-10-29T13:50:00Z"))).toBe("29 Oct 2026, 1:50 PM UTC");
  });

  it("says plainly when it cannot be read", async () => {
    server.use(http.get(`${BASE}/api/v1/session`, () => HttpResponse.json({ detail: "no", code: "x" }, { status: 503 })));
    const queries = makeQueryClient();
    const failed = queries.fetchQuery(sessionQuery);
    await expect(failed).rejects.toBeInstanceOf(ApiError);
    await expect(failed).rejects.toMatchObject({ status: 503, message: "Your session could not be read." });
  });

  it("knows what the person may do", () => {
    const session = SESSION as Session;
    expect(can(session, "review")).toBe(true);
    expect(can(session, "approve")).toBe(false);
    expect(can(undefined, "view")).toBe(false);
  });

  it("signs out with the CSRF token, forgets it, and goes to the sign-in page", async () => {
    let sent: string | null = null;
    server.use(
      http.delete(`${BASE}/api/v1/session`, ({ request }) => {
        sent = request.headers.get("X-CSRF-Token");
        return new HttpResponse(null, { status: 204 });
      }),
    );
    setCsrf("t-2");
    const leave = vi.fn();
    await signOut(leave);
    expect(sent).toBe("t-2");
    expect(csrfToken()).toBeNull();
    expect(leave).toHaveBeenCalledWith("/signin?why=out");
  });

  it("treats an already ended session as signed out, and says when signing out failed", async () => {
    const leave = vi.fn();
    server.use(http.delete(`${BASE}/api/v1/session`, () => HttpResponse.json({ detail: "x", code: "unauthenticated" }, { status: 401 })));
    await signOut(leave);
    expect(leave).toHaveBeenCalledWith("/signin?why=out");
    server.use(http.delete(`${BASE}/api/v1/session`, () => HttpResponse.json({ detail: "x", code: "internal" }, { status: 500 })));
    setCsrf("t-3");
    const again = vi.fn();
    await expect(signOut(again)).rejects.toMatchObject({ status: 500, message: "Signing out did not work; try again." });
    expect(again).not.toHaveBeenCalled();
    expect(csrfToken()).toBe("t-3");
  });
});

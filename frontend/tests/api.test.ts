import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { confirmProposals, getCost, getCounts } from "../src/client/sdk.gen";
import { BACKGROUND, client, configure, csrfToken, errorText, setCsrf, setLeave, signinUrl } from "../src/lib/api";
import { resetBuildState, serverBuild } from "../src/lib/build";
import { makeQueryClient } from "../src/lib/session";

const BASE = "http://localhost:3000";
const SESSION = {
  user: { id: 1, username: "asha", display_name: "Asha" },
  mode: "local",
  capabilities: [{ name: "view", label: "see" }],
  csrf_token: "fresh-token",
  expires_at: "2026-10-23T20:00:00Z",
  idle_expires_at: "2026-10-23T12:30:00Z",
  idle_timeout_s: 1800,
  stepped_up_at: null,
  step_up_valid_until: null,
  since: null,
};
const seen: Request[] = [];
const server = setupServer();

beforeAll(() => {
  configure();
  client.setConfig({ baseUrl: BASE });
  server.listen({ onUnhandledRequest: "error" });
  server.events.on("request:start", ({ request }) => {
    seen.push(request.clone());
  });
});
beforeEach(() => {
  seen.length = 0;
  resetBuildState();
  setCsrf(null);
});
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

describe("the API client", () => {
  it("sends the CSRF token from memory on a change, never on a read, and no cookie by hand", async () => {
    server.use(
      http.post(`${BASE}/api/v1/proposals/confirm`, () => HttpResponse.json({ accepted: 0, skipped: 0 })),
      http.get(`${BASE}/api/v1/counts`, () => HttpResponse.json({})),
    );
    setCsrf("token-1");
    await confirmProposals({ body: { investigations: [] } as never });
    await getCounts();
    expect(seen[0]?.headers.get("X-CSRF-Token")).toBe("token-1");
    expect(seen[1]?.headers.get("X-CSRF-Token")).toBeNull();
    for (const r of seen) {
      expect(r.headers.get("cookie")).toBeNull();
      expect(r.headers.get("X-Argus-Background")).toBeNull();
      expect(r.credentials).toBe("same-origin");
    }
    setCsrf(null);
    await confirmProposals({ body: { investigations: [] } as never });
    expect(seen[2]?.headers.get("X-CSRF-Token")).toBeNull();
    expect(csrfToken()).toBeNull();
  });

  it("marks polls as background requests", async () => {
    server.use(http.get(`${BASE}/api/v1/cost`, () => HttpResponse.json({})));
    await getCost({ headers: BACKGROUND });
    expect(seen[0]?.headers.get("X-Argus-Background")).toBe("1");
  });

  it("sends a signed-out person to /signin and back to this page of the app", async () => {
    const leave = vi.fn();
    setLeave(leave);
    window.history.replaceState(null, "", "/app/design?tab=2");
    server.use(http.get(`${BASE}/api/v1/counts`, () => HttpResponse.json({ detail: "x", code: "unauthenticated" }, { status: 401 })));
    await getCounts();
    // review F10: the person is told why (the classic pages' "Your session ended")
    expect(leave).toHaveBeenCalledWith("/signin?next=%2Fapp%2Fdesign%3Ftab%3D2&why=ended");
    expect(signinUrl({ pathname: "/elsewhere", search: "" })).toBe("/signin?next=%2Fapp&why=ended");
    expect(signinUrl({ pathname: "//evil.example/app", search: "" })).toBe("/signin?next=%2Fapp&why=ended");
    // a background poll's 401 too (the idle clock ran out while the shell polled)
    server.use(http.get(`${BASE}/api/v1/cost`, () => HttpResponse.json({ detail: "x", code: "unauthenticated" }, { status: 401 })));
    await getCost({ headers: BACKGROUND });
    expect(new URL(leave.mock.calls[1]?.[0] ?? "", BASE).searchParams.get("why")).toBe("ended");
  });

  it("reads the session again once on 403 csrf, and does not resend the change", async () => {
    const queries = makeQueryClient();
    let sessions = 0;
    let changes = 0;
    server.use(
      http.get(`${BASE}/api/v1/session`, () => {
        sessions++;
        return HttpResponse.json(SESSION);
      }),
      http.post(`${BASE}/api/v1/proposals/confirm`, () => {
        changes++;
        return HttpResponse.json({ detail: "missing or wrong X-CSRF-Token", code: "csrf" }, { status: 403 });
      }),
    );
    setCsrf("stale");
    const result = await confirmProposals({ body: { investigations: [] } as never });
    expect(result.response?.status).toBe(403);
    expect(changes).toBe(1);
    expect(sessions).toBe(1);
    expect(csrfToken()).toBe("fresh-token");
    queries.clear();
  });

  it("does nothing more on another 403 or a 4xx, and never retries", async () => {
    let n = 0;
    server.use(
      http.post(`${BASE}/api/v1/proposals/confirm`, () => {
        n++;
        return HttpResponse.json({ detail: "no", code: "forbidden" }, { status: 403 });
      }),
      http.get(`${BASE}/api/v1/counts`, () => HttpResponse.text("not json", { status: 403 })),
    );
    await confirmProposals({ body: { investigations: [] } as never });
    await getCounts();
    expect(n).toBe(1);
    expect(seen.filter((r) => r.url.endsWith("/api/v1/session"))).toHaveLength(0);
  });

  it("feeds the build header to the stale-build check", async () => {
    server.use(http.get(`${BASE}/api/v1/counts`, () => HttpResponse.json({}, { headers: { "X-Argus-Build": "fedcba9876543210" } })));
    await getCounts();
    expect(serverBuild()).toBe("fedcba9876543210");
  });

  it("says errors in plain words", () => {
    expect(errorText(409, { detail: "it changed", code: "conflict" })).toBe("it changed");
    expect(errorText(409, { detail: "x".repeat(400) })).toHaveLength(300);
    expect(errorText(429, null)).toContain("wait a minute");
    expect(errorText(503, { detail: "" })).toContain("try again in a minute");
    expect(errorText(500, "boom")).toContain("it has been logged");
    expect(errorText(404, { code: "not_found" })).toBe("The request was refused (404).");
  });
});

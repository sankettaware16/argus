// The shell (docs/p4f-ui-spec.md §4): the system dot's three states and Today's banner (S-3), the
// Today badge as the Needs-you number (T-4), the old addresses' new homes (S-5), the classic
// queues still reachable (S-6), the Design system entry only for an admin (S-7), and `/` focusing
// the search box (R-2).
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";
import { systemDot } from "../src/lib/system";
import { BASE, ID, detail, mockApi, renderApp, server, sessionWith, shellHandlers } from "./helpers";
import { health, today } from "./v2Fixtures";

mockApi();
const NOW = new Date("2026-11-06T13:25:00Z");

describe("the system dot (§4.2)", () => {
  it("is OK, Caution or Problem by the defined rules, and only Problem has a banner", () => {
    const fresh = { siem_probed_at: "2026-11-06T13:20:00Z" };
    expect(systemDot(health(fresh), NOW)).toMatchObject({ state: "ok", word: "OK", banner: null });
    expect(systemDot(health({ ...fresh, siem_state: "caution" }), NOW)).toMatchObject({ state: "caution", banner: null });
    expect(systemDot(health({ ...fresh, kibana_sync: { state: "late", last_cycle_at: null, last_outcome: null, last_reason: null, last_complete_at: null } }), NOW).state).toBe("caution");
    expect(systemDot(health({ ...fresh, jobs_failed: 1 }), NOW).state).toBe("caution");
    const stop = systemDot(health({ siem_state: "stop", siem_probed_at: "2026-11-06T11:25:00Z" }), NOW, () => "4:55 PM");
    expect(stop.state).toBe("problem");
    expect(stop.banner).toBe("ARGUS has not read the SIEM since 4:55 PM (2 h). New incidents may be missing or late.");
    expect(systemDot(health({ siem_probed_at: "2026-11-06T12:00:00Z" }), NOW).state).toBe("problem"); // over 60 min old
    expect(stop.parts.map((p) => p.name)).toEqual(["SIEM", "ARGUS's reading", "Kibana read-back"]);
  });

  it("S-3: the stop fixture shows Problem and the banner on Today; caution shows Caution and no banner", async () => {
    server.use(http.get(`${BASE}/api/v1/health`, () => HttpResponse.json(health({ siem_state: "stop", siem_probed_at: new Date(Date.now() - 2 * 3_600_000).toISOString() }))));
    const view = renderApp("/");
    await waitFor(() => expect(screen.getByTestId("system-dot").getAttribute("data-state")).toBe("problem"));
    expect(within(screen.getByTestId("system-dot")).getByRole("button").textContent).toContain("Problem");
    expect((await screen.findByTestId("system-banner")).textContent).toMatch(/ARGUS has not read the SIEM since .* New incidents may be missing or late\./);
    view.unmount();
    server.use(http.get(`${BASE}/api/v1/health`, () => HttpResponse.json(health({ siem_state: "caution" }))));
    renderApp("/");
    await waitFor(() => expect(screen.getByTestId("system-dot").getAttribute("data-state")).toBe("caution"));
    expect(screen.queryByTestId("system-banner")).toBeNull();
  });
});

describe("the menu", () => {
  it("T-4: the Today badge is the Needs-you number", async () => {
    server.use(http.get(`${BASE}/api/v1/today`, () => HttpResponse.json(today())));
    renderApp("/");
    const nav = await screen.findByRole("navigation", { name: "Main" });
    expect((await within(nav).findByTestId("today-badge")).textContent).toContain("17");
  });

  it("S-2: a phone has the bottom tab bar with the same four pages", async () => {
    renderApp("/");
    const bar = await screen.findByTestId("bottom-bar");
    expect(within(bar).getAllByRole("link").map((a) => a.textContent)).toEqual(["Today", "Incidents", "Search", "Reports"]);
    expect(screen.getByTestId("app-header").className).toContain("h-14");
  });

  it("S-6, S-7: the classic queues are in More; the Design system only for an admin (this test build is not a dev build)", async () => {
    const user = userEvent.setup();
    const view = renderApp("/");
    const nav = await screen.findByRole("navigation", { name: "Main" });
    await user.click(within(nav).getByRole("button", { name: /More/ }));
    const more = within(screen.getByTestId("more-list"));
    expect(more.getByRole("link", { name: "Patterns" }).getAttribute("href")).toBe("/app/patterns");
    expect(more.getByRole("link", { name: "Proposals" }).getAttribute("href")).toBe("/app/proposals");
    const designShown = more.queryByRole("link", { name: "Design system" }) !== null;
    expect(designShown).toBe(import.meta.env.DEV);
    view.unmount();
    server.use(...shellHandlers(sessionWith(["view", "admin"])));
    renderApp("/");
    const admin = await screen.findByRole("navigation", { name: "Main" });
    await user.click(within(admin).getByRole("button", { name: /More/ }));
    expect(within(screen.getByTestId("more-list")).getByRole("link", { name: "Design system" })).toBeTruthy();
  });

  it("R-2: / focuses the search box from Today", async () => {
    const user = userEvent.setup();
    renderApp("/");
    await screen.findByRole("heading", { level: 1 });
    await user.keyboard("/");
    expect(document.activeElement?.getAttribute("data-search-box")).toBe("header");
  });
});

describe("the old addresses (S-5)", () => {
  const lands = async (from: string, path: string, search: Record<string, unknown>) => {
    const { router } = renderApp(from);
    await waitFor(() => expect(router.state.location.pathname).toBe(path));
    expect(router.state.location.search).toEqual(search);
  };

  it("send each old list to its new home, with the same parameters", async () => {
    server.use(http.get(`${BASE}/api/v1/investigations`, () => HttpResponse.json({ items: [], has_more: false, limit: 100, offset: 0, sort: "newest", view: "open" })));
    await lands("/cases?view=suspected", "/incidents", { view: "needs-you" });
    await lands("/cases?view=attention", "/incidents", { view: "needs-you" });
    await lands("/cases?view=active", "/incidents", { view: "open" });
    await lands("/cases?view=notified", "/incidents", { view: "owner-told" });
    await lands("/cases?view=closed", "/incidents", { view: "closed" });
    await lands("/inbox?view=open", "/search", { advanced: "1", view: "open" });
    await lands("/rules", "/search", { advanced: "1", view: "attention" });
    await lands("/metrics", "/quality", { tab: "metrics" });
    await lands("/gold", "/quality", { tab: "gold" });
  });

  it("send /investigations/<id> to /alert-groups/<id>", async () => {
    server.use(
      http.get(`${BASE}/api/v1/investigations/${ID}`, () => HttpResponse.json(detail())),
      http.get(`${BASE}/api/v1/investigations/${ID}/reports`, () => HttpResponse.json({ items: [], logs_hidden: false })),
    );
    const { router } = renderApp(`/investigations/${ID}`);
    await waitFor(() => expect(router.state.location.pathname).toBe(`/alert-groups/${ID}`));
  });
});

// The case list: views with their counts, a case found by number or word, the rows in words, and
// text from alerts and people shown as text.
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";
import { CASE2_ID, caseRow, casePage, RLO } from "./caseFixtures";
import { BASE, mockApi, must, renderApp, sent, server } from "./helpers";

mockApi();

describe("the views", () => {
  it("are links with their counts, and the open cases are the first", async () => {
    server.use(http.get(`${BASE}/api/v1/cases`, () => HttpResponse.json(casePage())));
    renderApp("/cases");
    await screen.findByRole("table", { name: "Cases" });
    const nav = screen.getByRole("navigation", { name: "Views" });
    expect(within(nav).getAllByRole("link").map((a) => a.textContent)).toEqual(["Open cases1", "Needs a person2", "Notified, still active0", "Needs attention1", "Mine2", "Suspected3", "Closed4", "All9"]);
    expect(within(nav).getByRole("link", { name: /^Open cases/ }).getAttribute("aria-current")).toBe("page");
    expect(within(nav).getByRole("link", { name: /^Mine/ }).getAttribute("href")).toBe("/app/cases?view=mine");
    expect(document.title).toBe("Cases · ARGUS");
  });

  it("read the view named in the address", async () => {
    server.use(http.get(`${BASE}/api/v1/cases`, ({ request }) => HttpResponse.json(casePage([], { view: new URL(request.url).searchParams.get("view") as "mine" }))));
    renderApp("/cases?view=mine");
    await screen.findByText("No case here.");
    expect(sent("GET", "/api/v1/cases")[0]?.path).toBe("/api/v1/cases?view=mine&offset=0&limit=100");
  });
});

describe("the rows", () => {
  it("say what a case is, who has it, how big it is and what it waits for", async () => {
    const waiting = caseRow({ id: CASE2_ID, number: 13, title: "Second", severity: "critical", state: "assigned", owner: { id: 1, username: "asha", display_name: "Asha Rao" }, waiting_for_approval: 2, needs_attention: true, in_kibana: true, kibana_wait: null });
    server.use(http.get(`${BASE}/api/v1/cases`, () => HttpResponse.json(casePage([caseRow(), waiting]))));
    renderApp("/cases");
    const table = await screen.findByRole("table", { name: "Cases" });
    const rows = within(table).getAllByRole("row").slice(1);
    const text = (i: number) => rows[i]?.textContent?.replace(/\s+/g, " ") ?? "";
    expect(text(0)).toContain("Case 12: Regular beaconing from 10.0.0.1");
    expect(text(0)).toContain("Open");
    expect(text(0)).toContain("nobody");
    expect(text(0)).toContain("3 · 41");
    expect(text(0)).toContain("waits for Kibana");
    expect(text(1)).toContain("Assigned");
    expect(text(1)).toContain("Asha Rao");
    expect(text(1)).toContain("attention");
    expect(text(1)).toContain("2 to approve");
    expect(text(1)).toContain("in Kibana");
    expect(within(rows[0] as HTMLElement).getByRole("link").getAttribute("href")).toBe("/app/cases/c1c1c1c1-0000-4000-8000-000000000001");
  });

  it("say why a closed case is closed and where a merged one went", async () => {
    const closed = caseRow({ state: "closed", closure_reason: "benign_policy", closed_at: "2026-10-25T04:00:00Z" });
    const merged = caseRow({ id: CASE2_ID, number: 14, state: "closed", closure_reason: "duplicate", merged_into: { id: "x", number: 12, title: "t", state: "open" } });
    server.use(http.get(`${BASE}/api/v1/cases`, () => HttpResponse.json(casePage([closed, merged], { view: "closed" }))));
    renderApp("/cases?view=closed");
    await screen.findByText("Closed: Benign: allowed by policy");
    expect(screen.getByText("Merged into case 12")).toBeTruthy();
  });

  it("are text only, whatever a title holds", async () => {
    const title = `<img src=x onerror="window.__pwned=1"> ${RLO}elif`;
    server.use(http.get(`${BASE}/api/v1/cases`, () => HttpResponse.json(casePage([caseRow({ title, owner: { id: 3, username: "evil", display_name: title } })]))));
    const { container } = renderApp("/cases");
    await screen.findByRole("table", { name: "Cases" });
    expect(container.querySelector("main img")).toBeNull();
    expect(container.querySelectorAll("main .ut-mark").length).toBeGreaterThanOrEqual(2);
    expect((window as unknown as { __pwned?: number }).__pwned).toBeUndefined();
  });

  it("say what to do when there is nothing", async () => {
    server.use(http.get(`${BASE}/api/v1/cases`, () => HttpResponse.json(casePage([]))));
    renderApp("/cases");
    expect(await screen.findByText(/No open case\. ARGUS opens one when a person's verdict confirms a true positive\./)).toBeTruthy();
  });
});

describe("finding a case", () => {
  it("by number, across every view, and the address keeps it", async () => {
    const user = userEvent.setup();
    server.use(http.get(`${BASE}/api/v1/cases`, () => HttpResponse.json(casePage([caseRow()]))));
    const { history } = renderApp("/cases?view=mine");
    await screen.findByRole("table", { name: "Cases" });
    await user.type(screen.getByRole("textbox", { name: /Find a case/ }), "12");
    await user.click(screen.getByRole("button", { name: "Find" }));
    await waitFor(() => expect(history.location.search).toBe("?view=mine&q=12"));
    await waitFor(() => expect(sent("GET", "/api/v1/cases").some((r) => r.path.includes("number=12") && r.path.includes("view=all"))).toBe(true));
    await user.click(screen.getByRole("button", { name: "Clear" }));
    await waitFor(() => expect(history.location.search).toBe("?view=mine"));
    expect((screen.getByRole("textbox", { name: /Find a case/ }) as HTMLInputElement).value).toBe("");
  });

  it("by a word of the title, and says when nothing matches", async () => {
    const user = userEvent.setup();
    server.use(http.get(`${BASE}/api/v1/cases`, ({ request }) => HttpResponse.json(casePage(new URL(request.url).searchParams.get("q") === "zzz" ? [] : [caseRow()]))));
    renderApp("/cases");
    await screen.findByRole("table", { name: "Cases" });
    await user.type(screen.getByRole("textbox", { name: /Find a case/ }), "zzz");
    await user.click(screen.getByRole("button", { name: "Find" }));
    expect(await screen.findByText("Nothing matches that. Try a number or another word.")).toBeTruthy();
  });
});

describe("a long list", () => {
  it("shows more cases on request and says it is not the whole list yet", async () => {
    const user = userEvent.setup();
    server.use(
      http.get(`${BASE}/api/v1/cases`, ({ request }) => {
        const offset = Number(new URL(request.url).searchParams.get("offset"));
        return HttpResponse.json(casePage([caseRow({ id: offset === 0 ? CASE2_ID : "c3c3c3c3-0000-4000-8000-000000000003", number: offset === 0 ? 2 : 1, title: offset === 0 ? "Newer" : "Older" })], { has_more: offset === 0, offset }));
      }),
    );
    renderApp("/cases");
    expect(await screen.findByText("1 or more case.")).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Show more cases" }));
    expect(await screen.findByText("2 cases.")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Show more cases" })).toBeNull();
    expect(must(screen.getByRole("link", { name: /Older/ }))).toBeTruthy();
  });
});

describe("a list that cannot be read", () => {
  it("says so once, offers one try again, and does not retry by itself", async () => {
    server.use(http.get(`${BASE}/api/v1/cases`, () => HttpResponse.json({ detail: "boom", code: "internal" }, { status: 500 })));
    renderApp("/cases");
    expect(await screen.findByText(/The cases could not be shown\./)).toBeTruthy();
    await new Promise((r) => setTimeout(r, 200));
    expect(sent("GET", "/api/v1/cases")).toHaveLength(1);
    expect(screen.getAllByRole("button", { name: "Try again" })).toHaveLength(1);
  });
});

// The two-pane Inbox in the app: the list, the keys, the pane that follows the cursor, the one-pane
// layout below 1024 px, the validated search and the pages read as the list nears its end.
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { beforeEach, describe, expect, it } from "vitest";
import type { InvestigationPage } from "../src/client/types.gen";
import { BASE, detail, ID, ID2, ID3, investigation, layout, must, renderApp, REPORT, sent, server, setLeaveSpy, mockApi, viewport } from "./helpers";

mockApi();
beforeEach(() => {
  layout();
  viewport(true);
});

const row = (id: string, n: number) => investigation(id, { rule_name: `Rule ${n}`, key_fields: [{ field: "source.ip", value: `10.0.0.${n}` }] });
const ROWS = [row(ID, 1), row(ID2, 2), row(ID3, 3)];

function page(items = ROWS, more = false, view: "attention" | "open" | "reviewed" | "all" = "attention"): InvestigationPage {
  return { items, view, sort: "newest", offset: 0, limit: 100, has_more: more };
}

function api(items = ROWS) {
  server.use(
    http.get(`${BASE}/api/v1/investigations`, () => HttpResponse.json(page(items))),
    http.get(`${BASE}/api/v1/investigations/:id`, ({ params }) => HttpResponse.json({ ...detail(), investigation: { ...investigation(String(params.id)), rule_name: `Detail of ${String(params.id).slice(0, 4)}` } })),
    http.get(`${BASE}/api/v1/investigations/:id/reports`, () => HttpResponse.json({ items: [REPORT], logs_hidden: false })),
    http.get(`${BASE}/api/v1/rules`, () => HttpResponse.json([{ rule_id: "rule-0", rule_name: "Rule zero", investigations: 3, open: 3, alerts: 6, last_event_at: null, type: null, revision: null, interval: null, max_signals: null, execution_status: null, truncated: 0 }])),
  );
}

const grid = () => screen.getByRole("grid", { name: "Investigations" });
const cursorText = () => document.getElementById(grid().getAttribute("aria-activedescendant") ?? "x")?.textContent ?? "";

describe("two panes", () => {
  it("reads the list for the view in the address, newest first, and opens the first investigation at its right", async () => {
    api();
    const { router } = renderApp("/inbox");
    await screen.findByRole("grid", { name: "Investigations" });
    expect(sent("GET", "/api/v1/investigations?")[0]?.path).toBe("/api/v1/investigations?view=attention&sort=newest&offset=0&limit=100");
    await waitFor(() => expect(router.state.location.search).toMatchObject({ view: "attention", id: ID }));
    expect(await screen.findByText(`Detail of ${ID.slice(0, 4)}`)).toBeTruthy();
    expect(grid().getAttribute("aria-rowcount")).toBe("4");
    expect(cursorText()).toContain("Rule 1");
    expect(screen.getByRole("region", { name: "Investigation details" })).toBeTruthy();
  });

  it("has the views as links with their counts, and the one shown is the current page", async () => {
    api();
    renderApp("/inbox?view=open");
    const views = within(await screen.findByRole("navigation", { name: "Views" }));
    await views.findByText("13");
    expect(views.getAllByRole("link").map((a) => a.textContent)).toEqual(["Needs attention6", "Not reviewed yet13", "Reviewed4", "All17", "Notified, still active3"]);
    expect(views.getByRole("link", { name: /Not reviewed yet/ }).getAttribute("aria-current")).toBe("page");
    expect(views.getByRole("link", { name: /^All/ }).getAttribute("href")).toBe("/app/inbox?view=all");
    expect(sent("GET", "/api/v1/investigations?")[0]?.path).toContain("view=open");
  });

  it("has the notified, still active investigations as a view, with what it means", async () => {
    api();
    renderApp("/inbox?view=known");
    await screen.findByRole("grid", { name: "Investigations" });
    expect(sent("GET", "/api/v1/investigations?")[0]?.path).toContain("view=known");
    const views = within(screen.getByRole("navigation", { name: "Views" }));
    expect(views.getByRole("link", { name: /^Notified, still active/ }).getAttribute("aria-current")).toBe("page");
    expect(screen.getByText(/Investigations of devices whose owner was told \(a notified case\)/)).toBeTruthy();
  });

  it("opens a deep link's investigation even when it is not in the list, with its tab", async () => {
    api();
    renderApp(`/inbox?id=${ID3}&tab=report`);
    await screen.findByText(`Detail of ${ID3.slice(0, 4)}`);
    expect(screen.getByRole("tab", { name: "Report", selected: true })).toBeTruthy();
    expect(await screen.findByText("Verdict")).toBeTruthy();
  });

  it("says when there is nothing", async () => {
    server.use(http.get(`${BASE}/api/v1/investigations`, () => HttpResponse.json(page([]))));
    renderApp("/inbox");
    expect(await screen.findByText("Nothing here.")).toBeTruthy();
  });

  it("says what went wrong when the list fails, once, with a way to try again", async () => {
    server.use(http.get(`${BASE}/api/v1/investigations`, () => HttpResponse.json({ detail: "ARGUS cannot reach its database; try again in a minute", code: "unavailable" }, { status: 503 })));
    renderApp("/inbox");
    const problem = await screen.findByText("The list could not be shown.");
    expect(problem.closest("[role=alert]")?.textContent).toContain("ARGUS cannot reach its database");
    expect(within(problem.closest("[role=alert]") as HTMLElement).getByRole("button", { name: "Try again" })).toBeTruthy();
    await new Promise((r) => setTimeout(r, 120));
    expect(sent("GET", "/api/v1/investigations?")).toHaveLength(1);
  });

  it("sends the person to sign in when the session ended", async () => {
    const urls: string[] = [];
    setLeaveSpy(urls);
    server.use(http.get(`${BASE}/api/v1/investigations`, () => HttpResponse.json({ detail: "sign in first", code: "unauthenticated" }, { status: 401 })));
    renderApp("/inbox");
    await screen.findByText("The list could not be shown.");
    expect(urls[0]).toMatch(/^\/signin\?next=.*&why=ended$/);
  });
});

describe("the keys", () => {
  it("move the cursor with j, k and the arrows; the right pane follows once the cursor rests", async () => {
    api();
    const user = userEvent.setup();
    renderApp("/inbox");
    await screen.findByText(`Detail of ${ID.slice(0, 4)}`);
    grid().focus();
    await user.keyboard("j");
    expect(cursorText()).toContain("Rule 2");
    await user.keyboard("{ArrowDown}");
    expect(cursorText()).toContain("Rule 3");
    await user.keyboard("k");
    expect(cursorText()).toContain("Rule 2");
    expect(grid().querySelectorAll("[aria-selected=true]")).toHaveLength(1);
    await screen.findByText(`Detail of ${ID2.slice(0, 4)}`);
    // the pane followed the rest, not each key: the investigations in between were never read
    expect(sent("GET", `/api/v1/investigations/${ID3}`).filter((r) => r.path === `/api/v1/investigations/${ID3}`)).toHaveLength(0);
  });

  it("move the focus into the investigation with Enter, and back to the list with Escape", async () => {
    api();
    const user = userEvent.setup();
    renderApp("/inbox");
    await screen.findByText(`Detail of ${ID.slice(0, 4)}`);
    grid().focus();
    await user.keyboard("j{Enter}");
    await waitFor(() => expect(document.activeElement?.id).toBe("detail-pane"));
    await screen.findByText(`Detail of ${ID2.slice(0, 4)}`);
    await user.keyboard("{Escape}");
    expect(document.activeElement).toBe(grid());
  });

  it("show their list with ?, which Escape closes, the focus back on the list", async () => {
    api();
    const user = userEvent.setup();
    renderApp("/inbox");
    await screen.findByText(`Detail of ${ID.slice(0, 4)}`);
    grid().focus();
    await user.keyboard("?");
    const dialog = await screen.findByRole("dialog", { name: "Keyboard shortcuts in the Inbox" });
    expect(dialog.textContent).toContain("next investigation");
    expect(dialog.textContent).toContain("Enter");
    await user.keyboard("{Escape}");
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    await waitFor(() => expect(document.activeElement).toBe(grid()));
  });

  it("can be switched off, the letters only: the arrows and Enter still work, and the choice is kept", async () => {
    api();
    const user = userEvent.setup();
    const { unmount } = renderApp("/inbox");
    await screen.findByText(`Detail of ${ID.slice(0, 4)}`);
    const box = screen.getByLabelText("Single-key shortcuts (j, k, ?)") as HTMLInputElement;
    expect(box.checked).toBe(true);
    await user.click(box);
    expect(window.localStorage.getItem("argus-shortcuts")).toBe("off");
    grid().focus();
    await user.keyboard("j");
    await user.keyboard("?");
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(cursorText()).toContain("Rule 1");
    await user.keyboard("{ArrowDown}");
    expect(cursorText()).toContain("Rule 2");
    unmount();
    renderApp("/inbox");
    await screen.findByRole("grid", { name: "Investigations" });
    expect((screen.getByLabelText("Single-key shortcuts (j, k, ?)") as HTMLInputElement).checked).toBe(false);
  });

  it("still list the shortcuts from the ? button when the letters are off", async () => {
    api();
    window.localStorage.setItem("argus-shortcuts", "off");
    const user = userEvent.setup();
    renderApp("/inbox");
    await screen.findByRole("grid", { name: "Investigations" });
    await user.click(screen.getByRole("button", { name: "Show keyboard shortcuts" }));
    expect(await screen.findByRole("dialog")).toBeTruthy();
  });
});

describe("one pane below 1024 px", () => {
  beforeEach(() => viewport(false));

  it("shows the list first and does not open an investigation by itself", async () => {
    api();
    const { router } = renderApp("/inbox");
    await screen.findByRole("grid", { name: "Investigations" });
    await new Promise((r) => setTimeout(r, 200));
    expect(screen.queryByRole("region", { name: "Investigation details" })).toBeNull();
    expect(router.state.location.search).toEqual({ view: "attention" });
    expect(sent("GET", `/api/v1/investigations/${ID}`)).toHaveLength(0);
  });

  it("opens the investigation alone on Enter or a click, with a way back that returns to the list", async () => {
    api();
    const user = userEvent.setup();
    renderApp("/inbox");
    await screen.findByRole("grid", { name: "Investigations" });
    grid().focus();
    await user.keyboard("jj");
    await new Promise((r) => setTimeout(r, 200));
    expect(sent("GET", `/api/v1/investigations/${ID2}`)).toHaveLength(0); // moving the cursor opens nothing
    await user.keyboard("{Enter}");
    await screen.findByText(`Detail of ${ID2.slice(0, 4)}`);
    expect(screen.queryByRole("grid")).toBeNull();
    await user.click(screen.getByRole("button", { name: "← Back to the list" }));
    await screen.findByRole("grid", { name: "Investigations" });
    await waitFor(() => expect(document.activeElement).toBe(grid()));
    await user.click(must(within(grid()).getAllByRole("row")[3]));
    await screen.findByText(`Detail of ${ID3.slice(0, 4)}`);
  });
});

describe("the search", () => {
  it("refuses an address that is not one, in words, and sends nothing", async () => {
    api();
    const user = userEvent.setup();
    renderApp("/inbox");
    await screen.findByRole("grid", { name: "Investigations" });
    await user.click(screen.getByText("Find, filter and sort"));
    await user.type(screen.getByLabelText("Value"), "999.1.1.1");
    await user.click(screen.getByRole("button", { name: "Find" }));
    expect((await screen.findByText(/That is not an IP address\. Write it like 10\.8\.235\.157/)).getAttribute("role")).toBe("alert");
    expect(sent("GET", "/api/v1/investigations?")).toHaveLength(1);
  });

  it("finds what was typed, written the way ARGUS stores it, across every investigation", async () => {
    api();
    const user = userEvent.setup();
    const { router } = renderApp("/inbox");
    await screen.findByRole("grid", { name: "Investigations" });
    await user.click(screen.getByText("Find, filter and sort"));
    await user.selectOptions(screen.getByLabelText("Find"), "domain");
    await user.type(screen.getByLabelText("Value"), " Example.COM. ");
    await user.click(screen.getByRole("button", { name: "Find" }));
    await waitFor(() => expect(router.state.location.search).toMatchObject({ view: "all", kind: "domain", value: "example.com" }));
    await waitFor(() => expect(sent("GET", "/api/v1/investigations?").some((r) => r.path.includes("kind=domain&value=example.com"))).toBe(true));
    await waitFor(() => expect(screen.getByText("Find, filter and sort").closest("details")?.textContent).toContain("Showing domain example.com."));
    expect(screen.getByRole("link", { name: "Clear" }).getAttribute("href")).toBe("/app/inbox?view=all");
  });

  it("narrows to one rule from the rule menu and turns the sort around", async () => {
    api();
    const user = userEvent.setup();
    const { router } = renderApp("/inbox");
    await screen.findByRole("grid", { name: "Investigations" });
    await user.click(screen.getByText("Find, filter and sort"));
    await screen.findByRole("option", { name: "Rule zero" });
    await user.selectOptions(screen.getByLabelText("Rule"), "rule-0");
    await waitFor(() => expect(router.state.location.search).toMatchObject({ rule: "rule-0" }));
    await user.selectOptions(screen.getByLabelText("Sort"), "oldest");
    await waitFor(() => expect(sent("GET", "/api/v1/investigations?").some((r) => r.path.includes("sort=oldest") && r.path.includes("rule=rule-0"))).toBe(true));
  });
});

describe("reading more", () => {
  it("reads the next page, from offset 100, when the window nears the end, and stops at the last", async () => {
    let calls = 0;
    server.use(
      http.get(`${BASE}/api/v1/investigations`, ({ request }) => {
        calls += 1;
        const offset = Number(new URL(request.url).searchParams.get("offset"));
        return HttpResponse.json(offset === 0 ? page(ROWS, true) : page([row("aaaaaaaa-0000-4000-8000-000000000001", 4)], false));
      }),
      http.get(`${BASE}/api/v1/investigations/:id`, () => HttpResponse.json(detail())),
      http.get(`${BASE}/api/v1/investigations/:id/reports`, () => HttpResponse.json({ items: [], logs_hidden: false })),
    );
    renderApp("/inbox");
    await waitFor(() => expect(calls).toBe(2));
    await waitFor(() => expect(grid().getAttribute("aria-rowcount")).toBe("5"));
    expect(sent("GET", "/api/v1/investigations?").map((r) => new URL(`http://x${r.path}`).searchParams.get("offset"))).toEqual(["0", "100"]);
    await new Promise((r) => setTimeout(r, 150));
    expect(calls).toBe(2);
  });
});

describe("a page that fails to read", () => {
  it("is said once, is not asked for again by itself, and leaves the rows already read", async () => {
    let calls = 0;
    server.use(
      http.get(`${BASE}/api/v1/investigations`, ({ request }) => {
        calls += 1;
        const offset = Number(new URL(request.url).searchParams.get("offset"));
        return offset === 0 ? HttpResponse.json(page(ROWS, true)) : HttpResponse.json({ detail: "ARGUS cannot reach its database; try again in a minute", code: "unavailable" }, { status: 503 });
      }),
      http.get(`${BASE}/api/v1/investigations/:id`, () => HttpResponse.json(detail())),
      http.get(`${BASE}/api/v1/investigations/:id/reports`, () => HttpResponse.json({ items: [], logs_hidden: false })),
    );
    renderApp("/inbox");
    const problem = await screen.findByText("The next part of the list could not be shown.");
    expect(problem.closest("[role=alert]")?.textContent).toContain("ARGUS cannot reach its database");
    await new Promise((r) => setTimeout(r, 400));
    expect(calls).toBe(2); // the first page, and the one that failed: never more by itself
    expect(grid().getAttribute("aria-rowcount")).toBe("4");
  });
});

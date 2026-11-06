// Today (docs/p4f-ui-spec.md §5): the summary (T-4), every P1 and P2 on its own card and at most 8
// lower slots (T-3), no lane phrase or version on cards (T-5), "N similar" (T-6), confirm from a
// card (T-7), the Kibana line (T-8), d s on the exposure P2 (T-9), the spot-check's order (T-12),
// the gray alert group (T-13, A-3), Home when Today is not served (T-16), and the outside address
// never a Device (G-5).
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";
import { caseRow, casePage } from "./caseFixtures";
import { BASE, detail as investigationDetail, mockApi, renderApp, sent, server } from "./helpers";
import { CONF_ID, GROUP_ID, P1_ID, P2X_ID, today } from "./v2Fixtures";

mockApi();

function serveToday(body: Record<string, unknown> = today()) {
  server.use(http.get(`${BASE}/api/v1/today`, () => HttpResponse.json(body)));
}

const cards = () => screen.getAllByTestId("incident-card");

describe("Today", () => {
  it("T-16: falls back to Home when /today answers 404", async () => {
    renderApp("/");
    expect(await screen.findByRole("heading", { level: 1, name: "Home" })).toBeTruthy();
    expect(screen.queryByTestId("today-summary")).toBeNull();
  });

  it("falls back to Home while the engine only watches (shadow)", async () => {
    serveToday(today({ mode: "shadow" }));
    renderApp("/");
    expect(await screen.findByRole("heading", { level: 1, name: "Home" })).toBeTruthy();
  });

  it("T-4: the summary starts with the urgent count, the rest need you", async () => {
    serveToday();
    renderApp("/");
    const summary = await screen.findByTestId("today-summary");
    expect(summary.textContent?.startsWith("2 urgent (P1) · 15 more need you · 1 with new activity · ARGUS handled 1,140 since your last round")).toBe(true);
    expect(within(summary).getByText("2 urgent (P1)").tagName).toBe("STRONG");
  });

  it("T-3, T-6: every P1 and P2 has its own card, the 3 similar collapse into one row, the rest is one line", async () => {
    serveToday();
    renderApp("/");
    const needs = await screen.findByTestId("today-needs-you");
    const own = within(needs).getAllByTestId("incident-card");
    const urgent = own.filter((c) => ["P1", "P2"].includes(c.getAttribute("data-band") ?? ""));
    expect(urgent).toHaveLength(4);
    expect(own.length - urgent.length).toBeLessThanOrEqual(8);
    const similar = within(needs).getAllByTestId("similar-row");
    expect(similar).toHaveLength(1);
    expect(similar[0]?.textContent).toContain("3 similar: P3");
    expect(similar[0]?.textContent).toContain("no HTTP 200 after the alerts");
    expect(similar[0]?.textContent).not.toMatch(/P1|P2/);
    expect(within(needs).getByTestId("today-more-waiting").textContent).toContain("+ 4 more waiting · lower priority");
  });

  it("T-5: no card shows a lane phrase, a version or an evidence id", async () => {
    serveToday();
    renderApp("/");
    await screen.findByTestId("today-needs-you");
    for (const c of cards()) expect(c.textContent).not.toMatch(/Strong signal|Sudden burst|Slow build-up|\bv\d+\b|\bE\d+\b/i);
  });

  it("G-5: the P1's outside address is an Outside address on its card", async () => {
    serveToday();
    renderApp("/");
    await screen.findByTestId("today-needs-you");
    const p1 = cards().find((c) => c.getAttribute("data-id") === P1_ID) as HTMLElement;
    const actors = within(p1).getAllByTestId("entity-chip").filter((c) => c.getAttribute("data-role") === "actor");
    expect(actors[0]?.textContent).toBe("Outside address 203.0.113.40");
    for (const chip of document.querySelectorAll("[data-testid=entity-chip][data-role=actor]")) expect(chip.getAttribute("data-noun")).not.toBe("Device");
  });

  it("the P1 card: meta line, changed strip, three why points then +N more, checks with words, two sides", async () => {
    serveToday();
    renderApp("/");
    await screen.findByTestId("today-needs-you");
    const p1 = within(cards().find((c) => c.getAttribute("data-id") === P1_ID) as HTMLElement);
    expect(p1.getByTestId("card-meta").textContent).toMatch(/Possible incident #31 · .*still active since 4 Nov · waiting for a person since .* · Raised by ARGUS's AI/);
    expect(p1.getByTestId("changed-strip").textContent).toContain("New since you last looked: 2 more campus devices");
    expect(p1.getByTestId("card-why").textContent).toContain("+50 VirusTotal: 7 of 94 engines flag 203.0.113.40 · +20 Regular timing");
    expect(p1.getByTestId("card-why").textContent).toContain("+2 more");
    expect(p1.getByTestId("checks-inline").textContent).toMatch(/Checked: .*Ruled out: .*Not known: /);
    expect(p1.getByRole("heading", { level: 3 })).toBeTruthy();
  });

  it("T-7: confirm from a card shows the Kibana sentence and Still open, then a decided row with its Kibana state", async () => {
    const user = userEvent.setup();
    serveToday();
    server.use(http.post(`${BASE}/api/v1/cases/${P1_ID}/confirm`, () => HttpResponse.json({ case: caseRow({ id: P1_ID, number: 31, state: "open", version: 4, in_kibana: false, kibana_wait: "waiting for someone who may open it in Kibana" }), result: "done", request_id: null })));
    renderApp("/");
    await screen.findByTestId("today-needs-you");
    const p1 = cards().find((c) => c.getAttribute("data-id") === P1_ID) as HTMLElement;
    await user.click(within(p1).getByRole("button", { name: "Confirm incident…" }));
    const dialog = within(await screen.findByRole("alertdialog"));
    expect(dialog.getByTestId("what-happens").textContent).toContain("nothing is sent there by this");
    expect(dialog.getByTestId("still-open")).toBeTruthy();
    await user.click(dialog.getByRole("button", { name: "Confirm anyway" }));
    const row = await screen.findByTestId("decided-row");
    expect(row.textContent).toContain("#31");
    expect(row.textContent).toContain("Confirmed by you · Not in Kibana yet: waiting for someone who may open it in Kibana");
    await waitFor(() => expect(cards().some((c) => c.getAttribute("data-id") === P1_ID)).toBe(false));
  });

  it("T-8: the Kibana line names the confirmed incident not in Kibana for over an hour", async () => {
    serveToday();
    const threeHoursAgo = new Date(Date.now() - 3 * 3_600_000).toISOString();
    server.use(http.get(`${BASE}/api/v1/cases`, ({ request }) => HttpResponse.json(new URL(request.url).searchParams.get("view") === "active" ? casePage([caseRow({ id: CONF_ID, number: 33, state: "open", opened_at: threeHoursAgo, in_kibana: false })]) : casePage([]))));
    renderApp("/");
    const line = await screen.findByTestId("today-kibana");
    expect(line.textContent).toContain("1 confirmed incident is not in Kibana yet, so ACME cannot see it there. Oldest #33");
    expect(within(line).getByRole("link", { name: "See them" }).getAttribute("href")).toBe("/app/incidents?view=open&kibana=waiting");
  });

  it("T-9: d then s on the exposure P2 finds Scan or attempt disabled", async () => {
    const user = userEvent.setup();
    serveToday();
    renderApp("/");
    await screen.findByTestId("today-needs-you");
    const p2 = cards().find((c) => c.getAttribute("data-id") === P2X_ID) as HTMLElement;
    within(p2).getByTestId("card-title").focus();
    await user.keyboard("d");
    const menu = await within(p2).findByRole("menu");
    await user.keyboard("s");
    const scan = within(menu).getAllByRole("menuitem").find((m) => m.getAttribute("data-reason") === "attempt_no_impact") as HTMLElement;
    expect(scan.getAttribute("aria-disabled")).toBe("true");
    expect(scan.textContent).toContain("Something answered: check first");
    expect(within(p2).queryByTestId("dismiss-sheet")).toBeNull();
  });

  it("j moves between the cards' titles", async () => {
    const user = userEvent.setup();
    serveToday();
    renderApp("/");
    await screen.findByTestId("today-needs-you");
    await user.keyboard("j");
    expect(document.activeElement?.getAttribute("data-testid")).toBe("card-title");
    const first = document.activeElement;
    await user.keyboard("j");
    expect(document.activeElement).not.toBe(first);
  });

  it("T-12: a spot-check shows the facts before ARGUS's conclusion, and no primary button", async () => {
    serveToday();
    renderApp("/");
    const audits = await screen.findAllByTestId("today-audit");
    expect(audits).toHaveLength(3);
    const a = audits[0] as HTMLElement;
    const facts = within(a).getByTestId("audit-facts");
    const closed = within(a).getByTestId("audit-closed-as");
    expect(facts.compareDocumentPosition(closed) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(facts.textContent).toBe("212 requests from 192.0.2.15 to 3 campus servers · answers: 212 × 403 · no 2xx");
    expect(closed.textContent).toBe("ARGUS closed it as: known noise");
    expect(within(a).queryAllByRole("button").filter((b) => b.className.includes("bg-accent"))).toHaveLength(0);
    expect(screen.getByTestId("audit-score").textContent).toBe("Your team's spot-checks, 30 days: 64 checked, 1 wrong");
  });

  it("T-13, A-3: the gray alert group's primary is Real: open an incident…, and nothing is sent before the dialog's own button", async () => {
    const user = userEvent.setup();
    serveToday();
    server.use(
      http.get(`${BASE}/api/v1/investigations/${GROUP_ID}`, () => HttpResponse.json(investigationDetail({}, { id: GROUP_ID, version: 7, latest_review: null }))),
      http.post(`${BASE}/api/v1/investigations/${GROUP_ID}/reviews`, () => HttpResponse.json({ ok: true })),
    );
    renderApp("/");
    const gray = await screen.findByTestId("today-gray");
    const group = within(gray).getAllByTestId("incident-card").find((c) => c.getAttribute("data-kind") === "alert_group") as HTMLElement;
    const real = within(group).getByRole("button", { name: "Real: open an incident…" });
    expect(real.className).toContain("bg-accent");
    await user.click(real);
    const dialog = within(await screen.findByRole("alertdialog"));
    expect(dialog.getByText(/Marking it real opens a possible incident, or adds it to the incident that holds its activity/)).toBeTruthy();
    expect(sent("POST", "/api")).toHaveLength(0);
    await user.click(dialog.getByRole("button", { name: "Mark it real" }));
    await waitFor(() => expect(sent("POST", `/api/v1/investigations/${GROUP_ID}/reviews`)).toHaveLength(1));
    expect(JSON.parse(sent("POST", `/api/v1/investigations/${GROUP_ID}/reviews`)[0]?.body ?? "")).toEqual({ action: "reviewed", outcome: "true_positive", seen_review: null, seen_version: 7 });
  });

  it("the gray incident says why ARGUS is unsure and the check that would decide", async () => {
    serveToday();
    renderApp("/");
    const gray = await screen.findByTestId("today-gray");
    expect(gray.textContent).toContain("Why it's unsure: 40 failures, then 1 success; no second sign seen");
    expect(gray.textContent).toContain("The check that would decide: did the account sign in from a new place after the success?");
    expect(gray.textContent).not.toContain("Raise as possible incident");
  });

  it("new activity is one line each with its first change", async () => {
    serveToday();
    renderApp("/");
    const lines = await screen.findByTestId("today-new-activity");
    expect(lines.textContent).toContain("#12");
    expect(lines.textContent).toContain("Owner told 2 Nov");
    expect(lines.textContent).toContain("New: a second destination");
  });

  it("says plainly when nothing needs you and ARGUS closed nothing", async () => {
    serveToday({ mode: "present", needs_you: [], more_waiting: 0, new_activity: [], gray: [], handled: { since: null, count: 0, categories: [], audit: null } });
    renderApp("/");
    expect(await screen.findByText("Nothing needs you right now. ARGUS puts new incidents here.")).toBeTruthy();
    expect(screen.getByText("No new activity on incidents you know.")).toBeTruthy();
    expect(screen.getByText("ARGUS closed nothing on its own since your last round.")).toBeTruthy();
    expect(screen.queryByTestId("today-gray")).toBeNull();
  });

  it("says Today could not load, and nothing was changed, when it fails", async () => {
    server.use(http.get(`${BASE}/api/v1/today`, () => HttpResponse.json({ detail: "boom" }, { status: 500 })));
    renderApp("/");
    const error = await screen.findByTestId("today-error");
    expect(error.textContent).toContain("Today could not load. Nothing was changed.");
    expect(within(error).getByRole("button", { name: "Try again" })).toBeTruthy();
  });
});

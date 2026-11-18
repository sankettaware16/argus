// The incident page's top (docs/p4f-ui-spec.md §7.1–§7.3, step 2): the sticky decision bar in
// words (I-2), the Overview's order (I-5), points that add up (I-6), the AI label (I-7), the
// still-fits line (I-8), Undo after a dismissal (I-9, T-11), a 409 (I-10), the CISO draft (I-11),
// "Taken by" (I-12), no UUID outside [⋯] (I-13), every ? says Not known (I-14), the confirm dialog
// (§5.4) and the dismiss menu's keys and guard (T-9, T-10).
import { act, fireEvent, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";
import type { CaseDetail } from "../src/client/types.gen";
import { cisoDraft } from "../src/components/incident/Ciso";
import { engineOf } from "../src/lib/engine";
import { caseRow } from "./caseFixtures";
import { report, reportOut } from "./incidentFixtures";
import { BASE, mockApi, renderApp, sent, server, sessionWith, shellHandlers } from "./helpers";
import { engineBlock, P1_ID, p1Detail, p1Engine } from "./v2Fixtures";

mockApi();
const CASE_URL = `${BASE}/api/v1/cases/${P1_ID}`;
const UUID = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i;

function serve(d: CaseDetail, rep = reportOut({ case_id: P1_ID, case_number: 31, case_state: d.case.state }, { summary: { ...report().summary, prose: [{ by: "model", cites: [], text: "Since 4 Nov, five lab PCs sent small HTTP POSTs to 203.0.113.40 about every 10 minutes." }] } })) {
  server.use(
    http.get(CASE_URL, () => HttpResponse.json(d)),
    http.get(`${CASE_URL}/report`, () => HttpResponse.json(rep)),
  );
}

const bar = async () => within(await screen.findByTestId("decision-bar"));

describe("the decision bar (§7.1)", () => {
  it("I-2: says ARGUS's call in words and the band, never the number", async () => {
    serve(p1Detail());
    renderApp(`/incidents/${P1_ID}`);
    const call = (await bar()).getByTestId("bar-call").textContent ?? "";
    expect(call).toMatch(/ARGUS: .* · Priority P[1-4]/);
    expect(call).toBe("ARGUS: likely real · Priority P1");
    expect(call).not.toMatch(/\(\d+\)|\b82\b/);
  });

  it("offers Confirm incident…, Not an incident ▾ and Merge into… on a possible incident, Confirm first", async () => {
    serve(p1Detail());
    renderApp(`/incidents/${P1_ID}`);
    const b = await bar();
    const names = b.getAllByRole("button").map((x) => x.textContent);
    expect(names.slice(0, 3)).toEqual(["Confirm incident…", "Not an incident ▾", "Merge into…"]);
    expect(b.getByRole("button", { name: "Confirm incident…" }).className).toContain("bg-accent");
  });

  it("an open incident nobody took: Take it first, then Assign and More; never Owner:", async () => {
    serve(p1Detail({ decision: null }, { state: "open" }));
    renderApp(`/incidents/${P1_ID}`);
    const b = await bar();
    expect(b.getAllByRole("button")[0]?.textContent).toBe("Take it");
    expect(b.getByRole("button", { name: "More ▾" })).toBeTruthy();
    // a person confirmed it (here: opened it), never "ARGUS: confirmed" (§7.1)
    expect(b.getByTestId("bar-call").textContent).toBe("Confirmed by Asha Rao · Priority P1");
    expect(screen.getByTestId("taken-by").textContent).toBe("Taken by: nobody");
    expect(document.querySelector("main")?.textContent).not.toMatch(/Owner:/);
  });

  it("a person without review access reads the state sentence only", async () => {
    server.use(...shellHandlers(sessionWith(["view"])));
    serve(p1Detail());
    renderApp(`/incidents/${P1_ID}`);
    const b = await bar();
    expect(b.getByText("A person with review access decides this.")).toBeTruthy();
    expect(b.queryByRole("button", { name: "Confirm incident…" })).toBeNull();
  });

  it("a part a person may not use says why, in the server's words", async () => {
    const d = p1Detail();
    serve({ ...d, decision: { ...(d.decision as NonNullable<CaseDetail["decision"]>), confirm: { enabled: false, why_not: "Only a person with review access confirms." } } });
    renderApp(`/incidents/${P1_ID}`);
    const b = await bar();
    expect(b.getByRole("button", { name: "Confirm incident…" }).getAttribute("aria-disabled")).toBe("true");
    expect(b.getByText("Only a person with review access confirms.")).toBeTruthy();
  });
});

describe("the confirm dialog (§5.4, F1, F15)", () => {
  it("says what happens in the server's words, lists what is still open, and sends the version seen", async () => {
    const user = userEvent.setup();
    server.use(http.post(`${CASE_URL}/confirm`, () => HttpResponse.json({ case: caseRow({ id: P1_ID, number: 31, state: "open", version: 5 }), result: "done", request_id: null })));
    serve(p1Detail());
    renderApp(`/incidents/${P1_ID}`);
    await user.click((await bar()).getByRole("button", { name: "Confirm incident…" }));
    const dialog = within(await screen.findByRole("alertdialog"));
    expect(dialog.getByRole("heading", { name: "Confirm incident #31?" })).toBeTruthy();
    expect(dialog.getByTestId("what-happens").textContent).toContain("waits for someone who may open it in Kibana; nothing is sent there by this");
    expect(dialog.getByTestId("what-happens").textContent).not.toMatch(/is posted to Kibana|goes to Kibana now/);
    const open = dialog.getByTestId("still-open");
    expect(open.textContent).toContain("still fits: A remote-management tool the lab installed");
    expect(open.textContent).toContain("Not known: Who used the devices");
    await user.type(dialog.getByRole("textbox", { name: /Note/ }), "the lab admin knows no such tool");
    await user.click(dialog.getByRole("button", { name: "Confirm anyway" }));
    await screen.findByText("Incident #31 is confirmed.", { selector: "p" });
    const [post] = sent("POST", `/api/v1/cases/${P1_ID}/confirm`);
    expect(JSON.parse(post?.body ?? "")).toEqual({ expected_version: 4, note: "the lab admin knows no such tool" });
  });

  it("reads Confirm incident when nothing argues against it", async () => {
    const user = userEvent.setup();
    serve(p1Detail({}, {}, p1Engine({ alternatives: [], checks: [{ state: "checked", text: "on 1 list" }] })));
    renderApp(`/incidents/${P1_ID}`);
    await user.click((await bar()).getByRole("button", { name: "Confirm incident…" }));
    const dialog = within(await screen.findByRole("alertdialog"));
    expect(dialog.queryByTestId("still-open")).toBeNull();
    expect(dialog.getByRole("button", { name: "Confirm incident" })).toBeTruthy();
  });

  it("I-10: a 409 closes the dialog, reads the case again and says it changed while you were deciding", async () => {
    const user = userEvent.setup();
    server.use(http.post(`${CASE_URL}/confirm`, () => HttpResponse.json({ detail: "The case changed since you read it." }, { status: 409 })));
    serve(p1Detail());
    renderApp(`/incidents/${P1_ID}`);
    await user.click((await bar()).getByRole("button", { name: "Confirm incident…" }));
    await user.click(within(await screen.findByRole("alertdialog")).getByRole("button", { name: "Confirm anyway" }));
    await waitFor(() => expect(screen.queryByRole("alertdialog")).toBeNull());
    expect((await screen.findByTestId("conflict-strip")).textContent).toContain("It changed while you were deciding");
  });

  it("takes it as well when asked, and says so apart when taking fails", async () => {
    const user = userEvent.setup();
    server.use(...shellHandlers(sessionWith(["view", "review", "manage_cases"])));
    server.use(
      http.post(`${CASE_URL}/confirm`, () => HttpResponse.json({ case: caseRow({ id: P1_ID, number: 31, state: "open", version: 5 }), result: "done", request_id: null })),
      http.post(`${CASE_URL}/take`, () => HttpResponse.json({ detail: "Someone took it first." }, { status: 409 })),
    );
    serve(p1Detail());
    renderApp(`/incidents/${P1_ID}`);
    await user.click((await bar()).getByRole("button", { name: "Confirm incident…" }));
    const dialog = within(await screen.findByRole("alertdialog"));
    await user.click(dialog.getByRole("checkbox", { name: "Take it myself" }));
    await user.click(dialog.getByRole("button", { name: "Confirm anyway" }));
    await screen.findByText(/Incident #31 is confirmed. Taking it failed: Someone took it first./, { selector: "p" });
    expect(JSON.parse(sent("POST", `/api/v1/cases/${P1_ID}/take`)[0]?.body ?? "")).toEqual({ expected_version: 5 });
  });
});

describe("Not an incident (§5.5)", () => {
  it("T-10: d, e, Enter sends exactly one dismiss for benign_expected, the consequence shown first", async () => {
    const user = userEvent.setup();
    server.use(http.post(`${CASE_URL}/dismiss`, () => HttpResponse.json({ case: caseRow({ id: P1_ID, number: 31, state: "closed", closure_reason: "benign_expected", version: 5 }), result: "done", request_id: null })));
    serve(p1Detail());
    renderApp(`/incidents/${P1_ID}`);
    await bar();
    await user.keyboard("d");
    const menu = await screen.findByRole("menu", { name: "Why is it not an incident?" });
    expect(within(menu).queryByText(/created in error/i)).toBeNull();
    for (const key of ["e", "s", "p", "w", "u"]) expect(within(menu).getByText(key, { selector: "kbd" })).toBeTruthy();
    await user.keyboard("e");
    const sheet = await screen.findByTestId("dismiss-sheet");
    expect(within(sheet).getByTestId("dismiss-consequence").textContent).toContain("ARGUS does not suggest the same activity on lab-pc-17 +4 again for two weeks unless something new appears.");
    expect(sent("POST", `/api/v1/cases/${P1_ID}/dismiss`)).toHaveLength(0);
    await user.keyboard("{Enter}");
    await screen.findByText(/Incident #31 closed: Expected activity\./, { selector: "p" });
    const posts = sent("POST", `/api/v1/cases/${P1_ID}/dismiss`);
    expect(posts).toHaveLength(1);
    expect(JSON.parse(posts[0]?.body ?? "")).toEqual({ expected_version: 4, reason: "benign_expected" });
  });

  it("T-9: on the exposure lane, Scan or attempt is aria-disabled and says something answered", async () => {
    const user = userEvent.setup();
    serve(p1Detail({}, {}, engineBlock("P2", 60, { lane: "exposure" })));
    renderApp(`/incidents/${P1_ID}`);
    await bar();
    await user.keyboard("d");
    const menu = await screen.findByRole("menu");
    const scan = within(menu).getAllByRole("menuitem").find((m) => m.getAttribute("data-reason") === "attempt_no_impact") as HTMLElement;
    expect(scan.getAttribute("aria-disabled")).toBe("true");
    expect(scan.textContent).toContain("Something answered: check first");
    expect(within(menu).getByRole("link", { name: "Ask ARGUS to check" })).toBeTruthy();
    await user.keyboard("s");
    expect(screen.queryByTestId("dismiss-sheet")).toBeNull();
  });

  it("A-4: the digits do nothing in the dismiss menu", async () => {
    const user = userEvent.setup();
    serve(p1Detail());
    renderApp(`/incidents/${P1_ID}`);
    await bar();
    await user.keyboard("d");
    await screen.findByRole("menu");
    await user.keyboard("2");
    expect(screen.queryByTestId("dismiss-sheet")).toBeNull();
    expect(sent("POST", "/api")).toHaveLength(0);
  });

  it("I-9, T-11: Undo reopens it; the toast stays while hovered", async () => {
    const user = userEvent.setup();
    server.use(...shellHandlers(sessionWith(["view", "review", "reopen"])));
    let state: "suspected" | "closed" = "suspected";
    server.use(
      http.post(`${CASE_URL}/dismiss`, () => {
        state = "closed";
        return HttpResponse.json({ case: caseRow({ id: P1_ID, number: 31, state: "closed", closure_reason: "rule_false_positive", version: 5 }), result: "done", request_id: null });
      }),
      http.post(`${CASE_URL}/reopen`, () => {
        state = "suspected";
        return HttpResponse.json({ case: caseRow({ id: P1_ID, number: 31, state: "suspected", version: 6 }), result: "done", request_id: null });
      }),
      http.get(CASE_URL, () => HttpResponse.json(state === "suspected" ? p1Detail() : p1Detail({ decision: null }, { state: "closed", closure_reason: "rule_false_positive", closed_at: "2026-11-06T13:00:00Z", version: 5 }))),
      http.get(`${CASE_URL}/report`, () => HttpResponse.json(reportOut({ case_id: P1_ID }))),
    );
    renderApp(`/incidents/${P1_ID}`);
    await user.click((await bar()).getByRole("button", { name: "Not an incident ▾" }));
    await user.click(within(await screen.findByRole("menu")).getByText("The rule was wrong"));
    await user.click(within(await screen.findByTestId("dismiss-sheet")).getByRole("button", { name: "Close it" }));
    const toast = await screen.findByTestId("undo-toast");
    expect(toast.textContent).toContain("Incident #31 closed: The rule was wrong.");
    fireEvent.mouseEnter(toast);
    await waitFor(() => expect(screen.getByTestId("decision-bar").getAttribute("data-state")).toBe("closed"));
    await user.click(within(toast).getByRole("button", { name: "Undo" }));
    const [reopen] = sent("POST", `/api/v1/cases/${P1_ID}/reopen`);
    expect(JSON.parse(reopen?.body ?? "")).toEqual({ expected_version: 5, reason: "Undone by Asha right after closing it" });
    await waitFor(() => expect(screen.getByTestId("decision-bar").getAttribute("data-state")).toBe("possible"));
  });

  it("without reopen, the toast says who can reopen it and offers no Undo", async () => {
    const user = userEvent.setup();
    server.use(http.post(`${CASE_URL}/dismiss`, () => HttpResponse.json({ case: caseRow({ id: P1_ID, number: 31, state: "closed", version: 5 }), result: "done", request_id: null })));
    serve(p1Detail());
    renderApp(`/incidents/${P1_ID}`);
    await user.click((await bar()).getByRole("button", { name: "Not an incident ▾" }));
    await user.click(within(await screen.findByRole("menu")).getByText("Expected activity"));
    await user.click(within(await screen.findByTestId("dismiss-sheet")).getByRole("button", { name: "Close it" }));
    const toast = await screen.findByTestId("undo-toast");
    expect(toast.textContent).toContain("a person with reopen access can reopen it");
    expect(within(toast).queryByRole("button", { name: "Undo" })).toBeNull();
  });
});

describe("the Overview (§7.3)", () => {
  it("I-5: keeps the order, and I-7: labels the AI's summary", async () => {
    serve(p1Detail({ decision: null }, { state: "open" }));
    renderApp(`/incidents/${P1_ID}`);
    await screen.findByTestId("summary");
    const order = [...document.querySelectorAll("[data-testid=overview] [data-region]")].map((r) => r.getAttribute("data-region"));
    const want = ["changed", "what-happened", "still-fits", "why", "checked", "alternatives", "next-steps", "sides"];
    expect(order.filter((r) => want.includes(r ?? ""))).toEqual(want);
    expect(screen.getByTestId("ai-label").textContent).toContain("Written by ARGUS's AI");
  });

  it("I-7: the code's summary carries no label", async () => {
    serve(p1Detail(), reportOut({ case_id: P1_ID }));
    renderApp(`/incidents/${P1_ID}`);
    await screen.findByTestId("summary");
    expect(screen.queryByTestId("ai-label")).toBeNull();
  });

  it("I-8: the still-fits line sits directly under What happened", async () => {
    serve(p1Detail());
    renderApp(`/incidents/${P1_ID}`);
    await screen.findByTestId("summary");
    const regions = [...document.querySelectorAll("[data-testid=overview] [data-region]")].map((r) => r.getAttribute("data-region"));
    expect(regions[regions.indexOf("what-happened") + 1]).toBe("still-fits");
    expect(screen.getByTestId("still-fits-line").textContent).toContain("1 other explanation still fits: A remote-management tool the lab installed");
  });

  it("I-6: the visible points add up to the shown priority, for the summing and the non-summing engine", async () => {
    for (const engine of [p1Engine(), p1Engine({ why: [{ op: "+", points: 44, text: "Long random subdomains" }, { op: "+", points: 30, text: "Many queries" }] })]) {
      serve(p1Detail({}, {}, engine));
      const view = renderApp(`/incidents/${P1_ID}`);
      const table = await screen.findByTestId("why-points");
      const sum = within(table).getAllByTestId("why-value").reduce((s, td) => s + Number((td.textContent ?? "").replace("−", "-")), 0);
      expect(sum).toBe(Number(within(table).getByTestId("why-total").textContent));
      expect(screen.getByTestId("priority-heading").textContent).toBe("Priority 82 of 100 · P1: look today, before you leave");
      view.unmount();
    }
  });

  it("I-14: every ? line in Checked says Not known", async () => {
    serve(p1Detail());
    renderApp(`/incidents/${P1_ID}`);
    await screen.findByTestId("check-list");
    const marks = screen.getAllByTestId("check-mark").filter((m) => m.textContent?.includes("?"));
    expect(marks.length).toBeGreaterThan(0);
    for (const m of marks) expect(m.textContent).toContain("Not known");
  });

  it("G-5: the outside address is on the Other side, never a Device", async () => {
    serve(p1Detail());
    renderApp(`/incidents/${P1_ID}`);
    const sides = await screen.findByTestId("sides");
    const actor = within(sides).getAllByTestId("entity-chip").filter((c) => c.getAttribute("data-role") === "actor");
    expect(actor[0]?.textContent).toBe("Outside address 203.0.113.40");
    for (const c of actor) expect(c.getAttribute("data-noun")).not.toBe("Device");
  });

  it("I-13, G-1: no UUID and no true positive in the page's text outside [⋯]", async () => {
    serve(p1Detail());
    renderApp(`/incidents/${P1_ID}`);
    await screen.findByTestId("summary");
    const text = document.querySelector("main")?.textContent ?? "";
    expect(text).not.toMatch(UUID);
    expect(text).not.toMatch(/true positive|\bTP\b|\bFP\b|\bBP\b|Needs decision/i);
  });

  it("an old case without an engine says ARGUS's call from the report, not prioritised yet, and the bar still works", async () => {
    serve(p1Detail({}, {}, null));
    renderApp(`/incidents/${P1_ID}`);
    await waitFor(() => expect(screen.getByTestId("not-scored").textContent).toBe("ARGUS's call: Real: act on it · not prioritised yet."));
    expect((await bar()).getByTestId("bar-call").textContent).toBe("ARGUS's call: Real: act on it · not prioritised yet");
    expect(document.querySelector("main")?.textContent).not.toMatch(/has not scored|not scored yet/);
    expect(screen.getAllByTestId("priority-badge")[0]?.textContent).toContain("—");
  });

  it("an old case without an engine and without a report call says it has none, never a percentage", async () => {
    const rep = reportOut({ case_id: P1_ID, case_state: "suspected" }, { verdict: { ...report().verdict, outcome: null, confidence: null } });
    serve(p1Detail({}, {}, null), rep);
    renderApp(`/incidents/${P1_ID}`);
    await waitFor(() => expect(screen.getByTestId("not-scored").textContent).toBe("ARGUS has not prioritised this incident yet."));
    expect((await bar()).getByTestId("bar-call").textContent).toBe("ARGUS: no call yet · not prioritised yet");
    expect((await bar()).getByTestId("bar-call").textContent).not.toMatch(/%/);
  });

  it("F15: without the engine, Confirm incident… lists the report's other explanations still open", async () => {
    const user = userEvent.setup();
    const hypotheses = [
      { name: "A real threat: malicious activity or a compromise (a true positive)", status: "kept" as const, by: "argus" as const, why: [] },
      { name: "Expected or harmless activity (benign)", status: "ruled_out" as const, by: "argus" as const, why: [] },
      { name: "Internet research or measurement scanning", status: "open" as const, by: "argus" as const, why: [{ by: "code" as const, cites: [], text: "ARGUS cannot rule out a researcher's scan from the alerts alone." }] },
    ];
    serve(p1Detail({}, {}, null), reportOut({ case_id: P1_ID, case_state: "suspected" }, { hypotheses }));
    renderApp(`/incidents/${P1_ID}`);
    await screen.findByTestId("not-scored");
    await waitFor(() => expect(screen.getByTestId("not-scored").textContent).toContain("ARGUS's call"));
    await user.click((await bar()).getByRole("button", { name: "Confirm incident…" }));
    const dialog = await screen.findByRole("alertdialog");
    expect(dialog.textContent).toContain("not tested: Internet research or measurement scanning");
    expect(dialog.textContent).not.toContain("A real threat");
    expect(dialog.textContent).not.toContain("Expected or harmless activity");
  });

  it("I-11: a confirmed incident's first next step is Report to the CISO, and Mark as sent posts the exact note", async () => {
    const user = userEvent.setup();
    server.use(http.post(`${CASE_URL}/notes`, () => HttpResponse.json({ id: 9, author: "Asha", body: "x", created_at: "2026-11-06T13:00:00Z" })));
    serve(p1Detail({ decision: null }, { state: "open" }), reportOut({ case_id: P1_ID, version: 4 }));
    renderApp(`/incidents/${P1_ID}`);
    const steps = await screen.findByTestId("next-steps");
    const firstStep = steps.querySelector("li") as HTMLElement;
    expect(firstStep.textContent).toContain("Report to the CISO");
    expect(firstStep.textContent).toContain("Who: you");
    await user.click(within(firstStep).getByRole("button", { name: "Draft it…" }));
    const draft = within(await screen.findByTestId("ciso-draft"));
    expect(draft.getByRole("button", { name: "Copy" })).toBeTruthy();
    expect(draft.getByText(/send them only to the CISO's office and ACME/)).toBeTruthy();
    await user.click(draft.getByRole("button", { name: "Mark as sent" }));
    await waitFor(() => expect(sent("POST", `/api/v1/cases/${P1_ID}/notes`)).toHaveLength(1));
    expect(JSON.parse(sent("POST", `/api/v1/cases/${P1_ID}/notes`)[0]?.body ?? "")).toEqual({ body: "Reported to the CISO with incident report v4." });
  });
});

describe("the page's address", () => {
  it("S-5: /cases/<id> lands on /incidents/<id>, an old anchor on its tab", async () => {
    serve(p1Detail());
    const { router } = renderApp(`/cases/${P1_ID}`);
    await screen.findByTestId("decision-bar");
    expect(router.state.location.pathname).toBe(`/incidents/${P1_ID}`);
    const second = renderApp(`/cases/${P1_ID}#notes`);
    await waitFor(() => expect(second.router.state.location.search).toEqual({ tab: "activity" }));
  });

  it("the CISO draft names the IR number and leaves accounts to the PDF without see_logs", () => {
    const d = p1Detail({ incident_id: "IR-2026-1106-02" });
    const draft = cisoDraft(d, reportOut({ case_id: P1_ID }), engineOf(p1Engine()), false);
    expect(draft.subject).toBe("ACME: Likely beaconing from 5 campus devices to 203.0.113.40 (VirusTotal: 7 engines) (IR-2026-1106-02)");
    expect(draft.body).toContain("Accounts: in the attached PDF");
    act(() => undefined);
  });

  it("with an analyst brief the CISO draft opens with what is happening and ends with numbered steps (D-332)", () => {
    const line = (text: string) => ({ text, cites: ["F1"] });
    const brief = {
      statement: [line("A laptop keeps sending its browser's cookies to 203.0.113.40.")],
      points: [line("It started on 31 Oct."), line("One account is behind most addresses.")],
      why: [line("The paths name cookies and history.")],
      impact: [line("Signed-in sessions may be taken over.")],
      actions: [
        { ...line("Block 203.0.113.40 at the proxy."), who: "network" as const, when: "now" as const },
        { ...line("Change the account's password from a clean device."), who: "accounts" as const, when: "today" as const },
      ],
      facts: { F1: "A fact." },
      facts_sha: "0".repeat(64),
      by: "anthropic/claude-opus-5-5",
      at: "2026-10-29T07:30:00Z",
      basis: "true_positive|ongoing|open",
      dropped: 0,
    };
    const account = (name: string, device: string) => ({ name, device, first_seen: "2026-10-28T00:00:00Z", last_seen: "2026-10-28T01:00:00Z", signins: 1, failed: 0, days: 1, browsers: [] });
    const device = (ip: string, names: string[]) => ({ device: ip, state: (names.length === 1 ? "likely" : "possible") as "likely" | "possible", sentence: { text: `${ip}: seen.`, cites: ["F1"], by: "code" as const }, accounts: names.map((n) => account(n, ip)), account_count: names.length, at_least: false });
    const users = { lead: "", devices_total: 3, signins: [], same: { text: "One account, u1, is the probable user on 3 of the 3 addresses with a sign-in.", cites: ["F1"], by: "code" as const }, devices: [device("10.0.0.1", ["u1"]), device("10.0.0.2", ["u1"]), device("10.0.0.3", ["u1", "u2"])] };
    const data = reportOut({ case_id: P1_ID }, { brief, users });
    const body = cisoDraft(p1Detail(), data, engineOf(p1Engine()), true).body;
    expect(body.startsWith("A laptop keeps sending its browser's cookies to 203.0.113.40.\n\nSummary\n- It started on 31 Oct.")).toBe(true);
    expect(body).toContain("- u1: the only account seen on 2 addresses; one of several on 1 address");
    expect(body).toContain("- u2: one of several on 1 address");
    expect(body).toContain("One account, u1, is the probable user on 3 of the 3 addresses with a sign-in.");
    expect(body).toContain("Why it is judged real\n- The paths name cookies and history.");
    expect(body).toContain("Risk\n- Signed-in sessions may be taken over.");
    expect(body).toContain("Requested actions\n1. Block 203.0.113.40 at the proxy. (Network team, immediately)\n2. Change the account's password from a clean device. (Account holders, today)");
    // without log access the server hides the brief and the accounts: the draft says neither
    const hidden = cisoDraft(p1Detail(), reportOut({ case_id: P1_ID }, { users }), engineOf(p1Engine()), false).body;
    expect(hidden).not.toContain("u1");
    expect(hidden).toContain("Accounts: in the attached PDF");
    act(() => undefined);
  });
});

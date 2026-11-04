// Q-B4: the pages the classic server-rendered app had and the app did not: By rule, By host or IP,
// Patterns, Health, Glossary, Metrics, Tuning, Gold set. Each one says what the classic page said,
// and shows a hostile value as text only.
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse, type JsonBodyType } from "msw";
import { describe, expect, it } from "vitest";
import { ID, ID2, BASE, detail, mockApi, must, renderApp, sent, server, sessionWith, shellHandlers } from "./helpers";

mockApi();
const HOSTILE = '<img src=x onerror="window.__pwned=1"> ‮';
const get = (path: string, body: JsonBodyType) => http.get(`${BASE}/api/v1${path}`, () => HttpResponse.json(body));

describe("By rule", () => {
  const rule = (n: number, more: Record<string, string | number | null> = {}) => ({
    rule_id: `rule-${n}`, rule_name: `Rule ${n}`, investigations: 3, open: 2, alerts: 10, last_event_at: "2026-10-09T06:30:00Z",
    type: "query", revision: 1, interval: "5m", max_signals: 100, execution_status: null, truncated: 0, ...more,
  });

  it("lists each rule with its counts, the runs at the limit and a link to its unreviewed investigations", async () => {
    server.use(get("/rules", [rule(1), rule(2, { truncated: 4, max_signals: 100, rule_name: null, type: null, interval: null })]));
    renderApp("/rules");
    const table = await screen.findByRole("table", { name: "Rules" });
    const rows = within(table).getAllByRole("row").slice(1).map((r) => [...r.querySelectorAll("td")].map((c) => c.textContent));
    expect(rows).toEqual([
      ["Rule 1", "2", "3", "10", "9 Oct 2026, 12:00 PM IST", "0", "query, every 5m"],
      ["rule-2", "2", "3", "10", "9 Oct 2026, 12:00 PM IST", "4", "unknown"],
    ]);
    expect(within(table).getByRole("link", { name: "Rule 1" }).getAttribute("href")).toBe("/app/inbox?view=open&rule=rule-1");
    expect(within(table).getByTitle(/maximum of 100 alerts/).textContent).toBe("4");
    expect(screen.getByText(/Whether a rule is still running needs Kibana/)).toBeTruthy();
    expect(screen.getByRole("heading", { level: 1 }).textContent).toBe("By rule");
    await waitFor(() => expect(document.title).toBe("By rule · ARGUS"));
  });

  it("says when there is nothing and when it cannot be read", async () => {
    server.use(get("/rules", []));
    const first = renderApp("/rules");
    expect(await screen.findByText("No investigations yet.")).toBeTruthy();
    first.unmount();
    server.use(http.get(`${BASE}/api/v1/rules`, () => HttpResponse.text("down", { status: 503 })));
    renderApp("/rules");
    expect(await screen.findByText(/The rules could not be shown\./)).toBeTruthy();
  });

  it("shows a hostile rule name as text", async () => {
    server.use(get("/rules", [rule(1, { rule_name: HOSTILE })]));
    const { container } = renderApp("/rules");
    await screen.findByRole("table", { name: "Rules" });
    expect(container.querySelector("img")).toBeNull();
  });
});

describe("By host or IP", () => {
  it("lists each entity with its kind and a common mark, linking to the Inbox filtered to it", async () => {
    server.use(get("/entities", [
      { kind: "ip", value: "10.0.0.1", investigations: 7, supernode: false },
      { kind: "domain", value: "proxy.example", investigations: 900, supernode: true },
    ]));
    renderApp("/hosts");
    const table = await screen.findByRole("table", { name: "Hosts and addresses" });
    const rows = within(table).getAllByRole("row").slice(1).map((r) => [...r.querySelectorAll("td")].map((c) => c.textContent?.replace(/\s+/g, " ").trim()));
    expect(rows).toEqual([["10.0.0.1 IP address", "7"], ["proxy.example Domain common", "900"]]);
    expect(within(table).getByRole("link", { name: "10.0.0.1" }).getAttribute("href")).toBe("/app/inbox?view=all&kind=ip&value=10.0.0.1");
    expect(screen.getByText(/more than 200 investigations/)).toBeTruthy();
  });

  it("does not make a link of a kind it does not know", async () => {
    server.use(get("/entities", [{ kind: "mac", value: "aa:bb", investigations: 1, supernode: false }]));
    renderApp("/hosts");
    await screen.findByText("aa:bb");
    expect(screen.queryByRole("link", { name: "aa:bb" })).toBeNull();
  });
});

describe("Patterns", () => {
  const GROUP = {
    rule_id: "rule-1", rule_name: "Rule 1", steps: ["answered", "deferred", "manual"], listed: true, alerts: 5,
    common: [{ field: "source.ip", values: ["10.0.0.1", "10.0.0.2"] }],
    members: [ID, ID2, "99999999-aaaa-4bbb-8ccc-dddddddddddd"].map((id, n) => ({ investigation_id: id, version: n + 1, latest_review: n === 1 ? 7 : null })),
  };

  // the page: the groups and what they were made from (a sample of the newest unreviewed, AR4 review)
  const page = (groups: unknown[], more: Record<string, unknown> = {}) => ({ groups, read: 40, limit: 2000, sampled: false, ...more });

  it("says what the group shares and links three examples", async () => {
    server.use(get("/patterns", page([GROUP])));
    renderApp("/patterns");
    const card = await screen.findByRole("region", { name: "Pattern: Rule 1" });
    expect(card.textContent).toContain("Rule 1: 3 investigations, 5 alerts");
    for (const word of ["Answered", "Not checked yet", "For you", "Threat-list hit"]) expect(within(card).getByText(word)).toBeTruthy();
    expect(card.textContent).toContain("In common: source.ip 10.0.0.1, 10.0.0.2");
    expect(within(card).getAllByRole("link").map((a) => a.getAttribute("href"))).toEqual([`/app/investigations/${ID}`, `/app/investigations/${ID2}`, "/app/investigations/99999999-aaaa-4bbb-8ccc-dddddddddddd"]);
  });

  it("says it is a sample when the groups were made from the newest only, and not otherwise", async () => {
    server.use(get("/patterns", page([GROUP], { read: 2000, sampled: true })));
    renderApp("/patterns");
    const note = await screen.findByTestId("patterns-sample");
    expect(note.textContent).toContain("This is a sample.");
    expect(note.textContent).toContain("2,000 newest investigations");
    expect(note.textContent).toContain("older ones are in no group here");
  });

  it("has no sample note when it looked at every unreviewed investigation", async () => {
    server.use(get("/patterns", page([GROUP])));
    renderApp("/patterns");
    await screen.findByRole("region", { name: "Pattern: Rule 1" });
    expect(screen.queryByTestId("patterns-sample")).toBeNull();
  });

  it("says when every open investigation stands alone", async () => {
    server.use(get("/patterns", page([])));
    renderApp("/patterns");
    expect(await screen.findByText(/No patterns: every open investigation stands on its own\./)).toBeTruthy();
  });

  it("needs an outcome first, shows the exact request with each version seen, and sends exactly that", async () => {
    const user = userEvent.setup();
    server.use(get("/patterns", page([GROUP])), http.post(`${BASE}/api/v1/patterns/review`, () => HttpResponse.json({ reviewed: 2, changed: 1 })));
    renderApp("/patterns");
    const button = await screen.findByRole("button", { name: "Mark these 3 reviewed" });
    expect((button as HTMLButtonElement).disabled).toBe(true);
    await user.selectOptions(screen.getByLabelText("Outcome"), "benign_expected");
    await user.click(button);
    const dialog = await screen.findByRole("alertdialog");
    const shown = within(dialog).getByTestId("payload").textContent ?? "";
    expect(JSON.parse(shown)).toEqual({
      outcome: "benign_expected",
      items: [
        { investigation_id: ID, version: 1, latest_review: null },
        { investigation_id: ID2, version: 2, latest_review: 7 },
        { investigation_id: "99999999-aaaa-4bbb-8ccc-dddddddddddd", version: 3, latest_review: null },
      ],
    });
    expect(dialog.textContent).toContain("POST/api/v1/patterns/review");
    await user.click(within(dialog).getByRole("button", { name: "Mark 3 reviewed" }));
    await screen.findByText("2 reviewed. 1 changed since you looked and were left as they are.", { selector: "p" });
    expect(sent("POST", "/api")[0]?.body).toBe(shown);
    await waitFor(() => expect(sent("GET", "/api/v1/patterns")).toHaveLength(2)); // read again
  });

  it("does not carry a reviewed group's outcome to the next group of the same rule (review B4 finding 7)", async () => {
    const user = userEvent.setup();
    const second = { ...GROUP, members: [{ investigation_id: "aaaaaaaa-1111-4222-8333-444444444444", version: 1, latest_review: null }], alerts: 1 };
    let reviewed = false;
    server.use(
      http.get(`${BASE}/api/v1/patterns`, () => HttpResponse.json(page(reviewed ? [second] : [GROUP, second]))),
      http.post(`${BASE}/api/v1/patterns/review`, () => {
        reviewed = true;
        return HttpResponse.json({ reviewed: 3, changed: 0 });
      }),
    );
    renderApp("/patterns");
    const first = (await screen.findAllByRole("region", { name: "Pattern: Rule 1" }))[0];
    await user.selectOptions(within(must(first)).getByLabelText("Outcome"), "benign_expected");
    await user.click(within(must(first)).getByRole("button", { name: "Mark these 3 reviewed" }));
    await user.click(within(await screen.findByRole("alertdialog")).getByRole("button", { name: "Mark 3 reviewed" }));
    await waitFor(() => expect(screen.getAllByRole("region", { name: "Pattern: Rule 1" })).toHaveLength(1));
    expect((screen.getByLabelText("Outcome") as HTMLSelectElement).value).toBe("");
    expect((screen.getByRole("button", { name: "Mark these 1 reviewed" }) as HTMLButtonElement).disabled).toBe(true);
  });

  it("names at most 200 investigations in a request and says so", async () => {
    const many = Array.from({ length: 250 }, (_, n) => ({ investigation_id: `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`, version: 1, latest_review: null }));
    const user = userEvent.setup();
    server.use(get("/patterns", page([{ ...GROUP, members: many }])));
    renderApp("/patterns");
    await user.selectOptions(await screen.findByLabelText("Outcome"), "true_positive");
    await user.click(screen.getByRole("button", { name: "Mark the first 200 of these 250 reviewed" }));
    const shown = JSON.parse(within(await screen.findByRole("alertdialog")).getByTestId("payload").textContent ?? "{}") as { items: unknown[] };
    expect(shown.items).toHaveLength(200);
  });

  it("is not offered to an account that may only view, which is told why", async () => {
    server.use(...shellHandlers(sessionWith(["view"])), get("/patterns", page([GROUP])));
    renderApp("/patterns");
    await screen.findByRole("region", { name: "Pattern: Rule 1" });
    expect(screen.queryByRole("button", { name: /reviewed$/ })).toBeNull();
    expect(screen.getByText(/Your account may view only: deciding a group needs the “review” capability/)).toBeTruthy();
  });

  it("shows hostile values as text", async () => {
    server.use(get("/patterns", page([{ ...GROUP, rule_name: HOSTILE, common: [{ field: HOSTILE, values: [HOSTILE] }] }])));
    const { container } = renderApp("/patterns");
    await screen.findByRole("region", { name: /Pattern:/ });
    expect(container.querySelector("img")).toBeNull();
  });
});

describe("Health", () => {
  const HEALTH = {
    siem_state: "caution", siem_reasons: ["load"], siem_probed_at: "2026-10-26T00:00:00Z", live_cursor: "2026-10-25T23:50:00Z", backfill_cursor: "2026-10-20T00:00:00Z",
    open_gaps: [{ kind: "cursor_stall", subject: "live", start_at: "2026-10-25T20:00:00Z", detail: HOSTILE }],
    last_reconciliation: { finished_at: "2026-10-25T22:00:00Z", hours: 24, hours_mismatched: 2, recovered: 3, outcome: "ok" },
    alerts: 12000, quarantined: 4, investigations: 300, jobs_waiting: 5, jobs_deferred: 2, jobs_failed: 1, dossiers: 280, checkpoint_threads: 3, checkpoint_bytes: 20480,
    kibana_sync: { state: "partial", last_cycle_at: "2026-10-25T23:40:00Z", last_outcome: "partial", last_reason: "budget", last_complete_at: "2026-10-25T23:20:00Z" },
  };

  it("says what is collected, stored and waiting, the last check against the SIEM and every open gap", async () => {
    server.use(get("/health", HEALTH));
    const { container } = renderApp("/health");
    const stored = await screen.findByText(/12,000 alerts \(4 could not be read\)/);
    expect(stored.textContent).toBe("12,000 alerts (4 could not be read), 300 investigations, 5 waiting for work");
    expect(container.textContent).toContain("caution: ARGUS reads less (load), checked");
    expect(container.textContent).toContain("280 dossiers written, 2 waiting for the SIEM to be available, 1 could not be completed; 3 runs in progress (20 KiB)");
    expect(container.textContent).toContain("24 hours, 2 differed, 3 recovered (ok)");
    const gap = must(within(screen.getByRole("heading", { name: "Coverage gaps" }).parentElement as HTMLElement).getByRole("listitem"));
    expect(gap.textContent).toContain("cursor stall since");
    expect(gap.textContent).toContain("alerts from this time may be missing until it closes");
    expect(container.querySelector("img")).toBeNull();
  });

  it("shows the Kibana read-back from its newest cycle, on the page and in the status bar", async () => {
    server.use(get("/health", HEALTH));
    const { container } = renderApp("/health");
    await screen.findByText(/12,000 alerts/);
    expect(container.textContent).toContain("partly read, last cycle");
    expect(container.textContent).toContain("(partial: budget)");
    expect(container.textContent).toContain("last complete");
    const bar = await screen.findByRole("link", { name: /Kibana sync/ });
    expect(bar.textContent).toContain("partly read");
    expect(bar.getAttribute("title")).toContain("last complete");
  });

  it("says the read-back has not run yet, never that it works", async () => {
    server.use(get("/health", { ...HEALTH, kibana_sync: { state: "none", last_cycle_at: null, last_outcome: null, last_reason: null, last_complete_at: null } }));
    const { container } = renderApp("/health");
    await screen.findByText(/12,000 alerts/);
    expect(container.textContent).toContain("not running yet no cycle recorded");
    const bar = await screen.findByRole("link", { name: /Kibana sync/ });
    expect(bar.textContent).toContain("not running yet");
    expect(bar.textContent).not.toContain("in sync");
  });

  it("calls a read-back in sync only when its newest cycle says so", async () => {
    server.use(get("/health", { ...HEALTH, kibana_sync: { state: "ok", last_cycle_at: "2026-10-25T23:40:00Z", last_outcome: "complete", last_reason: null, last_complete_at: "2026-10-25T23:40:00Z" } }));
    renderApp("/health");
    const bar = await screen.findByRole("link", { name: /Kibana sync/ });
    await waitFor(() => expect(bar.textContent).toContain("in sync"));
  });

  it("says none are open and that nothing was collected yet", async () => {
    server.use(get("/health", { ...HEALTH, open_gaps: [], last_reconciliation: null, live_cursor: null, backfill_cursor: null, siem_probed_at: null, siem_reasons: [], siem_state: "normal" }));
    renderApp("/health");
    expect(await screen.findByText("None open.")).toBeTruthy();
    expect(screen.getAllByText("not yet")).toHaveLength(2);
  });
});

describe("Glossary", () => {
  it("explains the pages and, from the server, the facts and signals", async () => {
    server.use(get("/glossary", [{ name: "supernode", label: "Common address", how: "In so many investigations that it links nothing." }]));
    renderApp("/glossary");
    expect(await screen.findByText("Common address")).toBeTruthy();
    expect(screen.getByText("In so many investigations that it links nothing.")).toBeTruthy();
    for (const heading of ["The pages", "ARGUS's assessment of an investigation", "The full report", "What ARGUS checked", "Facts and signals"]) {
      expect(screen.getByRole("heading", { name: heading })).toBeTruthy();
    }
    expect(screen.getAllByText("Not checked yet").length).toBeGreaterThan(0);
    expect(within(screen.getByRole("main")).getByRole("link", { name: "Patterns" }).getAttribute("href")).toBe("/app/patterns");
  });
});

describe("Metrics", () => {
  const METRICS = {
    validator_blocks: 2, fallbacks: 5, floor_hits: 3, month_cost_usd: 1.23456, stopped: false,
    calls: [{ provider: "groq", attempts: 10, ok: 8, cost_usd: 0 }],
    backlog: [{ assessor: "agent@1", waiting: 4, oldest_wait_s: 600 }],
    outcomes: [{ assessor: "engine@1", label: "benign_expected", count: 7 }, { assessor: "engine@1", label: "no_decision", count: 2 }],
    quota: [{ bucket: "groq requests", usage: "12 of 100" }],
  };

  it("says how the assessments and the AI connection are doing", async () => {
    server.use(get("/metrics", METRICS));
    const { container } = renderApp("/metrics");
    await screen.findByRole("table", { name: "Assessments by assessor" });
    expect(container.textContent).toContain("Benign: expected activity 7, no decision 2");
    expect(container.textContent).toContain("Benign answers stopped by the safety floor: 3.");
    expect(container.textContent).toContain("agent@1: 4, the oldest for 10 minutes");
    expect(container.textContent).toContain("Calls allowed. This month: $1.2346.");
    expect(container.textContent).toContain("Requests the leak validator refused (7 days): 2. Answers that came from a fallback provider (24 h): 5.");
    expect(container.textContent).toContain("groq requests: 12 of 100");
  });

  it("says plainly when the kill switch stopped the AI and when nothing happened", async () => {
    server.use(get("/metrics", { ...METRICS, stopped: true, outcomes: [], backlog: [], calls: [], quota: [] }));
    renderApp("/metrics");
    expect(await screen.findByText("Stopped by the kill switch")).toBeTruthy();
    expect(screen.getByText("None yet.")).toBeTruthy();
    expect(screen.getByText("Nothing waiting.")).toBeTruthy();
  });
});

describe("Rule tuning", () => {
  const REPORT = {
    rule: HOSTILE, week_end: "2026-10-25T00:00:00Z", alerts: 120, investigations: 40, runs: 50, runs_at_limit: 6, max_signals: 100, labels: { benign_expected: 3, true_positive: 1 },
    suggestions: [{ kind: "exception", path: "source.ip", value: "10.0.0.9", change: "Add an exception for 10.0.0.9", why: "Three benign verdicts", risk: "Hides a real hit", evidence: ["3 benign, 0 true positive"] }],
    dropped: ["a suggestion without evidence"], model: "m-1", cost_usd: 0, created_at: "2026-10-25T01:00:00Z",
  };

  it("shows each rule's week, its suggestions with why, risk and evidence, and what was not kept", async () => {
    server.use(get("/tuning", [REPORT, { ...REPORT, rule: "Quiet rule", suggestions: [], dropped: [] }]));
    const { container } = renderApp("/tuning");
    const card = (await screen.findAllByRole("region", { name: /Tuning:/ }))[0] as HTMLElement;
    expect(card.textContent).toContain("120 alerts, 40 investigations; 6 of 50 runs hit the alert limit (100). Verdicts: Benign: expected activity 3, True positive 1.");
    expect(card.textContent).toContain("Exception: source.ip = 10.0.0.9 — Add an exception for 10.0.0.9");
    expect(card.textContent).toContain("Why: Three benign verdicts Risk: Hides a real hit");
    expect(within(card).getByText("Evidence")).toBeTruthy();
    expect(within(card).getByText("1 not kept")).toBeTruthy();
    expect(screen.getByText("No suggestion this week.")).toBeTruthy();
    expect(container.querySelector("img")).toBeNull();
  });

  it("says when there is no report yet", async () => {
    server.use(get("/tuning", []));
    renderApp("/tuning");
    expect(await screen.findByText(/No report yet/)).toBeTruthy();
  });
});

describe("Gold set", () => {
  it("shows the progress and each item with the person's answer, linking to the investigation", async () => {
    server.use(get("/gold", {
      progress: { items: 3, answered: 1, by_split: { dev: 1, test: 0 } },
      items: [
        { investigation_id: ID, rule_name: "Rule 1", split: "dev", why: ["a kind"], outcome: null, answered_by: null, answered_at: null },
        { investigation_id: ID2, rule_name: "Rule 2", split: "test", why: [], outcome: "benign_policy", answered_by: "Asha", answered_at: "2026-10-25T10:00:00Z" },
      ],
    }));
    const { container } = renderApp("/gold");
    const table = await screen.findByRole("table", { name: "Gold set" });
    expect(container.textContent).toContain("1 of 3 answered · tuning part 1 · test part 0");
    const rows = within(table).getAllByRole("row").slice(1).map((r) => [...r.querySelectorAll("td")].map((c) => c.textContent));
    expect(rows).toEqual([["Rule 1", "not yet", "—", "tuning"], ["Rule 2", "Benign: allowed by policy", "25 Oct 2026, 3:30 PM IST", "test"]]);
    expect(within(table).getByRole("link", { name: "Rule 1" }).getAttribute("href")).toBe(`/app/investigations/${ID}`);
  });

  it("says when no gold set is stored", async () => {
    server.use(get("/gold", { progress: { items: 0, answered: 0, by_split: {} }, items: [] }));
    renderApp("/gold");
    expect(await screen.findByText(/No gold set is stored yet/)).toBeTruthy();
  });
});

describe("the menu", () => {
  it("opens each of these pages inside the app, and the two server pages as such", async () => {
    server.use(get("/rules", []));
    renderApp("/rules");
    const nav = await screen.findByRole("navigation", { name: "Main" });
    const hrefs = Object.fromEntries(within(nav).getAllByRole("link").map((a) => [a.textContent?.replace(/\s+/g, " ").trim(), a.getAttribute("href")]));
    expect(hrefs["By rule"]).toBe("/app/rules");
    expect(hrefs["By host or IP"]).toBe("/app/hosts");
    expect(hrefs["Patterns"]).toBe("/app/patterns");
    expect(hrefs["Tuning"]).toBe("/app/tuning");
    expect(hrefs["Metrics"]).toBe("/app/metrics");
    expect(hrefs["Gold set"]).toBe("/app/gold");
    expect(hrefs["Health"]).toBe("/app/health");
    expect(hrefs["Glossary"]).toBe("/app/glossary");
    expect(within(nav).getByRole("link", { name: /^Your access/ }).getAttribute("href")).toBe("/access");
    expect(hrefs["Classic pages (read-only)"]).toBe("/classic");
    expect(within(nav).queryByText("Classic Inbox")).toBeNull();
  });

  it("makes the status bar's links links inside the app", async () => {
    server.use(get("/rules", []));
    renderApp("/rules");
    const bar = await screen.findByRole("link", { name: /AI cost/ });
    expect(bar.getAttribute("href")).toBe("/app/metrics");
    // the classic cost bar's words: the month against the cap, then today against the daily cap
    expect(bar.textContent).toContain("$0.00 of $10.00 this month · today $0.00 of $0.30 (0 calls)");
    expect((await screen.findByRole("link", { name: /SIEM/ })).getAttribute("href")).toBe("/app/health");
  });
});

describe("the coverage banner", () => {
  it("says on an investigation that alerts may be missing and why (test_r15's banner)", async () => {
    server.use(
      http.get(`${BASE}/api/v1/investigations/${ID}`, () =>
        HttpResponse.json(detail({ coverage: [{ kind: "rule_limit", start_at: "2026-10-09T05:00:00Z", end_at: null, text: "the rule hit its alert limit", runs: [] }] })),
      ),
      http.get(`${BASE}/api/v1/investigations/${ID}/reports`, () => HttpResponse.json({ items: [], logs_hidden: false })),
    );
    renderApp(`/investigations/${ID}`);
    const note = await screen.findByRole("note");
    expect(note.textContent).toContain("Alerts may be missing");
    expect(note.textContent).toContain("the rule hit its alert limit");
  });
});

// What the page tests share: the API's answers as fixtures, a mock server with the shell's own
// reads answered, and the app rendered at an address with its router, queries and messages.
import { QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory, RouterProvider } from "@tanstack/react-router";
import { render } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { afterAll, afterEach, beforeAll, beforeEach, vi } from "vitest";
import type { CaseReportOut, DashboardOut, InvestigationChecksOut, InvestigationDetail, InvestigationOut, Report, SessionOut, StanceOut } from "../src/client/types.gen";
import { client, configure, setCsrf, setLeave } from "../src/lib/api";
import { AnnounceProvider } from "../src/lib/announce";
import { resetBuildState } from "../src/lib/build";
import { makeQueryClient } from "../src/lib/session";
import { createAppRouter } from "../src/router";
import { EXAMPLE_SITE } from "./exampleSite";
import { noTeamOut } from "./teamFixtures";

export const BASE = "http://localhost:3000";


/** A value that must be there (what a test looks at), or a failure that says it was not. */
export function must<T>(value: T | null | undefined, what = "the value"): T {
  if (value === null || value === undefined) throw new Error(`${what} was not there`);
  return value;
}
export const ID = "54c802b6-fb1a-5614-a6e4-f76c773213d2";
export const ID2 = "11111111-2222-4333-8444-555555555555";
export const ID3 = "99999999-aaaa-4bbb-8ccc-dddddddddddd";

export const SESSION: SessionOut = {
  user: { id: 1, username: "asha", display_name: "Asha" },
  mode: "local",
  break_glass: false,
  unverified: null,
  capabilities: ["view", "see_logs", "review", "answer_gold"].map((name) => ({ name, label: name })) as SessionOut["capabilities"],
  csrf_token: "token-1",
  expires_at: "2026-10-23T20:00:00Z",
  idle_expires_at: "2026-10-23T12:30:00Z",
  idle_timeout_s: 1800,
  stepped_up_at: null,
  step_up_valid_until: null,
  since: "2026-10-20T08:00:00Z",
  site: EXAMPLE_SITE,
};

export function sessionWith(capabilities: string[], more: Partial<SessionOut> = {}): SessionOut {
  return { ...SESSION, capabilities: capabilities.map((name) => ({ name, label: name })) as SessionOut["capabilities"], ...more };
}

export function investigation(id = ID, more: Partial<InvestigationOut> = {}): InvestigationOut {
  return {
    id,
    rule_id: "rule-0",
    rule_name: "Proxy: tunnel to a remote-admin port",
    key_fields: [{ field: "source.ip", value: "10.0.0.1" }],
    bucket_start: "2026-10-09T00:00:00+05:30",
    alert_count: 2,
    duplicate_count: 0,
    first_event_at: "2026-10-09T04:36:00Z",
    last_event_at: "2026-10-09T12:00:00Z",
    severity: "high",
    risk_score: 47,
    version: 3,
    created_at: "2026-10-21T08:00:00Z",
    continues_id: null,
    human_state: "unreviewed",
    latest_review: null,
    new_since_review: 0,
    last_outcome: null,
    last_reviewed_at: null,
    last_reviewer: null,
    reasons: ["The rule rates it high."],
    ai: null,
    known: null,
    ...more,
  };
}

/** ARGUS has nothing to say about an investigation. */
export const NO_STANCE: StanceOut = {
  kind: "none",
  outcome: null,
  confidence: null,
  source: null,
  why: null,
  assessment_id: null,
  from_investigation_id: null,
  acceptable: false,
  pattern_investigations: null,
  pattern_alerts: null,
};

export function stanceOf(more: Partial<StanceOut> = {}): StanceOut {
  return { ...NO_STANCE, ...more };
}

export function detail(more: Partial<InvestigationDetail> = {}, inv: Partial<InvestigationOut> = {}): InvestigationDetail {
  return {
    investigation: investigation(ID, inv),
    coverage: [],
    dossier: null,
    assessments: [],
    acceptable_assessment_id: null,
    stance: NO_STANCE,
    ask_available: false,
    gold: null,
    reviews: [],
    alert_fields: [],
    signins: null,
    ...more,
  };
}

export const REPORT: Report = {
  format: "report@2",
  investigation_id: ID,
  version: 3,
  pack: "generic@12",
  dossier_hash: "a".repeat(64),
  assessment_id: 7,
  recomputed: true,
  note: null,
  summary: { text: "It beacons every 300 s.", cites: [{ quote: "every 300 s", eids: ["E3"] }], checked: true, note: "Every quote was found." },
  verdict: { status: "proposed", outcome: "true_positive", assessor: "agent@1", source: "the AI investigator", decided_by: "agent@1#m", model_confidence: 0.75, why: ["It beacons."], at: "2026-10-09T13:00:00Z" },
  strength: { grade: "moderate", floor_known: 2, floor_total: 3, checks_complete: 3, checks_total: 4, steps_answered: 1, steps_total: 2, alerts_read: 2, alerts_total: 2, reasons: ["2 of 3 deciding facts known"] },
  found: {
    checks: 3,
    server_ms: 2100,
    items: [
      { kind: "new", sentence: "Host H1 reached the C2 every 300 s, 59 times.", eids: ["E3"], from_logs: true, values: [{ label: "destination", text: "203.0.113.9", count: 59 }], note: "E3 · proxy.pair@1 · complete" },
      { kind: "new", sentence: "Two more campus hosts reached the same C2 today.", eids: ["E4"], from_logs: true },
      { kind: "nothing_found", sentence: "No other destination of H1 is on a threat list.", eids: ["E5"] },
      { kind: "could_not_tell", sentence: "Whether H1 looked the C2 up by name; DNS logs were 40 minutes behind.", eids: ["E6"] },
      { kind: "still_open", sentence: "Who looks after H1." },
    ],
    new: {},
  },
  timeline: [{ at: "2026-10-09T09:02:00Z", until: "2026-10-09T13:52:00Z", kind: "check", sentence: "H1 reached the C2.", eids: ["E3"] }],
  relative_to: "true_positive",
  evidence: [
    { stance: "supports", fact: { key: "obs:E3", kind: "observation", name: "beacon", sentence: "Contacts at a fixed interval.", status: "known", eids: ["E3"] } },
    { stance: "neutral", fact: { key: "alert:count", kind: "alert", name: "count", sentence: "2 alerts.", status: "known" } },
  ],
  hypotheses: [{ name: "C2 beaconing", by: "model", support: [{ key: "obs:E3", text: "every 300 s", eids: ["E3"] }], against: [] }],
  unknowns: [{ key: "step:2", what: "Who looks after H1", why: "an asset owner decides", who: "the asset owner", floor: true }],
  actions: [{ text: "Ask the owner of H1 to isolate it", who: "a reviewer", why: "it is still active" }],
  cost: { siem_requests: 3, siem_server_ms: 2100, reused: 1, model_calls: 2, model_cost_usd: 0.0123, models: ["m-1"], seconds: 9.5 },
  provenance: [{ eid: "E3", template: "proxy.pair@1", origin: "wave", family: "log", status: "ok", line: "E3 · proxy.pair@1 · squid, 03:30-08:30 UTC · 59 rows · complete", from_logs: true }],
  hidden: 0,
};

export const EMPTY_DASHBOARD: DashboardOut = {
  filters: { range: "7d", start: null, end: null, severity: [], state: [], verdict: [], ai: [], rule: null, kind: null, value: null },
  start: "2026-10-19T00:00:00Z",
  end: "2026-10-26T00:00:00Z",
  bucket: "day",
  kpis: { investigations: 0, open: 0, attention: 0, known: 0, follow_up: 0, incidents: 0, suspected: 0, reviewed: 0, assessed: 0, open_critical: 0, alerts: 0, alerts_before: 0, median_review_s: null },
  series: [],
  states: {},
  severities: {},
  verdicts: {},
  ai: {},
  rules: [],
  entities: { ip: [], host: [], domain: [], user: [] },
  incidents: [],
  open_investigations: [],
  rule_choices: [],
  notified: [],
};

export const CHECK_TEMPLATES: InvestigationChecksOut["templates"] = [
  { template: "proxy.host", words: "A campus host's proxy traffic", takes: "internal", takes_words: "a campus address", heavy: true, cost_words: "A heavy check: a search of the logs. It counts against ARGUS's daily SIEM allowance (300 heavy requests and 6 minutes), may wait for its turn, and is asked of one day's index only." },
  { template: "proxy.pair", words: "How regularly a host reached a destination", takes: "address", takes_words: "any address", heavy: true, cost_words: "A heavy check: a search of the logs. It counts against ARGUS's daily SIEM allowance (300 heavy requests and 6 minutes), may wait for its turn, and is asked of one day's index only." },
  { template: "ti.lookup", words: "Whether an address or domain is on the threat lists", takes: "indicator", takes_words: "an address or a domain", heavy: false, cost_words: "A light check: one small lookup." },
];

export function checksOf(id = ID, more: Partial<InvestigationChecksOut> = {}): InvestigationChecksOut {
  return { investigation_id: id, version: 3, items: [], templates: CHECK_TEMPLATES, limits: { open_per_person: 5, open_now: 0, per_day: 30, today: 0 }, ...more };
}

/** The mock API: the shell's own reads are answered (the session, the cost bar, the SIEM's state). */
export const server = setupServer();
export const requests: { method: string; path: string; body: string }[] = [];
const left: string[] = [];

/** A case with no incident report yet: what the report section reads unless a test says otherwise (AR7). */
export function noReportOut(caseId: string): CaseReportOut {
  const none = { enabled: false, why_not: "There is no report to decide yet." };
  return {
    case_id: caseId,
    case_number: 12,
    case_state: "open",
    version: null,
    newest: null,
    generated_at: null,
    case_version: null,
    prose_by: null,
    stale: false,
    report: null,
    decision: null,
    versions: [],
    files: [],
    logs_hidden: false,
    confirm: none,
    reject: none,
    note: "ARGUS has not written this case's report yet: it writes one in its next assessment pass (every few minutes), once the case has alerts.",
  };
}

export function shellHandlers(session: SessionOut = SESSION) {
  return [
    http.get(`${BASE}/api/v1/cases/:id/report`, ({ params }) => HttpResponse.json(noReportOut(String(params.id)))),
    http.get(`${BASE}/api/v1/cases/:id/team`, ({ params }) => HttpResponse.json(noTeamOut(String(params.id)))),
    http.get(`${BASE}/api/v1/session`, () => HttpResponse.json(session)),
    http.get(`${BASE}/api/v1/cost`, () => HttpResponse.json({ month_usd: 0, today_usd: 0, cap_usd: 10, paid_until_usd: 8, daily_cap_usd: 0.3, calls_today: 0, providers: [], stopped: false, at: "2026-10-26T00:00:00Z" })),
    http.get(`${BASE}/api/v1/health`, () => HttpResponse.json({ siem_state: "normal", siem_reasons: [], siem_probed_at: "2026-10-26T00:00:00Z", live_cursor: null, backfill_cursor: null, open_gaps: [], last_reconciliation: null, alerts: 0, quarantined: 0, investigations: 0, jobs_waiting: 0, jobs_deferred: 0, jobs_failed: 0, dossiers: 0, checkpoint_threads: 0, checkpoint_bytes: 0 })),
    http.get(`${BASE}/api/v1/cases`, () => HttpResponse.json({ items: [], view: "active", offset: 0, limit: 1, has_more: false, counts: { active: 0, notified: 0, attention: 0, mine: 0, suspected: 0, closed: 0, all: 0 } })),
    http.get(`${BASE}/api/v1/approvals`, () => HttpResponse.json({ pending: [], pending_total: 0, recent: [], groups: [], step_up: { valid: false, valid_until: null, url: "/stepup?next=/app/approvals" }, can_sign: true })),
    http.get(`${BASE}/api/v1/investigations/:id/checks`, ({ params }) => HttpResponse.json(checksOf(String(params.id)))),
    http.get(`${BASE}/api/v1/counts`, () => HttpResponse.json({ attention: 6, known: 3, open: 13, follow_up: 1, changed: 2, reviewed: 4, reviewed_today: 1, all: 17 })),
  ];
}

/** Reads the shell does not make but Home does: an empty queue and no patterns (a test that cares sets its own). */
export function homeHandlers() {
  return [
    http.get(`${BASE}/api/v1/queue`, () => HttpResponse.json({ cases: [], cases_total: 0, singles: [], singles_total: 0, notified_cases: 0, order: [], order_total: 0 })),
    http.get(`${BASE}/api/v1/patterns`, () => HttpResponse.json({ groups: [], read: 0, limit: 2000, sampled: false })),
    http.get(`${BASE}/api/v1/patterns/summary`, () => HttpResponse.json({ total: 0, investigations: 0, items: [] })),
  ];
}

export function mockApi(): void {
  beforeAll(() => {
    configure();
    client.setConfig({ baseUrl: BASE });
    server.listen({ onUnhandledRequest: "error" });
    server.events.on("request:start", ({ request }) => {
      void request
        .clone()
        .text()
        .then((body) => requests.push({ method: request.method, path: new URL(request.url).pathname + new URL(request.url).search, body }));
    });
  });
  beforeEach(() => {
    requests.length = 0;
    left.length = 0;
    resetBuildState();
    setCsrf(null);
    server.use(...homeHandlers(), ...shellHandlers());
    setLeave(() => {
      left.push("left");
    });
  });
  afterEach(() => {
    server.resetHandlers();
    window.localStorage.clear();
    vi.restoreAllMocks();
  });
  afterAll(() => server.close());
}

/** How many times the page left for /signin. */
export function leftCount(): number {
  return left.length;
}
export function leftUrls(): string[] {
  return [...left];
}
export function setLeaveSpy(into: string[]): void {
  setLeave((url) => {
    into.push(url);
    left.push(url);
  });
}

/** How many requests went to a path (a path prefix, query included). */
export function sent(method: string, prefix: string): { method: string; path: string; body: string }[] {
  return requests.filter((r) => r.method === method && r.path.startsWith(prefix));
}

/** The viewport: two panes at 1024 px and up (what matchMedia says). */
export function viewport(wide: boolean): void {
  window.matchMedia = ((query: string) => ({
    matches: wide && query.includes("1024"),
    media: query,
    addEventListener: () => {},
    removeEventListener: () => {},
    addListener: () => {},
    removeListener: () => {},
    dispatchEvent: () => false,
    onchange: null,
  })) as unknown as typeof window.matchMedia;
}

/** jsdom has no layout: a list that scrolls is given a window of this size. */
export function layout(width = 420, height = 600): void {
  Object.defineProperty(HTMLElement.prototype, "offsetWidth", { configurable: true, get: () => width });
  Object.defineProperty(HTMLElement.prototype, "offsetHeight", { configurable: true, get: () => height });
  Object.defineProperty(HTMLElement.prototype, "clientHeight", { configurable: true, get: () => height });
}

export function renderApp(path: string) {
  const history = createMemoryHistory({ initialEntries: [`/app${path}`] });
  const router = createAppRouter(history);
  const queries = makeQueryClient();
  const view = render(
    <QueryClientProvider client={queries}>
      <AnnounceProvider>
        <RouterProvider router={router} />
      </AnnounceProvider>
    </QueryClientProvider>,
  );
  return { router, queries, history, ...view };
}

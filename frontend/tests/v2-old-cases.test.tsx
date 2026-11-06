// The UI v2 on the cases production has today (review of p4/f-ui-2c): titles whose campus servers
// answered never offer "Scan or attempt" (§5.5, F3); a case without the engine shows ARGUS's call
// from its report, "not prioritised yet", and the report's open explanations in the confirm dialog
// (§2.4, F15); a campus address is never an outside one (§12.3); counts say what they count (§9.6);
// a person confirms, never ARGUS (§7.1); ARGUS's own history lines are ARGUS's (§7.9); one IR number
// in the CISO's subject; a possible incident shows no IR number; no engine id on a first screen.
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";
import type { CaseDetail, HistoryItemOut } from "../src/client/types.gen";
import { cisoDraft } from "../src/components/incident/Ciso";
import { historyKind, historyWords } from "../src/components/incident/IncidentTabs";
import { engineOf, scanReasonBlocked, sidesWithoutEngine, stillOpen, type Engine } from "../src/lib/engine";
import { againstConfirming, callText, callWords, confirmedBy, reportAlternatives, reportCall } from "../src/lib/incident";
import { rowOf, titleSources, togetherRows } from "../src/lib/incidents";
import { TITLE_NAMES } from "../src/pages/Entity";
import { casePage } from "./caseFixtures";
import { report, reportOut } from "./incidentFixtures";
import { BASE, investigation, mockApi, renderApp, sent, server } from "./helpers";
import { engineBlock, engineRow, P1_ID, p1Detail } from "./v2Fixtures";

mockApi();
const CASE_URL = `${BASE}/api/v1/cases/${P1_ID}`;

const engine = (raw: Record<string, unknown>): Engine => {
  const e = engineOf(raw);
  if (e === null) throw new Error("no engine");
  return e;
};

const event = (text: string, by: string | null, at = "2026-11-04T10:00:00Z"): HistoryItemOut => ({ at, kind: "event", version: 1, text, by, detail: null });

function serve(d: CaseDetail, rep = reportOut({ case_id: P1_ID, case_number: 31, case_state: d.case.state })) {
  server.use(
    http.get(CASE_URL, () => HttpResponse.json(d)),
    http.get(`${CASE_URL}/report`, () => HttpResponse.json(rep)),
  );
}

// the title shapes the cases carry today (naming v2 and the older titles), from tests/unit/cases/test_naming_v2_golden.py
const ANSWERED_TITLES = [
  "Probing for WordPress pages by 12 outside addresses — some got successful answers",
  "Web attack by 3 outside addresses got successful answers",
  "Probing for Git repository folders by 9 outside addresses — config files served",
  "Likely WordPress scan of jobs.example.edu +1 site by 12 outside IPs — got HTTP 200, not verified",
  "Likely backup scan of apps.example.edu by 3 outside IPs — a .env file got HTTP 200, not verified",
  "Likely .env scan of med.example.edu by 4 outside IPs — a .env file served",
  "Scan of a site — got 206 for two paths",
];
const QUIET_TITLES = [
  "Likely web scan of w.example.edu by 2 outside IPs — only ordinary pages got HTTP 200",
  "Likely .env scan by 3 outside IPs — no HTTP 200 after the alerts",
  "Likely .env scan by 2 outside IPs — no web check yet",
  "Probing for WordPress pages by 2 outside addresses — no successful answers",
  "Observed beaconing from 10.30.6.59 to 192.0.2.10",
  "Likely beaconing to 198.51.100.48 from 8 campus devices",
];

describe("Scan or attempt is never offered where something answered (§5.5, F3)", () => {
  it("blocks every title shape that says a campus server answered, with or without the engine, and wherever the words sit", () => {
    for (const title of ANSWERED_TITLES) {
      expect(scanReasonBlocked(null, title), title).toBe(true);
      expect(scanReasonBlocked(engine(engineBlock("P3", 30)), title), title).toBe(true);
    }
    for (const title of QUIET_TITLES) expect(scanReasonBlocked(null, title), title).toBe(false);
    // the engine's own outcome words count too
    expect(scanReasonBlocked(engine(engineBlock("P3", 30, { outcome: { rung: "served", words: "a .env file served" } })), "Likely .env scan")).toBe(true);
  });

  it("the dismiss menu of an old case 'some got successful answers' disables Scan or attempt, and s sends nothing", async () => {
    const user = userEvent.setup();
    serve(p1Detail({}, { title: "Probing for WordPress pages by 12 outside addresses — some got successful answers" }, null));
    renderApp(`/incidents/${P1_ID}`);
    await screen.findByTestId("decision-bar");
    await user.keyboard("d");
    const menu = await screen.findByRole("menu");
    const scan = within(menu).getAllByRole("menuitem").find((m) => m.getAttribute("data-reason") === "attempt_no_impact") as HTMLElement;
    expect(scan.getAttribute("aria-disabled")).toBe("true");
    await user.keyboard("s");
    await user.keyboard("{Enter}");
    expect(sent("POST", `/api/v1/cases/${P1_ID}/dismiss`)).toHaveLength(0);
  });

  it("Review together leaves the old 'successful answers' cases out of Scan or attempt", () => {
    const rows = [engineRow(null, { id: "a1", number: 7, title: ANSWERED_TITLES[0] }), engineRow(null, { id: "a2", number: 18, title: ANSWERED_TITLES[1] }), engineRow(null, { id: "a3", number: 21, title: QUIET_TITLES[1] })].map(rowOf);
    expect(togetherRows(rows).map((t) => [t.number, t.blocked])).toEqual([
      [7, true],
      [18, true],
      [21, false],
    ]);
  });
});

describe("a case without the engine (§2.4)", () => {
  it("the call: the report's, no percentage, not prioritised yet; a person's confirmation is theirs", () => {
    const d = p1Detail({ history: [] }, {}, null);
    expect(callText(d, null, { outcome: "true_positive" })).toBe("ARGUS's call: Real: act on it · not prioritised yet");
    expect(callText(d, null, { outcome: null })).toBe("ARGUS: no call yet · not prioritised yet");
    expect(callText(d, null, null)).toBe("ARGUS: no call yet · not prioritised yet");
    expect(reportCall({ outcome: "inconclusive" })).toBe("ARGUS's call: Can't tell yet");
    expect(reportCall(null)).toBeNull();
    const confirmed = p1Detail({ history: [event("ARGUS (known) linked more of its investigations or indicators", "ARGUS (known)", "2026-11-05T10:00:00Z"), event("asha confirmed the case", "asha")] }, { state: "open" }, null);
    expect(callText(confirmed, null, { outcome: "inconclusive" })).toBe("Confirmed by asha · not prioritised yet");
    expect(callWords(confirmed, null, { outcome: "inconclusive" })).toBe("Confirmed by asha");
    expect(callText(confirmed, engine(engineBlock("P1", 90)), null)).toBe("Confirmed by asha · Priority P1");
    expect(callText(p1Detail({ history: [] }, { state: "open" }, null), null, null)).toBe("Confirmed by a person · not prioritised yet");
    for (const text of [callText(confirmed, null, null), callText(d, engine(engineBlock("P2", 60)), null)]) expect(text).not.toMatch(/ARGUS: confirmed|%/);
  });

  it("who confirmed: a verdict's person, else who confirmed or opened it; never ARGUS, never the containment", () => {
    expect(confirmedBy([event("A true-positive verdict by Asha Rao confirmed the case", "ARGUS")])).toBe("Asha Rao");
    expect(confirmedBy([event("asha confirmed the case is contained", "asha"), event("Ravi confirmed the case", "Ravi")])).toBe("Ravi");
    expect(confirmedBy([event("asha reopened the case", "asha"), event("Asha Rao opened the case with investigations moved from case 4", "Asha Rao")])).toBe("Asha Rao");
    expect(confirmedBy([event("ARGUS (known) opened the case", "ARGUS (known)")])).toBeNull();
    expect(confirmedBy([{ ...event("Ravi confirmed the case", "Ravi"), kind: "request" }])).toBeNull();
  });

  it("the report's explanations: all on the Overview; against confirming, all but the threat reading itself", () => {
    const hypotheses = [
      { name: "A real threat: malicious activity or a compromise (a true positive)", status: "kept" as const, by: "argus" as const, why: [] },
      { name: "A fault in the detection rule (a false positive)", status: "ruled_out" as const, by: "argus" as const, why: [] },
      { name: "Internet research or measurement scanning", status: "open" as const, by: "argus" as const, why: [{ by: "code" as const, cites: [], text: "ARGUS cannot rule it out." }] },
    ];
    expect(reportAlternatives({ hypotheses }).map((a) => [a.name, a.state])).toEqual([
      ["A real threat: malicious activity or a compromise (real: act on it)", "fits"],
      ["A fault in the detection rule (a wrong alert)", "ruled_out"],
      ["Internet research or measurement scanning", "unknown"],
    ]);
    const against = againstConfirming({ hypotheses });
    expect(against.map((a) => a.name)).toEqual(["A fault in the detection rule (a wrong alert)", "Internet research or measurement scanning"]);
    expect(stillOpen({ alternatives: against, checks: [] }).lines).toEqual(["Another explanation not tested: Internet research or measurement scanning."]);
    expect(againstConfirming(null)).toEqual([]);
  });

  it("the bar and the Overview say ARGUS's call from the report on the page", async () => {
    serve(p1Detail({}, {}, null), reportOut({ case_id: P1_ID, case_state: "suspected" }, { verdict: { ...report().verdict, outcome: "true_positive", confidence: 0.88, confidence_words: "high" } }));
    renderApp(`/incidents/${P1_ID}`);
    await waitFor(() => expect(screen.getByTestId("bar-call").textContent).toBe("ARGUS's call: Real: act on it · not prioritised yet"));
    expect(screen.getByTestId("not-scored").textContent).toBe("ARGUS's call: Real: act on it · not prioritised yet.");
    expect(screen.getByTestId("bar-call").textContent).not.toContain("88%");
  });
});

describe("a campus address is never an outside one (§12.3)", () => {
  const indicators = [
    { kind: "ip", value: "10.201.7.11", role: "actor" },
    { kind: "ip", value: "45.138.12.49", role: "actor" },
    { kind: "domain", value: "bad.example", role: "c2" },
    { kind: "ip", value: "10.0.0.9", role: "actor" },
    { kind: "ip", value: "131.21.124.7", role: "actor" },
    { kind: "user", value: "intruder", role: "actor" },
    { kind: "ip", value: "198.51.100.9", role: "indicator" },
  ];
  const body = { assets: [{ kind: "device", value: "10.201.7.11" }], targets: [], actors: [{ value: "131.21.124.7", inside: true }] };

  it("puts a private actor or one the report calls ours on the campus side, once", () => {
    const sides = sidesWithoutEngine(indicators, body);
    const campus = sides.filter((o) => o.role === "affected").map((o) => `${o.kind} ${o.label}`);
    const other = sides.filter((o) => o.role === "actor").map((o) => `${o.kind} ${o.label}`);
    expect(campus).toEqual(["device 10.201.7.11", "device 10.0.0.9", "device 131.21.124.7"]);
    expect(other).toEqual(["device 45.138.12.49", "device bad.example", "account intruder"]);
  });

  it("the Overview and the Entities tab show 10.201.7.11 as a Device on the campus side only", async () => {
    const user = userEvent.setup();
    const d = p1Detail({ indicators: [{ kind: "ip", value: "10.201.7.11", role: "actor", source: "investigation", notes: [], note_count: 0 }, { kind: "ip", value: "45.138.12.49", role: "actor", source: "investigation", notes: [], note_count: 0 }] }, { state: "open" }, null);
    serve(d, reportOut({ case_id: P1_ID, case_state: "open" }, { assets: [{ kind: "device", value: "10.201.7.11", label: null, alerts: 5, days: 1, first_seen: null, last_seen: null }], actors: [] }));
    renderApp(`/incidents/${P1_ID}`);
    const sides = await screen.findByTestId("sides");
    await waitFor(() => expect(sides.textContent).toContain("10.201.7.11"));
    expect(sides.textContent).not.toMatch(/Outside address 10\.198\.36\.230/);
    expect(sides.textContent).toContain("45.138.12.49");
    await user.click(screen.getByRole("tab", { name: /Entities/ }));
    const other = await screen.findByTestId("other-side");
    expect(other.textContent).not.toContain("10.201.7.11");
    expect(other.textContent).toContain("Outside address 45.138.12.49");
    expect(screen.getByTestId("campus-side").textContent).toContain("Device 10.201.7.11");
  });
});

describe("counts say what they count (§9.6)", () => {
  it("the entity page counts incidents whose title names it, never 'In 0 incidents'", async () => {
    server.use(
      http.get(`${BASE}/api/v1/investigations`, () => HttpResponse.json({ items: [investigation(undefined, { alert_count: 88 })], has_more: false, limit: 50, offset: 0, sort: "newest", view: "all" })),
      http.get(`${BASE}/api/v1/cases`, () => HttpResponse.json(casePage([]))),
      http.get(`${BASE}/api/v1/entity-notes`, () => HttpResponse.json({ items: [], kind: "ip", value: "45.138.12.49" })),
    );
    renderApp("/entities/outside/45.138.12.49");
    const block = await screen.findByTestId("entity-incidents");
    await waitFor(() => expect(within(block).getByRole("heading").textContent).toBe(`${TITLE_NAMES} · 0`));
    expect(block.textContent).toContain("ARGUS looks in incident titles only");
    await waitFor(() => expect(screen.getByTestId("entity-knows").textContent).toContain("1 alert group"));
    expect(document.querySelector("main")?.textContent).not.toMatch(/In 0 incidents|\bIn \d+ incidents?\b/);
  });

  it("Review together: the sources from the engine, else the title's count, else a dash, never a false 0", () => {
    expect(titleSources("Probing for WordPress pages by 12 outside addresses — some got successful answers")).toBe(12);
    expect(titleSources("Likely .env scan by 3 outside IPs — no web check yet")).toBe(3);
    expect(titleSources("Likely scan by 1 outside address")).toBe(1);
    expect(titleSources("Likely scan of a.example.edu by 203.0.113.5")).toBe(1);
    expect(titleSources("Beaconing from 10.30.6.59")).toBeNull();
    expect(titleSources("Amadey infection on 10.201.7.11")).toBeNull();
    const rows = [engineRow(null, { id: "a1", number: 7, title: "Probing for WordPress pages by 12 outside addresses — some got successful answers" }), engineRow(null, { id: "a2", number: 11, title: "Amadey infection on 10.201.7.11" }), engineRow(engineBlock("P3", 30), { id: "a3", number: 34, title: "Suspected .env scan" })].map(rowOf);
    expect(togetherRows(rows).map((t) => t.sources)).toEqual([12, null, 1]);
  });

  it("Review together's table shows a dash for an unknown count", async () => {
    const items = [engineRow(null, { id: "e1e1e1e1-0000-4000-8000-000000000001", number: 11, title: "Amadey infection on 10.201.7.11" }), engineRow(null, { id: "e1e1e1e1-0000-4000-8000-000000000002", number: 7, title: "Probing for WordPress pages by 12 outside addresses — some got successful answers" })];
    server.use(http.get(`${BASE}/api/v1/cases`, () => HttpResponse.json(casePage(items))));
    renderApp(`/incidents?view=needs-you&together=${items.map((i) => i.id).join(",")}`);
    const panel = await screen.findByTestId("review-together");
    const cells = within(panel)
      .getAllByTestId("together-row")
      .map((r) => r.querySelectorAll("td")[5]?.textContent ?? "");
    expect(cells.some((c) => c.startsWith("—"))).toBe(true);
    expect(cells.some((c) => c.startsWith("12"))).toBe(true);
    expect(cells.some((c) => c.startsWith("0"))).toBe(false);
  });
});

describe("the Activity tab (§7.9) and the Report tab's headline (§7.1)", () => {
  const history = [
    event("ARGUS (known) linked more of its investigations or indicators", "ARGUS (known)", "2026-11-05T10:00:00Z"),
    event("asha recorded that the owner was told", "asha", "2026-11-04T12:00:00Z"),
    event("asha confirmed the case", "asha", "2026-11-04T10:00:00Z"),
  ];

  it("files ARGUS's own lines under ARGUS and says the name once, in alert groups", () => {
    expect(historyKind({ by: "ARGUS (known)", text: "x" })).toBe("argus");
    expect(historyKind({ by: null, text: "ARGUS suspected this case" })).toBe("argus");
    expect(historyKind({ by: "asha", text: "asha took the case" })).toBe("people");
    expect(historyWords("ARGUS (known) linked more of its investigations or indicators")).toBe("ARGUS (known) linked more of its alert groups or indicators");
  });

  it("renders each line once, under the right chip", async () => {
    const user = userEvent.setup();
    serve(p1Detail({ history, history_total: 3, notes: [] }, { state: "open" }));
    renderApp(`/incidents/${P1_ID}?tab=activity`);
    const log = await screen.findByTestId("activity-log");
    const lines = [...log.querySelectorAll("li")].map((li) => [li.getAttribute("data-kind"), li.textContent?.replace(/^.*?(ARGUS|asha)/, "$1")]);
    expect(lines).toContainEqual(["argus", "ARGUS (known) linked more of its alert groups or indicators"]);
    expect(lines).toContainEqual(["people", "asha recorded that the owner was told"]);
    expect(log.textContent).not.toMatch(/ARGUS \(known\): ARGUS|asha: asha|investigations/);
    await user.click(within(log).getByRole("button", { name: "ARGUS" }));
    expect(log.textContent).toContain("ARGUS (known) linked more of its alert groups");
    await user.click(within(log).getByRole("button", { name: "People" }));
    expect(log.textContent).not.toContain("ARGUS (known)");
  });

  it("the Report tab's headline says who confirmed it, apart from ARGUS's call", async () => {
    serve(p1Detail({ history, decision: null }, { state: "open" }, null), reportOut({ case_id: P1_ID, case_state: "open" }, { verdict: { ...report().verdict, outcome: "inconclusive" } }));
    renderApp(`/incidents/${P1_ID}?tab=report`);
    const head = await screen.findByTestId("report-v2-headline");
    expect(head.textContent).toBe("Incident · Confirmed by asha");
    expect(head.textContent).not.toContain("ARGUS: confirmed");
    expect(screen.getByTestId("bar-call").textContent).toBe("Confirmed by asha · not prioritised yet");
  });
});

describe("IR numbers", () => {
  it("the CISO's subject carries one IR number, the case's, even when the title names another", () => {
    const d = p1Detail({ incident_id: "SOC-IR-2026-1030-02" }, { title: "Amadey infection on 10.201.7.11 (SOC-IR-2026-1027-01)", state: "open" }, null);
    expect(cisoDraft(d, reportOut({ case_id: P1_ID }), null, false).subject).toBe("ACME: Amadey infection on 10.201.7.11 (SOC-IR-2026-1030-02)");
    const bare = p1Detail({ incident_id: null }, { title: "SOC-IR-2026-1027-01 Amadey infection on 10.201.7.11", state: "open" }, null);
    const subject = cisoDraft(bare, undefined, null, false).subject;
    expect(subject).toBe("ACME: Amadey infection on 10.201.7.11 (SOC-IR-2026-1027-01)");
    expect(subject.match(/IR-\d{4}-\d{4}-\d{2}/g)).toHaveLength(1);
  });

  it("a possible incident's header holds no IR number; a confirmed one's does", async () => {
    serve(p1Detail({ incident_id: "SOC-IR-2026-1029-09" }));
    const first = renderApp(`/incidents/${P1_ID}`);
    const line = await screen.findByTestId("badge-line");
    expect(line.textContent).toContain("Possible incident #31");
    expect(line.textContent).not.toContain("SOC-IR-2026-1029-09");
    first.unmount();
    serve(p1Detail({ incident_id: "SOC-IR-2026-1029-09", decision: null }, { state: "open" }));
    renderApp(`/incidents/${P1_ID}`);
    await waitFor(() => expect(screen.getByTestId("badge-line").textContent).toContain("SOC-IR-2026-1029-09"));
  });
});

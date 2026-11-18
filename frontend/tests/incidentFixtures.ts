// The incident report's answer as the API gives it (AR7): the Amadey-shaped case in miniature, made by
// hand. Every address is a documentation or private one.
import type { CaseReportOut, IncidentReport, ReportFact, ReportQuery, ReportSentence } from "../src/client/types.gen";
import { CASE_ID } from "./caseFixtures";

const KIBANA = "https://kibana.example/s/acme-soc/app/discover#/?_g=(filters:!(),time:(from:'2026-10-23T05:30:00.000Z',to:'2026-10-28T00:00:00.000Z'))&_a=(dataSource:(type:'esql'),query:(esql:'FROM%20x'))";

function fact(id: string, text: string, more: Partial<ReportFact> = {}): ReportFact {
  return { id, kind: "alerts", text, source: "ARGUS's stored alerts", numbers: [], from_logs: false, safe: null, ...more };
}

function sentence(text: string, ...cites: string[]): ReportSentence {
  return { text, cites, by: "code" };
}

export function query(more: Partial<ReportQuery> = {}): ReportQuery {
  return {
    kind: "logs",
    language: "esql",
    index: "acme-logs-squid-*",
    text: 'FROM acme-logs-squid-* | WHERE source.ip == "10.201.7.11" | LIMIT 100',
    other: 'source.ip : "10.201.7.11"',
    time_from: "2026-10-25T04:30:00Z",
    time_to: "2026-10-25T10:30:00Z",
    url: KIBANA,
    template: "proxy.pair@1",
    ...more,
  };
}

export function report(more: Partial<IncidentReport> = {}): IncidentReport {
  const facts: ReportFact[] = [
    fact("F1", "1 campus device contacted 4 servers or names that the case lists as command-and-control, raising 35 alerts from 2 rules."),
    fact("F2", "The AI investigator proposed a true positive with confidence 80% for 5 investigations of 5.", { kind: "verdict" }),
    fact("F3", "VirusTotal flags 4 indicators of the case; the strongest, 77.221.155.153, is flagged by 10 of 94 engines.", { kind: "intel" }),
    fact("F4", "The detection rules raised 35 alerts in this case between 23 Oct 2026, 11:00 AM IST and 28 Oct 2026, 6:00 AM IST."),
    fact("F5", "10.201.7.11 made 42 requests to 77.221.155.150, 480 KB between 25 Oct 2026, 10:00 AM IST and 25 Oct 2026, 4:00 PM IST.", { kind: "evidence", from_logs: true }),
    fact("F6", "The still-active watch calls a case quiet after 3 whole UTC days without activity.", { kind: "case" }),
  ];
  return {
    header: {
      incident_id: "ACME-IR-2026-1026-01",
      title: "ACME-IR-2026-1026-01 · Regular beaconing from a campus host",
      case_number: 12,
      case_id: CASE_ID,
      case_state: "open",
      severity: "high",
      opened_in: "opened by a person; confirmed",
      detected_by: "Rules: Rule beacon (21 alerts); Rule download (14 alerts)",
      first_alert_at: "2026-10-23T05:30:00Z",
      last_alert_at: "2026-10-28T00:30:00Z",
      tags: ["ACME-IR-2026-1026-01", "incident", "verdict:true-positive"],
      first_detected_at: "2026-10-23T05:35:00Z",
      last_detected_at: "2026-10-28T00:40:00Z",
      certainty: null,
    },
    summary: {
      headline: "A true positive: Regular beaconing from a campus host",
      standing: "ongoing",
      standing_words: "The activity is still going on: the last alert is recent.",
      sentences: [sentence(facts[0]?.text ?? "", "F1"), sentence("The activity is still going on: the last alert is recent.", "F4")],
      notice: null,
      prose: [],
      prose_note: null,
    },
    verdict: {
      outcome: "true_positive",
      words: "a true positive",
      kind: "proposal",
      confidence: 0.8,
      confidence_words: "medium-high",
      source: "the AI investigator",
      sentences: [sentence(facts[1]?.text ?? "", "F2"), sentence(facts[2]?.text ?? "", "F3")],
      reviewed: 0,
      investigations: 5,
    },
    timeline: {
      first_seen: "2026-10-23T05:30:00Z",
      last_seen: "2026-10-28T00:30:00Z",
      dwell_seconds: 415800,
      dwell_words: "4 days 19 hours",
      phases: [{ name: "Rule download", start: "2026-10-23T05:30:00Z", end: "2026-10-25T15:30:00Z", alerts: 14, sentence: sentence("Rule download: 14 alerts from 23 Oct 2026, 11:00 AM IST to 25 Oct 2026, 9:00 PM IST.", "F4") }],
      columns: ["Rule beacon", "Rule download"],
      days: [
        { day: "2026-10-23", counts: [0, 7], total: 7 },
        { day: "2026-10-24", counts: [7, 0], total: 7 },
      ],
      alerts: 35,
      notes: [sentence("All times are IST.", "F4")],
    },
    actors: [{ value: "10.201.7.11", kind: "ip", role: "campus device", role_words: "A campus device that reached the case's servers.", inside: true, network: null, country: null, user_agents: [], first_seen: "2026-10-23T05:30:00Z", last_seen: "2026-10-28T00:30:00Z", alerts: 35, requests: null, answered: null, answered_exact: false, intel: null, listed: false, served: [], sentence: sentence("10.201.7.11 (campus device): 35 alerts.", "F1") }],
    assets: [{ kind: "device", value: "10.201.7.11", label: "77.221.155.150", alerts: 35, days: 5, first_seen: "2026-10-23T05:30:00Z", last_seen: "2026-10-28T00:30:00Z" }],
    assets_total: 1,
    outsiders_total: 0,
    targets: [],
    targets_total: 0,
    users: { lead: "", devices: [], devices_total: 0, signins: [], same: null },
    evidence: [
      { id: "E1", fact: "F4", title: "The alerts of the case", source: "ARGUS's stored alerts", status: "ok", count: 35, at: null, query: query({ kind: "alerts", index: ".alerts-security.alerts-acme-soc", template: "alerts", text: 'FROM .alerts-security.alerts-acme-soc | WHERE kibana.alert.rule.name IN ("Rule beacon") | LIMIT 200' }), from_logs: false, asked: [], shows: null, details: [] },
      { id: "E2", fact: "F5", title: "How a host reached a destination", source: "the campus proxy logs (squid)", status: "ok", count: 42, at: "2026-10-25T11:00:00Z", query: query(), from_logs: true, asked: [], shows: null, details: [] },
    ],
    hypotheses: [
      { name: "A real threat: malicious activity or a compromise (a true positive)", status: "kept", by: "argus", why: [sentence("It rests on:", "F3"), sentence(facts[2]?.text ?? "", "F3")] },
      { name: "Expected or harmless activity (benign)", status: "ruled_out", by: "argus", why: [sentence("Ruled out by facts a harmless explanation does not account for:", "F3")] },
    ],
    indicators: [
      { kind: "ip", value: "77.221.155.150", role: "c2", role_words: "command-and-control (the server or name the actor reached)", source: "threat_intel", evidence: "VirusTotal: 7 of 94 engines flag this IP; first seen on campus 23 Oct 2026" },
      { kind: "ip", value: "10.201.7.11", role: "actor", role_words: "the actor (a device or address the alerts name)", source: "investigation", evidence: "first seen on campus 23 Oct 2026" },
    ],
    indicators_total: 2,
    actions: {
      lines: [{ id: "c2_beacon.isolate_host", title: "Take the computers off the network", say: "Take each campus computer in this case off the network so it cannot reach the attacker.", owner: "Network team", state: "recommended", family: "c2_beacon", rank: 1 }],
      close_when: sentence("Close the case when the actions above are done and the case has been quiet; closing needs a person's approval.", "F6"),
      note: null,
    },
    queries: [query(), query({ kind: "alerts", template: "alerts", index: ".alerts-security.alerts-acme-soc", text: 'FROM .alerts-security.alerts-acme-soc | MV_EXPAND kibana.alert.workflow_tags | WHERE kibana.alert.workflow_tags == "ACME-IR-2026-1026-01"' })],
    out_of_scope: [sentence("ARGUS reads alerts and logs only: it has no endpoint data, so what runs on a device is not known.", "F4")],
    facts,
    meta: { schema_version: "incident-report@1", writer: "incident-writer@1", as_at: "2026-10-29T07:30:00Z", catalogue_version: 1, alerts_read: 35, alerts_total: 35, limits: ["2 more checks of the case are not listed"], carried: ["source.ip", "destination.ip"] },
    brief: null,
    brief_note: null,
    ...more,
  };
}

export function reportOut(more: Partial<CaseReportOut> = {}, body: Partial<IncidentReport> = {}): CaseReportOut {
  const on = { enabled: true, why_not: null };
  return {
    case_id: CASE_ID,
    case_number: 12,
    case_state: "open",
    version: 2,
    newest: 2,
    generated_at: "2026-10-29T07:31:00Z",
    case_version: 3,
    prose_by: null,
    stale: false,
    report: report(body),
    decision: null,
    versions: [
      { version: 2, generated_at: "2026-10-29T07:31:00Z", prose: false, decision: null, decided_at: null },
      { version: 1, generated_at: "2026-10-28T07:31:00Z", prose: false, decision: "rejected", decided_at: "2026-10-28T09:00:00Z" },
    ],
    files: [
      { kind: "pdf", name: "Incident report (PDF)", url: `/api/v1/cases/${CASE_ID}/report/files/report.pdf`, available: true },
      { kind: "indicators_csv", name: "Indicators (CSV)", url: `/api/v1/cases/${CASE_ID}/report/files/indicators.csv`, available: true },
      { kind: "affected_csv", name: "Affected devices (CSV)", url: `/api/v1/cases/${CASE_ID}/report/files/affected-devices.csv`, available: true },
    ],
    logs_hidden: false,
    confirm: on,
    reject: on,
    note: null,
    ...more,
  };
}

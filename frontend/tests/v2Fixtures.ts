// The UI v2's fixtures (docs/p4f-ui-spec.md §16.1): a Today answer, engine blocks, cases and
// health variants. Every value is made up: outside addresses come from the documentation ranges
// (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), campus names are invented, people are Asha
// and Ravi.
import type { CaseDetail, CaseRowOut, HealthOut } from "../src/client/types.gen";
import { caseDetail, caseRow, DECISION } from "./caseFixtures";

export const P1_ID = "a1a1a1a1-0000-4000-8000-000000000031";
export const P1B_ID = "a1a1a1a1-0000-4000-8000-000000000032";
export const P2_ID = "a2a2a2a2-0000-4000-8000-000000000029";
export const P2X_ID = "a2a2a2a2-0000-4000-8000-000000000030";
export const OLD_ID = "a0a0a0a0-0000-4000-8000-000000000007";
export const CONF_ID = "a3a3a3a3-0000-4000-8000-000000000033";
export const GRAY_ID = "a4a4a4a4-0000-4000-8000-000000000040";
export const GROUP_ID = "b4b4b4b4-0000-4000-8000-000000000041";
export const NOW = "2026-11-06T13:25:00Z"; // 6:55 PM IST

export function lowId(n: number): string {
  return `a9a9a9a9-0000-4000-8000-${String(100 + n).padStart(12, "0")}`;
}

type Raw = Record<string, unknown>;

/** The P1's engine block: 5 points summing to 82, 6 checks, 3 alternatives (1 fits), the mislabel trap. */
export function p1Engine(more: Raw = {}): Raw {
  return {
    incident_id: 31,
    priority: 82,
    band: "P1",
    lane: "decisive",
    certainty: "Likely",
    why: [
      { op: "+", points: 20, text: "Regular timing, like a beacon (98 of 100)" },
      { op: "+", points: 50, text: "VirusTotal: 7 of 94 engines flag 203.0.113.40" },
      { op: "+", points: -8, text: "All five are in one lab; a shared tool is possible" },
      { op: "+", points: 12, text: "Five campus devices, same destination" },
      { op: "+", points: 8, text: "Script download from a related address" },
    ],
    why_line: "+50 VirusTotal · +20 timing",
    checks: [
      { state: "checked", text: "Threat lists: on 1 list, and 7 of 94 VirusTotal engines" },
      { state: "checked", text: "Timing: very regular, every 10 minutes ± 4 s" },
      { state: "ruled_out", text: "Other campus servers talking to it: none in 5 days" },
      { state: "ruled_out", text: "A known update service: the address hosts no known vendor domain" },
      { state: "unknown", text: "Who used the devices: no sign-in data for these PCs" },
      { state: "unknown", text: "What the POSTs carried: the proxy keeps no body" },
    ],
    alternatives: [
      { name: "A software update check", state: "ruled_out", test: "no vendor domain, and vendors don't use raw IPs here" },
      { name: "A remote-management tool the lab installed", state: "fits", test: "ask the lab admin whether such a tool runs" },
      { name: "A student's own server (a project)", state: "unknown", test: "the URL paths" },
    ],
    objects: [
      { kind: "device", label: "lab-pc-17", role: "affected" },
      { kind: "device", label: "lab-pc-21", role: "affected" },
      { kind: "device", label: "lab-pc-22", role: "affected" },
      { kind: "device", label: "lab-pc-23", role: "affected" },
      { kind: "device", label: "lab-pc-24", role: "affected" },
      { kind: "device", label: "203.0.113.40", role: "actor" },
      { kind: "device", label: "203.0.113.41", role: "actor" },
    ],
    raised_by_ai: true,
    active: true,
    first_seen: "2026-11-04T03:40:00Z",
    last_seen: "2026-11-06T13:25:00Z",
    version: 6,
    changed: ["2 more campus devices (lab-pc-21, lab-pc-22)", "VirusTotal 5 → 7 engines"],
    alert_groups: 4,
    alerts: 312,
    ...more,
  };
}

export function engineBlock(band: string, priority: number, more: Raw = {}): Raw {
  return {
    priority,
    band,
    lane: "burst",
    certainty: "Suspected",
    why: [{ op: "+", points: priority, text: "Many outside addresses probed one campus site" }],
    checks: [{ state: "checked", text: "Answers after the probe" }, { state: "unknown", text: "Is the answer a real file or the site's error page" }],
    alternatives: [],
    objects: [
      { kind: "site", label: "www.dept.example.ac.in", role: "affected" },
      { kind: "device", label: "198.51.100.7", role: "actor" },
    ],
    raised_by_ai: false,
    active: false,
    first_seen: "2026-11-05T05:00:00Z",
    last_seen: "2026-11-05T08:30:00Z",
    version: 2,
    changed: [],
    ...more,
  };
}

export function card(id: string, number: number, title: string, engine: Raw, more: Raw = {}): Raw {
  return { kind: "incident", id, number, title, state: "suspected", version: 3, engine, taken_by: null, notified_at: null, in_kibana: false, kibana_wait: null, ...more };
}

export const P1_TITLE = "Likely beaconing from 5 campus devices to 203.0.113.40 (VirusTotal: 7 engines)";
export const P2X_TITLE = "Likely .env scan of www.dept.example.ac.in +1 site by 6 outside IPs — got HTTP 200, not verified — 6 sources";

export function p1Card(more: Raw = {}): Raw {
  return card(P1_ID, 31, P1_TITLE, p1Engine(), { waiting_since: "2026-11-03T04:00:00Z", ...more });
}

/** The P1 whose points do not add up (74 shown, priority 82). */
export function p1bCard(): Raw {
  return card(
    P1B_ID,
    32,
    "Likely DNS tunnelling from lab-pc-02",
    p1Engine({ incident_id: 32, why: [{ op: "+", points: 44, text: "Long random subdomains" }, { op: "+", points: 30, text: "Many queries a minute" }], changed: [], raised_by_ai: false, objects: [{ kind: "device", label: "lab-pc-02", role: "affected" }] }),
  );
}

export function p2ExposureCard(): Raw {
  return card(P2X_ID, 30, P2X_TITLE, engineBlock("P2", 60, { lane: "exposure", certainty: "Likely", changed: ["2 more outside IPs", "a second site answered"] }));
}

export function p2Card(): Raw {
  return card(P2_ID, 29, "Suspected password guessing against 1 account from 198.51.100.9", engineBlock("P2", 55, { objects: [{ kind: "account", label: "student42", role: "affected" }, { kind: "device", label: "198.51.100.9", role: "actor" }] }));
}

export const SIMILAR_TAIL = "no HTTP 200 after the alerts";

/** 9 P3/P4: 3 share a similar key and the outcome words. */
export function lowCards(): Raw[] {
  const out: Raw[] = [];
  for (let i = 0; i < 9; i++) {
    const similar = i < 3;
    const band = i % 2 === 0 ? "P3" : "P4";
    out.push(
      card(
        lowId(i),
        40 + i,
        similar ? `Suspected .env scan of site${i}.example.ac.in — ${SIMILAR_TAIL}` : `Suspected odd login ${i} on host-${i}`,
        engineBlock(similar ? "P3" : band, 30 - i, similar ? { similar_key: "env-scan", outcome: { rung: "no_answer", words: SIMILAR_TAIL } } : {}),
      ),
    );
  }
  return out;
}

export function today(more: Raw = {}): Raw {
  return {
    mode: "present",
    needs_you: [p1Card(), p1bCard(), p2ExposureCard(), p2Card(), ...lowCards()],
    more_waiting: 4,
    new_activity: [
      card(CONF_ID, 12, "Likely beaconing from 1 campus device to 203.0.113.40", engineBlock("P2", 50, { changed: ["a second destination"] }), { state: "open", notified_at: "2026-11-02T05:00:00Z" }),
    ],
    gray: [
      card(GRAY_ID, 44, "Unclear: password guessing against 1 account from 198.51.100.7", engineBlock("P3", 35, {
        certainty: "Unclear",
        checks: [{ state: "unknown", text: "40 failures, then 1 success; no second sign seen" }],
        alternatives: [{ name: "The owner mistyped", state: "fits", test: "did the account sign in from a new place after the success?" }],
      })),
      { ...card(GROUP_ID, null as unknown as number, "Plain-HTTP POST to a raw IP from lab-pc-09", engineBlock("P3", 33)), kind: "alert_group", number: null, state: null },
    ],
    handled: {
      since: "2026-11-04T10:40:00Z",
      count: 1140,
      categories: [
        { key: "noise", label: "Closed as known noise", count: 1020 },
        { key: "known", label: "Owner already told, still active", count: 90 },
        { key: "joined", label: "Joined existing incidents", count: 30 },
      ],
      audit: null,
    },
    audits: [
      { id: "d1d1d1d1-0000-4000-8000-000000000001", kind: "alert_group", title: "Web scan of 3 campus servers", closed_as: "known noise", facts: ["212 requests from 192.0.2.15 to 3 campus servers", "answers: 212 × 403", "no 2xx"] },
      { id: "d1d1d1d1-0000-4000-8000-000000000002", kind: "alert_group", title: "DNS lookups of a rare domain", closed_as: "known noise", facts: ["14 lookups from lab-pc-05", "no connection after"] },
      { id: "d1d1d1d1-0000-4000-8000-000000000003", kind: "alert_group", title: "Logins from a new place", closed_as: "owner already told", facts: ["3 logins for student7 from 198.51.100.20"] },
    ],
    audit_score: { days: 30, checked: 64, wrong: 1 },
    ...more,
  };
}

/** A case row with an engine block (the field engine builder C adds to CaseRowOut). */
export function engineRow(engine: Raw | null, more: Partial<CaseRowOut> = {}): CaseRowOut {
  return { ...caseRow({ state: "suspected", opened_at: null, cause: "raised", in_kibana: false, kibana_wait: null, ...more }), engine } as unknown as CaseRowOut;
}

/** The P1 as a whole case with its decision and engine block. */
export function p1Detail(more: Partial<CaseDetail> = {}, row: Partial<CaseRowOut> = {}, engine: Raw | null = p1Engine()): CaseDetail {
  const d = caseDetail(
    { decision: DECISION, cause_words: "Raised by ARGUS from evidence across alert groups.", ...more },
    { id: P1_ID, number: 31, title: P1_TITLE, state: "suspected", opened_at: null, cause: "raised", version: 4, kibana_wait: null, ...row },
  );
  return { ...d, case: { ...d.case, engine }, engine } as unknown as CaseDetail;
}

export function health(more: Partial<HealthOut> = {}): HealthOut {
  return {
    siem_state: "normal",
    siem_reasons: [],
    siem_probed_at: new Date().toISOString(),
    live_cursor: new Date().toISOString(),
    backfill_cursor: null,
    open_gaps: [],
    last_reconciliation: null,
    alerts: 10,
    quarantined: 0,
    investigations: 4,
    jobs_waiting: 0,
    jobs_deferred: 0,
    jobs_failed: 0,
    dossiers: 4,
    checkpoint_threads: 0,
    checkpoint_bytes: 0,
    kibana_sync: { state: "ok", last_cycle_at: null, last_outcome: null, last_reason: null, last_complete_at: null },
    ...more,
  };
}

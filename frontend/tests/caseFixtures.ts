// The case pages' fixtures: a case row, a whole case, an approval request and the queue.
import type { ApprovalOut, ApprovalQueueOut, CaseActionStateOut, CaseDetail, CasePage, CaseRowOut, ClosureChoiceOut, KnownOut, MirrorOut } from "../src/client/types.gen";

export const CASE_ID = "c1c1c1c1-0000-4000-8000-000000000001";
export const CASE2_ID = "c2c2c2c2-0000-4000-8000-000000000002";
export const LEAD_ID = "54c802b6-fb1a-5614-a6e4-f76c773213d2";
export const HASH = "a".repeat(64);
/** the right-to-left override, written so no source file holds the character itself */
export const RLO = String.fromCodePoint(0x202e);

export function caseRow(more: Partial<CaseRowOut> = {}): CaseRowOut {
  return {
    id: CASE_ID,
    number: 12,
    title: "Regular beaconing from 10.0.0.1",
    state: "open",
    severity: "high",
    version: 4,
    cause: "person",
    owner: null,
    opened_at: "2026-10-20T04:00:00Z",
    closed_at: null,
    closure_reason: null,
    attention: null,
    kibana_wait: "Waiting for someone who may open cases in Kibana",
    investigations: 3,
    alerts: 41,
    first_alert_at: "2026-10-18T04:00:00Z",
    last_alert_at: "2026-10-24T08:20:00Z",
    updated_at: "2026-10-24T09:00:00Z",
    in_kibana: false,
    waiting_for_approval: 0,
    needs_attention: false,
    merged_into: null,
    notified_at: null,
    blocked_at: null,
    ...more,
  };
}

export function casePage(items: CaseRowOut[] = [caseRow()], more: Partial<CasePage> = {}): CasePage {
  return { items, view: "active", offset: 0, limit: 100, has_more: false, counts: { active: items.length, notified: 0, attention: 1, mine: 2, suspected: 3, closed: 4, queue: 2, all: 9 }, ...more };
}

const action = (name: CaseActionStateOut["action"], label: string, enabled = true, why_not: string | null = null): CaseActionStateOut => ({ action: name, label, enabled, why_not });

export const ACTIONS: CaseActionStateOut[] = [
  action("take", "Take"),
  action("assign", "Assign"),
  action("release", "Release", false, "Only an assigned case can be released; this one is open."),
  action("contain", "Confirm contained", false, "ARGUS has not shown the case quiet for 72 hours, so it cannot be confirmed contained yet: the still-active watch is not running here, so nothing can be shown quiet."),
  action("request_closure", "Request closure"),
  action("merge", "Merge into another case"),
  action("reopen", "Reopen", false, "Only a closed case can be reopened; this one is open."),
];

const choice = (reason: ClosureChoiceOut["reason"], label: string, more: Partial<ClosureChoiceOut> = {}): ClosureChoiceOut => ({
  reason,
  label,
  meaning: `${label} means what it says.`,
  enabled: true,
  why_not: null,
  note: "optional",
  approvers: 1,
  note_hint: null,
  ...more,
});

export const CHOICES: ClosureChoiceOut[] = [
  choice("remediated_verified", "Fixed, and shown quiet", { enabled: false, why_not: "“Fixed, and shown quiet” needs ARGUS to have shown the case quiet for 72 hours, and it has not: the still-active watch is not running here, so nothing can be shown quiet." }),
  choice("remediated_unverified", "Fixed, as its owner says", { note: "required", approvers: 2, note_hint: "What the owner said, and who they are" }),
  choice("risk_accepted", "Left as it is, by decision", { note: "required", approvers: 2, note_hint: "Who accepted the risk, and why" }),
  choice("benign_expected", "Benign: expected activity"),
  choice("benign_policy", "Benign: allowed by policy"),
];

export const MIRROR: MirrorOut = {
  state: "waiting",
  words: "Waiting for someone who may open cases in Kibana",
  kibana_case_id: null,
  kibana_status: null,
  kibana_severity: null,
  kibana_version: null,
  tags: [],
  created_by: null,
  sync_alerts: null,
  unmanaged: [],
  read_at: null,
  kibana_updated_at: null,
  paused_reason: null,
  deleted_at: null,
  writes: [],
  writes_total: 0,
  findings: [],
  findings_total: 0,
};

export function caseDetail(more: Partial<CaseDetail> = {}, row: Partial<CaseRowOut> = {}): CaseDetail {
  return {
    case: caseRow(row),
    cause_words: "Opened by a person.",
    parent: null,
    children: [],
    children_total: 0,
    summary: {
      investigations: 3,
      alerts: 41,
      rules: [{ rule_name: "Proxy: tunnel to a remote-admin port", investigations: 3, alerts: 41 }],
      rules_total: 1,
      first_alert_at: "2026-10-18T04:00:00Z",
      last_alert_at: "2026-10-24T08:20:00Z",
      reviewed: 1,
      unreviewed: 2,
    },
    whats_new: { since: "2026-10-23T08:00:00Z", first_visit: false, items: [{ at: "2026-10-24T08:30:00Z", kind: "case", text: "Ravi Rao took the case", by: "Ravi Rao", investigation_id: null }] },
    timeline: [
      { at: "2026-10-18T04:00:00Z", until: "2026-10-18T09:00:00Z", kind: "alerts", text: "Proxy: tunnel to a remote-admin port: 14 alerts", by: null, investigation_id: LEAD_ID },
      { at: "2026-10-20T04:00:00Z", until: null, kind: "case", text: "Asha Rao opened the case", by: "Asha Rao", investigation_id: null },
    ],
    timeline_total: 2,
    lead_investigation_id: LEAD_ID,
    investigations: [
      {
        investigation_id: LEAD_ID,
        version: 3,
        rule_name: "Proxy: tunnel to a remote-admin port",
        severity: "high",
        alert_count: 14,
        first_event_at: "2026-10-18T04:00:00Z",
        last_event_at: "2026-10-18T09:00:00Z",
        bucket_start: "2026-10-18T00:00:00+05:30",
        human_state: "reviewed",
        last_outcome: "true_positive",
        link: "person",
        link_value: null,
        added_at: "2026-10-20T04:00:00Z",
        added_by: "Asha Rao",
      },
    ],
    investigations_total: 3,
    indicators: [
      { kind: "ip", value: "10.0.0.1", role: "actor", source: "investigation", notes: [{ id: 1, author: "Asha Rao", body: "A lab printer, says the lab.", created_at: "2026-10-21T04:00:00Z" }], note_count: 1 },
      { kind: "domain", value: "bad.example", role: "c2", source: "threat_intel", notes: [], note_count: 0 },
    ],
    indicators_total: 2,
    suggestions: [],
    suggestions_total: 0,
    watch: null,
    known: null,
    actions: ACTIONS,
    closure_choices: CHOICES,
    assignees: [
      { id: 1, username: "asha", display_name: "Asha Rao" },
      { id: 2, username: "ravi", display_name: "Ravi Rao" },
    ],
    approvals: [],
    approvals_total: 0,
    mirror: MIRROR,
    notes: [{ id: 5, author: "Asha Rao", body: "Called the lab admin.", created_at: "2026-10-22T04:00:00Z" }],
    notes_total: 1,
    history: [{ at: "2026-10-20T04:00:00Z", kind: "event", version: 1, text: "Asha Rao opened the case", by: "Asha Rao", detail: null }],
    history_total: 1,
    logs_hidden: false,
    signins: null,
    ...more,
  };
}

export function approval(more: Partial<ApprovalOut> = {}): ApprovalOut {
  return {
    id: 31,
    kind: "closure",
    words: "Close case 12: benign: expected activity",
    reason: "benign_expected",
    case: { id: CASE_ID, number: 12, title: "Regular beaconing from 10.0.0.1", state: "open" },
    case_version: 5,
    target: null,
    status: "pending",
    status_words: "0 of 1 approval so far",
    requested_by: { id: 1, username: "asha", display_name: "Asha Rao" },
    proposed_by: null,
    requested_at: "2026-10-24T08:00:00Z",
    expires_at: "2026-10-25T17:30:00Z",
    required: 1,
    decisions: [],
    payload: { case: CASE_ID, version: 5, reason: "benign_expected", writes: [{ class: "W3", op: "close", payload: { status: "closed", severity: "high", argus_tags: ["argus", "argus:closed"] } }, { class: "W3", op: "comment", payload: { template: "closed", params: { reason: "benign_expected" } } }] },
    payload_hash: HASH,
    alerts_then: 41,
    alerts_now: 41,
    alerts_same: true,
    note: null,
    kibana_version: null,
    hold: null,
    you: { can_decide: true, why_not: null, decided: null },
    group: null,
    ...more,
  };
}

export function queue(more: Partial<ApprovalQueueOut> = {}): ApprovalQueueOut {
  return {
    pending: [approval()],
    pending_total: more.pending?.length ?? 1,
    recent: [],
    groups: [],
    step_up: { valid: true, valid_until: "2999-01-01T00:00:00Z", url: "/stepup?next=/app/approvals" },
    can_sign: true,
    ...more,
  };
}

const state = (action: CaseActionStateOut["action"], label: string, enabled = true, why_not: string | null = null): CaseActionStateOut => ({ action, label, enabled, why_not });

/** The owner-notified record of a case (AR4b): by default told 6 days ago, still alerting, nothing changed. */
export function knownOut(more: Partial<KnownOut> = {}): KnownOut {
  return {
    alerts: 41,
    alerts_per_day: [
      { day: "2026-10-26", alerts: 12 },
      { day: "2026-10-25", alerts: 29 },
    ],
    block: state("block", "Record a network block"),
    blocked_at: null,
    blocklist_entries: 3,
    changes: [],
    days: 6,
    devices: 2,
    last_alert_at: "2026-10-26T08:00:00Z",
    line: "still active: 41 alerts in 6 days since the owner was notified on 20 Oct 2026",
    managed: false,
    new_destinations: [],
    new_destinations_total: 0,
    notices: [{ kind: "owner", at: "2026-10-20T04:00:00Z", told: "Hostel 5 warden", how: "phone", managed: false, note: "she will bring the laptop in", by: "Mina Manager", case_version: 2, withdrawn: false }],
    notified_at: "2026-10-20T04:00:00Z",
    notify: state("notify", "Record a notice"),
    reminders: [],
    trend: "about the same each day",
    withdraw_notice: state("withdraw_notice", "Withdraw the notice"),
    ...more,
  };
}

// The case team's preview as the API serves it (AR8, D-195): the Amadey-shaped case in miniature.
import type { CaseTeamOut } from "../src/client/types.gen";

export const PLAN_HASH = "ab".repeat(32);
const KIBANA = "https://kibana.example";
const open = { method: "POST", path: "/s/acme-soc/api/cases", content_type: "application/json", body: "{}" };

export function step(n: number, key: string, author: CaseTeamOut["steps"][number]["author"], kind: CaseTeamOut["steps"][number]["kind"], what: string, text: string | null, more: Partial<CaseTeamOut["steps"][number]> = {}): CaseTeamOut["steps"][number] {
  return {
    n,
    key,
    kind,
    author,
    part: key.split(":")[1] ?? key,
    what: `${author} ${what}`,
    text,
    request: { ...open, path: kind === "comment" ? "/s/acme-soc/api/cases/NEWCASE/comments" : open.path, body: kind === "comment" ? JSON.stringify({ comment: text }) : "{}" },
    state: null,
    ...more,
  };
}

export const STEPS: CaseTeamOut["steps"] = [
  step(1, "open", "argus-lead", "open", "opens the case", "## Summary\n\n1 campus device contacted 4 servers."),
  step(2, "attach:1", "argus-lead", "attach", "attaches 5 alerts", null, { request: { ...open, path: "/s/acme-soc/api/cases/NEWCASE/comments", content_type: "application/json", body: '{"alertId":["a1"]}' } }),
  step(3, "comment:evidence:1", "argus-evidence", "comment", "comments (evidence)", "## Evidence\n\n**E1 · The alerts of the case**"),
  step(4, "comment:queries:1", "argus-hunter", "comment", "comments (queries)", "## Queries to check it yourself\n\n```kql\nsource.ip : \"10.0.0.1\"\n```"),
  step(5, "file:pdf", "argus-reporter", "file", "uploads ACME-IR-2026-1026-01_Incident_Report", null, { request: { method: "POST", path: "/s/acme-soc/api/cases/NEWCASE/files", content_type: "multipart/form-data; boundary=argus-0", body: "ACME-IR-2026-1026-01_Incident_Report.pdf (application/pdf, 51180 bytes, sha-256 368ec2edfadbda48)" } }),
  step(6, "comment:verdict", "argus-lead", "comment", "comments (verdict)", "**ARGUS's verdict: true positive (0.8).**\n\nConfirm or reject in a comment."),
];

export function teamOut(caseId: string, more: Partial<CaseTeamOut> = {}): CaseTeamOut {
  return {
    case_id: caseId,
    case_number: 12,
    case_state: "open",
    post_enabled: false,
    incident_id: "ACME-IR-2026-1026-01",
    report_version: 2,
    decision: { action: "none", would: "open", why: "case_team.post is off: this is a dry run", route: "ARGUS's verdict is a true positive (0.80)", dry_run: true, needs_approval: false },
    plan_hash: PLAN_HASH,
    steps: STEPS,
    problems: [],
    approval: { required: false, given: false, why_not: null, can_approve: false, approve_why_not: "this case needs no approval now", needs_step_up: false, step_up_url: null },
    post: null,
    authors: ["argus-lead", "argus-evidence", "argus-intel", "argus-responder", "argus-hunter", "argus-reporter"],
    logs_hidden: false,
    note: "Posting is switched off (case_team.post), so nothing is written to Kibana: this is what ARGUS would do (open).",
    ...more,
  };
}

export function noTeamOut(caseId: string): CaseTeamOut {
  return teamOut(caseId, {
    incident_id: null,
    report_version: null,
    decision: { action: "none", would: "none", why: "ARGUS has not written this case's report yet", route: null, dry_run: false, needs_approval: false },
    plan_hash: null,
    steps: [],
    note: null,
  });
}

export const WAITING = {
  required: true,
  given: false,
  why_not: "no person has approved this plan yet",
  can_approve: true,
  approve_why_not: null,
  needs_step_up: false,
  step_up_url: null,
};

export const KIBANA_PREFIX = KIBANA;

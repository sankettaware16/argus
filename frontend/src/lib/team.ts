/**
 * The Kibana case preview's small rules, pure (AR8, D-195): what a decision is called, who the six
 * Kibana users are in plain words, and the body an approval sends. The server has the last word.
 */
import type { CaseTeamOut } from "../client/types.gen";
import type { Tone } from "../components/ui/badge";

export type TeamDecision = CaseTeamOut["decision"];
export type TeamStep = CaseTeamOut["steps"][number];

/** The seven users and what each says (D-158); the Kibana name is what the timeline shows. */
export const AUTHOR_ROLE: Record<TeamStep["author"], string> = {
  "argus-lead": "lead: opens the case, attaches and tags the alerts, gives the verdict",
  "argus-evidence": "evidence: what was seen, the hypotheses, the affected devices",
  "argus-intel": "threat intel: only when an outside indicator is not settled locally",
  "argus-responder": "responder: the recommended actions",
  "argus-hunter": "hunter: the queries to check it yourself",
  "argus-reporter": "reporter: the PDF, the one-page dashboard and the two CSVs, and the comment that lists them",
  "argus-visualiser": "visualiser: the incident at a glance, with live charts of the case's alerts",
};

export const STATE_WORDS: Record<string, string> = {
  planned: "waiting",
  sending: "being sent",
  sent: "sent",
  verified: "in Kibana",
  ambiguous: "in doubt: ARGUS is looking for it",
  resend: "not found: a person decides",
  failed: "failed",
  skipped: "skipped",
  held: "held",
};

export const STATE_TONE: Record<string, Tone> = {
  planned: "neutral",
  sending: "info",
  sent: "info",
  verified: "ok",
  ambiguous: "warn",
  resend: "danger",
  failed: "danger",
  skipped: "neutral",
  held: "warn",
};

/** What the decision comes to, in a few words and a tone. */
export function decisionTitle(d: TeamDecision): { words: string; tone: Tone } {
  if (d.dry_run) return { words: "Posting is off: a dry run", tone: "info" };
  switch (d.action) {
    case "open":
      return { words: "Ready to open the case", tone: "ok" };
    case "update":
      return { words: "Ready to post an update", tone: "ok" };
    case "resume":
      return { words: "A started post is being finished", tone: "info" };
    default:
      return { words: "Not posted yet", tone: "neutral" };
  }
}

/** The body of an approval: exactly the plan the person read, by its hash. */
export function approveBody(planHash: string): { plan_hash: string } {
  return { plan_hash: planHash };
}

/** The Kibana user's name without the prefix, for a short label. */
export function shortAuthor(author: string): string {
  return author.replace(/^argus-/, "");
}

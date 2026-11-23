import { Dialog } from "@base-ui/react/dialog";
import { own, teamName, zoneLabel } from "../../lib/site";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import type { CaseDetail, CaseReportOut, IncidentReport } from "../../client/types.gen";
import { useAnnounce } from "../../lib/announce";
import { parse } from "../../lib/time";
import { dayAndTime } from "../../lib/when";
import { caseReportOptions, caseTeamOptions, changedCase, changedReport } from "../../lib/queries";
import { can, useSession } from "../../lib/session";
import type { Engine } from "../../lib/engine";
import { ConfirmDialog } from "../ConfirmDialog";
import { UntrustedText } from "../UntrustedText";
import { Button } from "../ui/button";
import { sendShown } from "../decide/target";
import { briefOf, statementOf, WHEN, WHO } from "./Brief";

/** The note that records a report sent to the CISO without A14 (§7.3 step 9): the bar reads this exact note. */
export function cisoNote(version: number): string {
  return `Reported to the CISO with incident report v${version}.`;
}

/** The newest report version recorded as sent to the CISO, from the case's notes, or null. */
export function cisoSent(detail: CaseDetail): { version: number; at: string; by: string } | null {
  for (const n of detail.notes) {
    const m = /^Reported to the CISO with incident report v(\d+)\.$/.exec(n.body.trim());
    if (m) return { version: Number(m[1]), at: n.created_at, by: n.author };
  }
  return null;
}

export const restricted = (): string => `Reports hold ${own("addresses")} and names: send them only to the CISO's office and ${teamName()}.`;
const MAILTO_MAX = 1800;
const IR_NUMBER = /\b(?:[A-Z]+-)?IR-\d{4}-\d{4}-\d{2}\b/;
const IR_IN_TITLE = /\s*(?:\(\s*(?:[A-Z]+-)?IR-\d{4}-\d{4}-\d{2}\s*\)|\b(?:[A-Z]+-)?IR-\d{4}-\d{4}-\d{2}\b)/g;

/** How each account relates to the case's addresses: the only one seen on some, one of several on others. */
export function accountLines(report: IncidentReport): string[] {
  const alone = new Map<string, number>();
  const among = new Map<string, number>();
  for (const d of report.users.devices) {
    const names = [...new Set(d.accounts.map((a) => a.name).filter((n) => n !== ""))];
    for (const n of names) (names.length === 1 ? alone : among).set(n, ((names.length === 1 ? alone : among).get(n) ?? 0) + 1);
  }
  const all = [...new Set([...alone.keys(), ...among.keys()])].sort((x, y) => (alone.get(y) ?? 0) - (alone.get(x) ?? 0) || x.localeCompare(y));
  const n = (k: number) => `${k} ${k === 1 ? "address" : "addresses"}`;
  return all.map((name) => {
    const a = alone.get(name) ?? 0;
    const s = among.get(name) ?? 0;
    const said = [a > 0 ? `the only account seen on ${n(a)}` : "", s > 0 ? `one of several on ${n(s)}` : ""].filter((x) => x !== "").join("; ");
    return `- ${name}: ${said}`;
  });
}

/**
 * The draft's subject and body (pure; tests/v2-incident.test.tsx). With an analyst brief (D-332)
 * it reads as the team's hand-written escalation: what is happening, the summary, who, why it is
 * judged real, the risk and the numbered steps asked for; without one, the report's own summary.
 */
export function cisoDraft(detail: CaseDetail, data: CaseReportOut | undefined, engine: Engine | null, seeLogs: boolean): { subject: string; body: string; pdf: string | null } {
  const report = (data?.report ?? null) as IncidentReport | null;
  const brief = briefOf(report);
  const named = IR_NUMBER.exec(detail.case.title)?.[0] ?? null;
  const ir = detail.incident_id ?? report?.header.incident_id ?? named;
  const title = detail.case.title.replace(IR_IN_TITLE, "").replace(/\s{2,}/g, " ").trim() || detail.case.title;
  const subject = `${teamName()}: ${title}${ir ? ` (${ir})` : ""}`; // one IR number: the case's, never the title's beside it
  const pdf = data?.files.find((f) => f.kind === "pdf" && f.available)?.name ?? null;
  const lines: string[] = [];
  if (brief !== null) {
    lines.push(statementOf(brief), "", "Summary", ...brief.points.map((p) => `- ${p.text}`), "");
  } else {
    const summary = report?.summary.sentences.filter((s) => s.by === "code").map((s) => s.text) ?? [];
    lines.push("Summary", ...(summary.length > 0 ? summary : [detail.case.title]), "");
  }
  const assets = report?.assets.slice(0, 25) ?? [];
  if (assets.length > 0) {
    lines.push("Devices", ...assets.map((a) => `- ${a.value}${a.label ? ` (${a.label})` : ""}`));
    if ((report?.assets_total ?? 0) > assets.length) lines.push(`- and ${(report?.assets_total ?? 0) - assets.length} more, in the attached PDF`);
    if (seeLogs && report?.users.same) lines.push(report.users.same.text);
    lines.push("");
  }
  const first = parse(report?.header.first_alert_at ?? engine?.first_seen ?? detail.case.first_alert_at);
  const last = parse(report?.header.last_alert_at ?? engine?.last_seen ?? detail.case.last_alert_at);
  if (first && last) lines.push("Time window", `${dayAndTime(first)} to ${dayAndTime(last)} ${zoneLabel(last)}`, "");
  if (seeLogs && report !== null && report.users.devices.some((d) => d.accounts.length > 0)) {
    const accounts = accountLines(report);
    lines.push("Accounts (from the sign-in logs: a lead, not proof)", ...(accounts.length > 0 ? accounts : ["Accounts: in the attached PDF"]), "");
  } else lines.push("Accounts: in the attached PDF", "");
  if (brief !== null) {
    if (brief.why.length > 0) lines.push("Why it is judged real", ...brief.why.map((p) => `- ${p.text}`), "");
    if (brief.impact.length > 0) lines.push("Risk", ...brief.impact.map((p) => `- ${p.text}`), "");
    if (brief.actions.length > 0) lines.push("Requested actions", ...brief.actions.map((a, i) => `${i + 1}. ${a.text} (${WHO[a.who]}, ${WHEN[a.when].toLowerCase()})`), "");
  }
  if (pdf) lines.push(`Attached: ${pdf}`);
  return { subject, body: lines.join("\n").trim(), pdf };
}

/**
 * Report to the CISO (§7.3 step 9, F11): a draft to copy or open in mail, the PDF to download, and
 * "Mark as sent", which records the exact note the bar reads (no sent route exists yet: A14).
 */
export function CisoDraftDialog({ detail, engine, open, onOpenChange }: { detail: CaseDetail; engine: Engine | null; open: boolean; onOpenChange: (open: boolean) => void }) {
  const report = useQuery({ ...caseReportOptions(detail.case.id, null), enabled: open });
  const session = useSession();
  const queries = useQueryClient();
  const { announce } = useAnnounce();
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState(false);
  const draft = cisoDraft(detail, report.data, engine, can(session.data, "see_logs"));
  const mailto = `mailto:?subject=${encodeURIComponent(draft.subject)}&body=${encodeURIComponent(draft.body)}`;
  const pdf = report.data?.files.find((f) => f.kind === "pdf" && f.available) ?? null;
  const version = report.data?.version ?? null;

  async function markSent() {
    if (busy || version === null) return;
    setBusy(true);
    try {
      await sendShown({ method: "POST", path: `/api/v1/cases/${detail.case.id}/notes`, body: { body: cisoNote(version) } });
      announce(`Recorded: incident #${detail.case.number}'s report v${version} was sent to the CISO.`, "ok");
      onOpenChange(false);
      await changedCase(queries, detail.case.id);
    } catch (e) {
      announce(e instanceof Error ? e.message : "It could not be recorded; try again.", "danger");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Backdrop className="fixed inset-0 z-40 bg-black/40" />
        <Dialog.Popup data-testid="ciso-draft" className="fixed top-1/2 left-1/2 z-50 flex max-h-[90vh] w-[min(44rem,calc(100vw-2rem))] -translate-x-1/2 -translate-y-1/2 flex-col gap-3 overflow-auto rounded-card border border-border bg-raised p-5 text-text shadow-card">
          <Dialog.Title className="m-0 text-lg font-semibold">Report incident #{detail.case.number} to the CISO</Dialog.Title>
          <p className="m-0 text-sm">
            <span className="font-semibold">Subject: </span>
            <UntrustedText value={draft.subject} limits={{ maxChars: 300, maxLines: 2 }} />
          </p>
          <pre className="m-0 max-h-72 overflow-auto rounded-control bg-surface-2 p-3 text-sm whitespace-pre-wrap" data-testid="ciso-body" tabIndex={0} aria-label="The message">
            <UntrustedText value={draft.body} limits={{ maxChars: 8000, maxLines: 200 }} block />
          </pre>
          <div className="flex flex-wrap gap-2">
            <Button
              variant="primary"
              onClick={() => {
                void navigator.clipboard?.writeText(`${draft.subject}\n\n${draft.body}`).then(() => setCopied(true), () => announce("The browser did not let ARGUS copy; select the text instead.", "warn"));
              }}
            >
              {copied ? "Copied" : "Copy"}
            </Button>
            {mailto.length < MAILTO_MAX && (
              <a href={mailto} className="inline-flex min-h-8 items-center rounded-control border border-border-strong px-3 text-sm text-text no-underline hover:bg-surface-2">
                Open in mail
              </a>
            )}
            {mailto.length >= MAILTO_MAX && <span className="self-center text-sm text-muted">Too long for a mail link: copy it into your mail.</span>}
            {pdf && (
              <a href={pdf.url} className="inline-flex min-h-8 items-center rounded-control border border-border-strong px-3 text-sm text-text no-underline hover:bg-surface-2" download>
                Download the PDF
              </a>
            )}
            <Button aria-disabled={busy || version === null} onClick={() => void markSent()}>
              Mark as sent
            </Button>
          </div>
          <p className="m-0 text-sm text-muted">{restricted()}</p>
          <div className="flex justify-end">
            <Dialog.Close render={<Button />}>Close</Dialog.Close>
          </div>
        </Dialog.Popup>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

/** Send to Kibana (§7.1): the report's confirm route; its sentence is the case team's own. */
export function SendToKibanaDialog({ detail, open, onOpenChange }: { detail: CaseDetail; open: boolean; onOpenChange: (open: boolean) => void }) {
  const report = useQuery({ ...caseReportOptions(detail.case.id, null), enabled: open });
  const team = useQuery({ ...caseTeamOptions(detail.case.id), enabled: open });
  const queries = useQueryClient();
  const { announce } = useAnnounce();
  const version = report.data?.version ?? 0;
  if (!open) return null;
  return (
    <ConfirmDialog
      open={open}
      onOpenChange={onOpenChange}
      title={`Send incident #${detail.case.number} to Kibana`}
      description={
        <>
          {team.data ? <UntrustedText value={team.data.decision.why} limits={{ maxChars: 600, maxLines: 6 }} /> : "Reading what ARGUS would write…"} This also labels all the incident&apos;s alert groups as Real: act on it.
          {report.data && !report.data.confirm.enabled && report.data.confirm.why_not && (
            <span className="mt-1 block">
              <UntrustedText value={report.data.confirm.why_not} limits={{ maxChars: 400, maxLines: 4 }} />
            </span>
          )}
        </>
      }
      request={{ method: "POST", path: `/api/v1/cases/${detail.case.id}/report/confirm`, body: { expected_version: version } }}
      confirmLabel="Send to Kibana"
      onSent={() => {
        announce(`Incident #${detail.case.number}'s report is confirmed: it goes to Kibana.`, "ok");
        void changedReport(queries, detail.case.id);
      }}
    />
  );
}

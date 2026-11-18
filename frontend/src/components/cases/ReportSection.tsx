import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useId, useMemo, useRef, useState, type ReactNode } from "react";
import type { CaseReportOut, IncidentReport, ReportDecided, ReportEvidenceLine, ReportFact, ReportQuery } from "../../client/types.gen";
import { useAnnounce } from "../../lib/announce";
import { count, plural } from "../../lib/format";
import { useGuard } from "../../lib/guard";
import {
  confidenceText,
  confirmBody,
  dayLabel,
  FILE_KINDS,
  HYPOTHESIS_TONE,
  HYPOTHESIS_WORDS,
  rejectBody,
  rejectProblem,
  reportHeadline,
  safeLink,
  STANDING_TITLE,
  STANDING_TONE,
} from "../../lib/incident";
import { OUTCOME_KEYS, OUTCOMES } from "../../lib/labels";
import { caseReportOptions, changedReport } from "../../lib/queries";
import { ConfirmDialog } from "../ConfirmDialog";
import { Loading, Problem } from "../Problem";
import { Time } from "../Time";
import { UntrustedText } from "../UntrustedText";
import { Badge } from "../ui/badge";
import { Button } from "../ui/button";
import { Field, Select, TextArea } from "../ui/field";
import { plainWords } from "../../lib/plainWords";
import { BriefBlock } from "../incident/Brief";
import { DataTable } from "../ui/table";
import { zoneLabel } from "../../lib/site";

const CASE_TITLE = "case-title";

function Text({ value, max = 600, lines = 6 }: { value: string; max?: number; lines?: number }) {
  return <UntrustedText value={plainWords(value)} limits={{ maxChars: max, maxLines: lines }} />;
}

/** One part of the report: the heading is always there, the body opens and closes. */
function Part({ title, hint, open = false, children }: { title: string; hint?: string; open?: boolean; children: ReactNode }) {
  return (
    <details open={open} className="rounded-card bg-surface p-3">
      <summary className="cursor-pointer text-base font-semibold">{title}</summary>
      <div className="mt-2 flex flex-col gap-2">
        {hint && <p className="m-0 max-w-prose text-sm text-muted">{hint}</p>}
        {children}
      </div>
    </details>
  );
}

function Sentences({ items }: { items: readonly { text: string }[] }) {
  return (
    <ul className="m-0 flex list-none flex-col gap-1 p-0">
      {items.map((s, i) => (
        <li key={i} className="max-w-prose text-sm">
          <Text value={s.text} max={700} lines={4} />
        </li>
      ))}
    </ul>
  );
}

// ------------------------------------------------------------------ the top of the report

function Head({ data, onVersion, incidentId }: { data: CaseReportOut; onVersion: (v: number | null) => void; incidentId: string | null }) {
  const report = data.report as IncidentReport;
  const id = useId();
  return (
    <div className="flex flex-col gap-2">
      <p className="m-0 flex flex-wrap items-center gap-x-2 gap-y-1 text-sm">
        <strong data-testid="incident-id">{incidentId ?? report.header.incident_id}</strong>
        <span>
          · version {data.version} of {data.newest}, written <Time value={data.generated_at} />
        </span>
        {data.prose_by && <Badge tone="info">Summary worded by a model, checked by ARGUS</Badge>}
        {data.stale && <Badge tone="warn">The case changed: ARGUS writes a new version in its next pass</Badge>}
        {data.version !== data.newest && <Badge tone="warn">An older version</Badge>}
      </p>
      {data.versions.length > 1 && (
        <div className="flex flex-col gap-1 text-sm">
          <p id={id} className="m-0">
            Latest (v{data.newest}) · History:
          </p>
          <ul className="m-0 flex list-none flex-wrap gap-1 p-0" aria-labelledby={id} data-testid="report-versions">
            {data.versions.map((v) => (
              <li key={v.version}>
                <Button size="sm" variant={v.version === data.version ? "primary" : "secondary"} aria-pressed={v.version === data.version} onClick={() => onVersion(v.version === data.newest ? null : v.version)}>
                  v{v.version}
                  {v.decision ? ` · ${v.decision}` : ""}
                </Button>
              </li>
            ))}
          </ul>
        </div>
      )}
      <ul className="m-0 flex list-none flex-wrap items-center gap-x-4 gap-y-1 p-0 text-sm" aria-label="Files">
        {data.files.map((f) => (
          <li key={f.kind}>
            {f.available ? (
              <a href={f.url} download>
                {f.name}
              </a>
            ) : (
              <span className="text-muted" title="It says what the logs said: it needs log access in ELK.">
                {f.name} (needs log access)
              </span>
            )}{" "}
            <span className="text-muted">{FILE_KINDS[f.kind]}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

function SummaryBlock({ report, state }: { report: IncidentReport; state: string }) {
  const s = report.summary;
  const v = report.verdict;
  const words = s.prose.length > 0 ? s.prose : s.sentences;
  return (
    <div className="flex flex-col gap-2" aria-label="Report summary" role="group">
      <p className="m-0 text-base font-semibold" data-testid="report-headline">
        {reportHeadline(state, v.outcome, confidenceText(v.confidence, v.confidence_words))}
      </p>
      <p className="m-0 flex flex-wrap items-center gap-2 text-sm">
        <Badge tone={STANDING_TONE[s.standing]}>{STANDING_TITLE[s.standing]}</Badge>
        <span>{s.standing_words}</span>
      </p>
      <Sentences items={words} />
      {s.notice && (
        <p className="m-0 max-w-prose rounded-control border border-info/40 bg-info-soft px-3 py-2 text-sm text-info" data-testid="report-notice">
          <strong>Owner notified.</strong> <Text value={s.notice.line} max={500} lines={4} />
        </p>
      )}
      {s.prose_note && <p className="m-0 text-xs text-muted">{s.prose_note}</p>}
    </div>
  );
}

function VerdictBlock({ report }: { report: IncidentReport }) {
  const v = report.verdict;
  const sure = confidenceText(v.confidence, v.confidence_words);
  const basis = v.sentences.slice(1);
  return (
    <div className="flex flex-col gap-1" aria-label="ARGUS's call" role="group">
      <p className="m-0 flex flex-wrap items-center gap-2 text-sm" data-testid="verdict-line">
        <strong>ARGUS&apos;s call:</strong>
        <Badge tone={v.outcome === "true_positive" ? "high" : v.outcome === null ? "neutral" : "ok"}>{v.outcome ? OUTCOMES[v.outcome] : "No call yet"}</Badge>
        {sure && <span>confidence {sure}</span>}
        <span className="text-muted">
          from {v.source}
          {v.kind === "reading" ? " (a reading, not a proposal)" : ""}
        </span>
      </p>
      {basis.length > 0 && <Sentences items={basis} />}
    </div>
  );
}

// ------------------------------------------------------------------ the decision

function useFinish(caseId: string) {
  const queries = useQueryClient();
  const { announce } = useAnnounce();
  const done = useRef(false);
  return {
    sent: () => {
      done.current = true;
    },
    focus: () => {
      if (!done.current) return null;
      done.current = false;
      return document.getElementById(CASE_TITLE);
    },
    finish: async (say: string) => {
      announce(say, "ok");
      await changedReport(queries, caseId);
    },
    reload: () => changedReport(queries, caseId),
  };
}

type Asking = "confirm" | "reject" | null;

function Decision({ data }: { data: CaseReportOut }) {
  const id = useId();
  const after = useFinish(data.case_id);
  const version = data.version ?? 0;
  const verdict = (data.report as IncidentReport).verdict;
  const [form, setForm] = useState(false); // the reject form is open
  const [asking, setAsking] = useState<Asking>(null); // the dialog showing the exact request
  const [outcome, setOutcome] = useState("");
  const [reason, setReason] = useState("");
  // the version read when the request was shown: a new version under an open dialog changes
  // nothing the person read, and the server answers 409 if it is not the newest (D-186's rule)
  const [saw, setSaw] = useState<number | null>(null);
  const confirmGuard = useGuard(data.confirm.enabled ? null : (data.confirm.why_not ?? "Not available."));
  const rejectGuard = useGuard(data.reject.enabled ? rejectProblem(outcome, reason) : (data.reject.why_not ?? "Not available."));
  const confirmRequest = useMemo(() => ({ method: "POST" as const, path: `/api/v1/cases/${data.case_id}/report/confirm`, body: confirmBody(saw ?? version) }), [data.case_id, saw, version]);
  const rejectRequest = useMemo(() => ({ method: "POST" as const, path: `/api/v1/cases/${data.case_id}/report/reject`, body: rejectBody(saw ?? version, outcome, reason) }), [data.case_id, saw, version, outcome, reason]);
  const d = data.decision;
  const closed = (next: boolean) => {
    if (!next) {
      setAsking(null);
      setSaw(null);
      void after.reload();
    }
  };
  const said = (sent: { data?: unknown }) => {
    const out = sent.data as ReportDecided | undefined;
    after.sent();
    setForm(false);
    setReason("");
    setOutcome("");
    void after.finish(out?.words ?? "Recorded.");
  };
  return (
    <div className="flex flex-col gap-2 rounded-card bg-surface-2 p-3" aria-label="Your decision" role="group" data-testid="decision">
      <p className="m-0 text-sm font-medium">Your decision</p>
      {d && (
        <p className="m-0 max-w-prose text-sm" data-testid="decision-line">
          {d.decision === "confirmed" ? "Confirmed" : "Rejected"} by <Text value={d.by} max={80} lines={1} /> on <Time value={d.decided_at} />
          {d.outcome && ` as “${OUTCOMES[d.outcome]}”`}; {count(d.labelled)} {plural(d.labelled, "investigation")} labelled.
          {d.held_from != null && ` Made on version ${d.held_from}; it still holds: since then only the case's name or the sign-in accounts changed.`}
          {d.reason && (
            <>
              {" "}
              Reason: <Text value={d.reason} max={600} lines={6} />
            </>
          )}
        </p>
      )}
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <Button
          variant="primary"
          {...confirmGuard.props}
          onClick={confirmGuard.press(() => {
            setSaw(version);
            setAsking("confirm");
          })}
        >
          Confirm the verdict
        </Button>
        <Button variant="secondary" aria-expanded={form} aria-disabled={!data.reject.enabled} aria-describedby={data.reject.enabled ? undefined : `${id}-why`} onClick={() => data.reject.enabled && setForm((now) => !now)}>
          Reject with a reason…
        </Button>
        {confirmGuard.hint}
      </div>
      {!data.reject.enabled && data.reject.why_not && (
        <p id={`${id}-why`} className="m-0 text-sm text-muted">
          {data.reject.why_not}
        </p>
      )}
      <p className="m-0 max-w-prose text-xs text-muted">Both are labels ARGUS learns from, saved on the case&apos;s investigations. Neither closes the case: that stays a person&apos;s approval.</p>
      {form && data.reject.enabled && (
        <div className="flex flex-col gap-2 rounded-card bg-surface p-3">
          <Field label="What it is instead" htmlFor={`${id}-outcome`}>
            <Select id={`${id}-outcome`} value={outcome} onChange={(e) => setOutcome(e.target.value)} className="max-w-72">
              <option value="">Choose…</option>
              {OUTCOME_KEYS.filter((k) => k !== verdict.outcome || verdict.kind === "reading").map((k) => (
                <option key={k} value={k}>
                  {OUTCOMES[k]}
                </option>
              ))}
            </Select>
          </Field>
          <Field label="Why the report is wrong" hint="saved as the note of each label" htmlFor={`${id}-reason`}>
            <TextArea id={`${id}-reason`} value={reason} maxLength={4000} onChange={(e) => setReason(e.target.value)} />
          </Field>
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
            <Button
              variant="primary"
              {...rejectGuard.props}
              onClick={rejectGuard.press(() => {
                setSaw(version);
                setAsking("reject");
              })}
            >
              Review the request
            </Button>
            {rejectGuard.hint}
          </div>
        </div>
      )}
      <ConfirmDialog
        open={asking === "confirm"}
        onOpenChange={closed}
        title={`Confirm the report's verdict for case ${data.case_number}`}
        description="ARGUS labels the case's investigations with the verdict (what it learns from) and keeps any investigation a person reviewed otherwise. Nothing is closed."
        request={confirmRequest}
        confirmLabel="Confirm the verdict"
        finalFocus={after.focus}
        onSent={said}
      />
      <ConfirmDialog
        open={asking === "reject"}
        onOpenChange={closed}
        title={`Reject the report's verdict for case ${data.case_number}`}
        description="Your reason is saved as the note of the review (the label) of each of the case's investigations, so ARGUS learns from it. Nothing is closed."
        request={rejectRequest}
        confirmLabel="Reject with this reason"
        finalFocus={after.focus}
        onSent={said}
      />
    </div>
  );
}

// ------------------------------------------------------------------ the parts

function Timeline({ report }: { report: IncidentReport }) {
  const t = report.timeline;
  const columns = [
    { key: "day", header: `Date (${zoneLabel()})`, cell: (d: (typeof t.days)[number]) => dayLabel(d.day) },
    ...t.columns.map((name, i) => ({ key: `c${i}`, header: <Text value={name} max={80} lines={1} />, numeric: true, cell: (d: (typeof t.days)[number]) => (d.counts[i] ? count(d.counts[i]) : "–") })),
    { key: "total", header: "Total", numeric: true, cell: (d: (typeof t.days)[number]) => count(d.total) },
  ];
  return (
    <>
      <p className="m-0 text-sm">
        {t.first_seen && t.last_seen ? (
          <>
            First seen <Time value={t.first_seen} />, last seen <Time value={t.last_seen} />
            {t.dwell_words && <>; dwell time {t.dwell_words}</>}.
          </>
        ) : (
          "No alert time is known."
        )}
      </p>
      <DataTable caption={`Alerts a day by rule (${zoneLabel()})`} columns={columns} rows={t.days} rowKey={(d) => d.day} empty="No alert has a time." />
      <Sentences items={[...t.phases.map((p) => p.sentence), ...t.notes]} />
    </>
  );
}

function Actors({ report }: { report: IncidentReport }) {
  return (
    <>
      <DataTable
        caption="Actors and their roles"
        rows={report.actors}
        rowKey={(a) => a.value}
        empty="The case names no actor."
        columns={[
          { key: "who", header: "Actor", cell: (a) => <Text value={a.value} max={120} lines={1} /> },
          { key: "role", header: "Role", cell: (a) => <Badge>{a.role}</Badge> },
          { key: "net", header: "Network / country", cell: (a) => (a.network || a.country ? <Text value={[a.network, a.country].filter(Boolean).join(" / ")} max={160} lines={2} /> : "–") },
          { key: "ua", header: "User agents", cell: (a) => (a.user_agents.length ? a.user_agents.map((u, i) => <div key={i}><Text value={u} max={200} lines={2} /></div>) : "–") },
          { key: "alerts", header: "Alerts", numeric: true, cell: (a) => count(a.alerts) },
        ]}
      />
      <ul className="m-0 flex list-none flex-col gap-1 p-0">
        {report.actors.map((a) => (
          <li key={a.value} className="max-w-prose text-sm text-muted">
            <Text value={`${a.value}: ${a.role_words}`} max={400} lines={3} />
          </li>
        ))}
      </ul>
    </>
  );
}

function Assets({ report }: { report: IncidentReport }) {
  return (
    <>
      {report.assets_total > report.assets.length && <p className="m-0 text-sm text-muted">{count(report.assets.length)} of {count(report.assets_total)} are listed; the affected-devices file has the devices.</p>}
      <DataTable
        caption="Affected assets"
        rows={report.assets}
        rowKey={(a, i) => `${a.kind}-${a.value}-${i}`}
        empty="The case names no affected asset."
        columns={[
          { key: "kind", header: "Kind", cell: (a) => a.kind },
          { key: "value", header: "Asset", cell: (a) => <Text value={a.value} max={160} lines={1} /> },
          { key: "label", header: "Reached / where", cell: (a) => (a.label ? <Text value={a.label} max={160} lines={1} /> : "–") },
          { key: "alerts", header: "Alerts", numeric: true, cell: (a) => count(a.alerts) },
          { key: "days", header: "Days", numeric: true, cell: (a) => (a.days ? count(a.days) : "–") },
          { key: "last", header: "Last seen", cell: (a) => (a.last_seen ? <Time value={a.last_seen} /> : "–") },
        ]}
      />
    </>
  );
}

/**
 * The accounts that signed in from the affected devices (AR6, D-216): a lead, not proof. The server
 * sends the accounts only to an account that may read the logs; they are untrusted text.
 */
function Accounts({ report }: { report: IncidentReport }) {
  const users = report.users;
  if (users.devices.length === 0) return null;
  const named = users.devices.flatMap((d) => d.accounts.map((a) => ({ ...a, state: d.state })));
  return (
    <section aria-label="Accounts that signed in from the affected devices" className="flex flex-col gap-1.5">
      <h4 className="m-0 text-sm font-semibold">Accounts that signed in from the affected devices</h4>
      <p className="m-0 max-w-prose text-sm text-muted">{users.lead}</p>
      {named.length > 0 && (
        <DataTable
          reachable
          caption="Accounts that signed in from the affected devices"
          rows={named}
          rowKey={(a, i) => `${a.device}-${a.name}-${i}`}
          columns={[
            { key: "name", header: "Account", cell: (a) => <Text value={a.name} max={120} lines={1} /> },
            { key: "device", header: "Device", cell: (a) => <Text value={a.device} max={60} lines={1} /> },
            { key: "state", header: "State", cell: (a) => a.state.replace("_", " ") },
            { key: "n", header: "Sign-ins", numeric: true, cell: (a) => count(a.signins) },
            { key: "first", header: "First", cell: (a) => <Time value={a.first_seen} /> },
            { key: "last", header: "Last", cell: (a) => <Time value={a.last_seen} /> },
            { key: "browser", header: "Browser", cell: (a) => <Text value={a.browsers.join("; ") || "unknown browser"} max={160} lines={2} /> },
          ]}
        />
      )}
      <ul className="m-0 flex list-none flex-col gap-0.5 p-0 text-sm text-muted">
        {users.devices
          .filter((d) => d.accounts.length === 0)
          .map((d) => (
            <li key={d.device}>
              <Text value={d.sentence.text} max={400} lines={3} />
            </li>
          ))}
      </ul>
    </section>
  );
}

function Query({ q }: { q: ReportQuery }) {
  const link = safeLink(q.url);
  return (
    <div className="flex flex-col gap-1">
      <p className="m-0 text-xs text-muted">
        {q.language === "kql" ? "KQL" : "ES|QL"} on <Text value={q.index} max={120} lines={1} />, <Time value={q.time_from} /> to <Time value={q.time_to} />
      </p>
      <UntrustedText value={q.text} block limits={{ maxChars: 2000, maxLines: 12 }} className="rounded-control bg-surface-2 p-2 font-mono text-xs" />
      {link ? (
        <a href={link} target="_blank" rel="noopener noreferrer" className="text-sm">
          Open this query in Kibana Discover (read-only, a new tab)
        </a>
      ) : (
        <span className="text-sm text-muted">No link is available for this query.</span>
      )}
    </div>
  );
}

function Evidence({ report }: { report: IncidentReport }) {
  const facts = new Map<string, ReportFact>(report.facts.map((f) => [f.id, f]));
  return (
    <ol className="m-0 flex list-none flex-col gap-3 p-0" aria-label="Evidence">
      {report.evidence.map((e: ReportEvidenceLine) => (
        <li key={e.id} className="flex flex-col gap-1 border-b border-border pb-3 last:border-b-0" data-testid="evidence-line">
          <p className="m-0 text-sm">
            <strong>{e.id}</strong> · {e.title}
          </p>
          <p className="m-0 max-w-prose text-sm">
            <Text value={facts.get(e.fact)?.text ?? ""} max={700} lines={4} />
          </p>
          <p className="m-0 text-xs text-muted">
            Source: {e.source}. Check {e.query.template}
            {e.at && (
              <>
                , run <Time value={e.at} />
              </>
            )}
            . Status: {e.status}.
          </p>
          <Query q={e.query} />
        </li>
      ))}
    </ol>
  );
}

function Hypotheses({ report }: { report: IncidentReport }) {
  return (
    <ul className="m-0 flex list-none flex-col gap-3 p-0" aria-label="Hypotheses">
      {report.hypotheses.map((h, i) => (
        <li key={i} className="flex flex-col gap-1" data-testid="hypothesis">
          <p className="m-0 flex flex-wrap items-center gap-2 text-sm font-medium">
            <Badge tone={HYPOTHESIS_TONE[h.status]}>{HYPOTHESIS_WORDS[h.status]}</Badge>
            <Text value={h.name} max={300} lines={2} />
            {h.by === "investigator" && <span className="text-xs font-normal text-muted">(weighed by the AI investigator)</span>}
          </p>
          <Sentences items={h.why} />
        </li>
      ))}
    </ul>
  );
}

function Indicators({ report }: { report: IncidentReport }) {
  return (
    <>
      <p className="m-0 text-sm text-muted">
        {count(report.indicators_total)} {plural(report.indicators_total, "indicator")}, the case&apos;s own. The indicators file lists them for a block list.
      </p>
      <DataTable
        caption="Indicators"
        rows={report.indicators}
        rowKey={(i) => `${i.kind}-${i.value}`}
        empty="The case holds no indicator."
        columns={[
          { key: "value", header: "Indicator", cell: (i) => <Text value={i.value} max={200} lines={1} /> },
          { key: "kind", header: "Type", cell: (i) => i.kind },
          { key: "role", header: "Role", cell: (i) => i.role_words },
          { key: "evidence", header: "Evidence", cell: (i) => <Text value={i.evidence} max={500} lines={4} /> },
        ]}
      />
    </>
  );
}

function Actions({ report }: { report: IncidentReport }) {
  const a = report.actions;
  return (
    <>
      <DataTable
        caption="Recommended actions"
        rows={a.lines}
        rowKey={(l) => l.id}
        empty={a.note ?? "No action applies yet."}
        columns={[
          { key: "title", header: "Action", cell: (l) => (<><strong>{l.title}.</strong> <Text value={l.say} max={400} lines={4} /></>) },
          { key: "owner", header: "Owner", cell: (l) => l.owner },
          { key: "state", header: "Status", cell: (l) => l.state.replaceAll("_", " ") },
        ]}
      />
      {a.close_when && <Sentences items={[a.close_when]} />}
    </>
  );
}

function Queries({ report }: { report: IncidentReport }) {
  return (
    <ul className="m-0 flex list-none flex-col gap-3 p-0" aria-label="Queries to verify">
      {report.queries.map((q, i) => (
        <li key={i}>
          <p className="m-0 text-sm font-medium">{q.template}</p>
          <Query q={q} />
        </li>
      ))}
    </ul>
  );
}

function Limits({ report }: { report: IncidentReport }) {
  return (
    <>
      <Sentences items={report.out_of_scope} />
      {report.meta.limits.length > 0 && (
        <ul className="m-0 flex list-none flex-col gap-1 p-0 text-sm text-muted">
          {report.meta.limits.map((l, i) => (
            <li key={i}>Limit: {l}.</li>
          ))}
        </ul>
      )}
    </>
  );
}

// ------------------------------------------------------------------ the section

/**
 * The incident report of a case (AR7, D-190): what the security team writes by hand, written by ARGUS
 * from its own database: the summary and ARGUS's verdict first, your decision (Confirm, or Reject
 * with a reason: both are labels, neither closes anything), then each part, every evidence line
 * with the exact query behind it and a read-only Discover link, and the files.
 */
export function ReportSection({ caseId, incidentId = null }: { caseId: string; incidentId?: string | null }) {
  const [version, setVersion] = useState<number | null>(null);
  const found = useQuery(caseReportOptions(caseId, version));
  return (
    <section aria-label="Report" id="report" className="flex flex-col gap-3 scroll-mt-4" aria-busy={found.isFetching}>
      <h2 className="m-0 text-lg font-semibold">Report</h2>
      {found.isPending && <Loading what="the report" />}
      {found.isError && <Problem error={found.error} what="The report" onRetry={() => void found.refetch()} />}
      {found.isSuccess && <Body data={found.data} onVersion={setVersion} incidentId={incidentId} />}
    </section>
  );
}

function Body({ data, onVersion, incidentId }: { data: CaseReportOut; onVersion: (v: number | null) => void; incidentId: string | null }) {
  const report = data.report;
  if (report === null || report === undefined) {
    return (
      <p className="m-0 max-w-prose text-sm text-muted" data-testid="no-report">
        {data.note}
      </p>
    );
  }
  return (
    <>
      <Head data={data} onVersion={onVersion} incidentId={incidentId} />
      {data.logs_hidden && <p className="m-0 max-w-prose text-sm text-muted">Your account may not read the logs, so what the logs said is hidden here and in the PDF.</p>}
      <BriefBlock report={report} />
      <SummaryBlock report={report} state={data.case_state} />
      <VerdictBlock report={report} />
      <Decision key={`${data.case_id}-${data.version}`} data={data} />
      <Part title="Timeline" hint={`Alerts a day, ${zoneLabel()}; each phase is one rule's alerts.`}>
        <Timeline report={report} />
      </Part>
      <Part title="Actors and roles">
        <Actors report={report} />
      </Part>
      <Part title="Affected assets">
        <Assets report={report} />
        <Accounts report={report} />
      </Part>
      <Part title="Evidence" open hint="Each line is something ARGUS checked, with the exact query behind it, so you can check it in one click.">
        <Evidence report={report} />
      </Part>
      <Part title="Hypotheses" open hint="What ARGUS considered, and why each was kept or ruled out.">
        <Hypotheses report={report} />
      </Part>
      <Part title="Indicators">
        <Indicators report={report} />
      </Part>
      <Part title="Recommended actions" open hint="From the responder's catalogue, with the owner of each. Advice only: nothing here is done by ARGUS.">
        <Actions report={report} />
      </Part>
      <Part title="Queries to verify" hint="Read-only. Open one in Discover and set the time range if you want a different one.">
        <Queries report={report} />
      </Part>
      <Part title="Scope and limits">
        <Limits report={report} />
      </Part>
    </>
  );
}

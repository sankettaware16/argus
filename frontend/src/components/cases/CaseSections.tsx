import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { addCaseNote, addEntityNote } from "../../client/sdk.gen";
import type { ApprovalOut, CaseDetail, CaseIndicatorOut, FindingOut, MirrorOut } from "../../client/types.gen";
import { unwrap } from "../../lib/call";
import { APPROVAL_STATUS_TONE, APPROVAL_STATUS_WORDS, CASE_STATE_MEANING, caseStateWord } from "../../lib/cases";
import { count, plural } from "../../lib/format";
import { optionText } from "../../lib/optionText";
import { changedCase, reportsOptions } from "../../lib/queries";
import { StateChip } from "../chips";
import { Evidence, Hypotheses, Unknowns } from "../investigation/ReportView";
import { Loading, Problem } from "../Problem";
import { Time } from "../Time";
import { UntrustedText } from "../UntrustedText";
import { Badge } from "../ui/badge";
import { DataTable } from "../ui/table";
import { CheckMore } from "../investigation/CheckMore";
import { NoteForm } from "./NoteForm";
import { useCan, NeedsCapability } from "../investigation/actions";
import { CaseStateBadge } from "./CaseBits";
import { SuggestionsBlock, WatchBlock } from "./WatchBits";

function Section({ id, title, children, hint }: { id: string; title: string; children: React.ReactNode; hint?: string }) {
  return (
    <section aria-label={title} id={id} className="flex flex-col gap-2 scroll-mt-4">
      <h2 className="m-0 text-lg font-semibold">{title}</h2>
      {hint && <p className="m-0 max-w-prose text-sm text-muted">{hint}</p>}
      {children}
    </section>
  );
}

function Text({ value, max = 600, lines = 6 }: { value: string; max?: number; lines?: number }) {
  return <UntrustedText value={value} limits={{ maxChars: max, maxLines: lines }} />;
}

// ------------------------------------------------------------------ summary

export function SummarySection({ detail }: { detail: CaseDetail }) {
  const c = detail.case;
  const s = detail.summary;
  return (
    <Section id="summary" title="Summary">
      <div className="flex flex-wrap items-center gap-2">
        <CaseStateBadge state={c.state} />
        <Badge tone={c.severity === "critical" ? "critical" : c.severity === "high" ? "high" : c.severity === "medium" ? "medium" : "low"}>{c.severity}</Badge>
        {c.in_kibana ? <Badge tone="info">In Kibana</Badge> : <Badge>Not in Kibana</Badge>}
        {c.waiting_for_approval > 0 && (
          <Link to="/approvals" className="no-underline">
            <Badge tone="warn">
              {c.waiting_for_approval} {plural(c.waiting_for_approval, "request")} waiting for an approver
            </Badge>
          </Link>
        )}
      </div>
      <p className="m-0 text-sm">
        {caseStateWord(c.state)}: {CASE_STATE_MEANING[c.state]}{" "}
        {c.owner && (
          <>
            Owner: <Text value={c.owner.display_name} max={80} lines={1} />.{" "}
          </>
        )}
        {detail.cause_words}
      </p>
      <p className="m-0 text-sm">
        {count(s.investigations)} {plural(s.investigations, "investigation")}, {count(s.alerts)} {plural(s.alerts, "alert")}
        {s.first_alert_at && s.last_alert_at && (
          <>
            , from <Time value={s.first_alert_at} /> to <Time value={s.last_alert_at} />
          </>
        )}
        . A person has reviewed {count(s.reviewed)} of them; {count(s.unreviewed)} {s.unreviewed === 1 ? "has" : "have"} not been reviewed (or changed since).
      </p>
      {s.rules.length > 0 && (
        <p className="m-0 text-sm">
          Rules:{" "}
          {s.rules.map((r, i) => (
            <span key={i}>
              {i > 0 && "; "}
              <Text value={r.rule_name ?? "(no rule name)"} max={120} lines={1} /> ({count(r.investigations)} {plural(r.investigations, "investigation")}, {count(r.alerts)} {plural(r.alerts, "alert")})
            </span>
          ))}
          {s.rules_total > s.rules.length && ` and ${s.rules_total - s.rules.length} more`}.
        </p>
      )}
      {c.state === "suspected" && (
        <p className="m-0 text-sm">
          {c.cause === "raised"
            ? "ARGUS suggested it from evidence across investigations. A person confirms it with the case command (argus case confirm) or dismisses it (argus case dismiss); a verdict on one of its investigations is recorded but does not confirm it."
            : "To confirm it, review one of its investigations as a true positive (open it under Members); a case that is not real is merged into another or left to ARGUS."}
        </p>
      )}
      {(c.attention || c.kibana_wait) && (
        <ul className="m-0 flex list-none flex-col gap-1 p-0">
          {c.attention && (
            <li className="rounded-control border border-warn/40 bg-warn-soft px-3 py-2 text-sm text-warn">
              <strong>Needs a person.</strong> <Text value={c.attention} max={500} lines={4} />
            </li>
          )}
          {c.kibana_wait && (
            <li className="rounded-control border border-info/40 bg-info-soft px-3 py-2 text-sm text-info">
              <strong>Kibana.</strong> <Text value={c.kibana_wait} max={500} lines={4} />
            </li>
          )}
        </ul>
      )}
      {c.merged_into && (
        <p className="m-0 text-sm">
          Merged into{" "}
          <Link to="/cases/$id" params={{ id: c.merged_into.id }}>
            case {c.merged_into.number}
          </Link>
          .
        </p>
      )}
      {detail.parent && (
        <p className="m-0 text-sm">
          This case follows activity after{" "}
          <Link to="/cases/$id" params={{ id: detail.parent.id }}>
            case {detail.parent.number}
          </Link>{" "}
          was closed.
        </p>
      )}
      {detail.children.length > 0 && (
        <p className="m-0 text-sm">
          New activity after closing was made into:{" "}
          {detail.children.map((k, i) => (
            <span key={k.id}>
              {i > 0 && ", "}
              <Link to="/cases/$id" params={{ id: k.id }}>
                case {k.number}
              </Link>
            </span>
          ))}
          {detail.children_total > detail.children.length && ` and ${count(detail.children_total - detail.children.length)} more`}
          .
        </p>
      )}
    </Section>
  );
}

// ------------------------------------------------------------------ what's new, timeline

export function WhatsNewSection({ detail }: { detail: CaseDetail }) {
  const w = detail.whats_new;
  return (
    <Section id="whats-new" title="What's new" hint={w.first_visit ? "You have not seen this case before: here is what happened in the last two days." : undefined}>
      {w.items.length === 0 ? (
        <p className="m-0 text-sm text-muted">
          Nothing changed since your last visit (<Time value={w.since} />).
        </p>
      ) : (
        <>
          <p className="m-0 text-sm text-muted">
            Since <Time value={w.since} />, by others and by ARGUS:
          </p>
          <ul className="m-0 flex list-none flex-col gap-1 p-0 text-sm">
            {w.items.map((i, n) => (
              <li key={n} className="grid grid-cols-[minmax(8rem,12rem)_1fr] gap-x-3">
                <span className="text-muted">
                  <Time value={i.at} />
                </span>
                <span>
                  {i.by && (
                    <>
                      <Text value={i.by} max={80} lines={1} />{" "}
                    </>
                  )}
                  <Text value={i.text} />
                  {i.investigation_id && (
                    <>
                      {" "}
                      <Link to="/investigations/$id" params={{ id: i.investigation_id }}>
                        open
                      </Link>
                    </>
                  )}
                </span>
              </li>
            ))}
          </ul>
        </>
      )}
    </Section>
  );
}

const TIMELINE_WORD = { case: "Case", alerts: "Alerts", verdict: "Verdict", check: "Check", kibana: "Kibana", signin: "Sign-in (context)" } as const;

export function TimelineSection({ detail }: { detail: CaseDetail }) {
  return (
    <Section id="timeline" title="Timeline" hint="What happened, oldest first: alerts, people's verdicts, checks, and the case's own turning points. Sign-ins from the devices are context.">
      {detail.timeline.length === 0 ? (
        <p className="m-0 text-sm text-muted">Nothing with a time yet.</p>
      ) : (
        <>
          {detail.timeline_total > detail.timeline.length && (
            <p className="m-0 text-sm text-muted">
              {count(detail.timeline_total - detail.timeline.length)} older items are not shown (the newest {count(detail.timeline.length)} are).
            </p>
          )}
          <ol className="m-0 flex list-none flex-col gap-1.5 p-0 text-sm">
            {detail.timeline.map((t, i) => (
              <li key={i} className="grid grid-cols-[minmax(8rem,12rem)_1fr] gap-x-3">
                <span className="text-muted">
                  <Time value={t.at} />
                  {t.until && (
                    <>
                      {" "}
                      to <Time value={t.until} />
                    </>
                  )}
                </span>
                <span>
                  <Badge className="mr-1.5">{TIMELINE_WORD[t.kind]}</Badge>
                  {t.by && (
                    <>
                      <Text value={t.by} max={80} lines={1} />{" "}
                    </>
                  )}
                  <Text value={t.text} />
                  {t.investigation_id && (
                    <>
                      {" "}
                      <Link to="/investigations/$id" params={{ id: t.investigation_id }}>
                        open
                      </Link>
                    </>
                  )}
                </span>
              </li>
            ))}
          </ol>
        </>
      )}
    </Section>
  );
}

// ------------------------------------------------------------------ evidence, hypotheses, unknowns

/** The lead investigation's report: its evidence, hypotheses and what is still unknown. */
export function LeadReportSections({ detail }: { detail: CaseDetail }) {
  const lead = detail.lead_investigation_id;
  const reports = useQuery({ ...reportsOptions(lead ?? ""), enabled: lead !== null });
  const first = reports.data?.items[0];
  const from = detail.investigations.find((i) => i.investigation_id === lead);
  const why = (
    <p className="m-0 max-w-prose text-sm text-muted">
      From the lead investigation
      {from && (
        <>
          : <Text value={from.rule_name ?? "(no rule name)"} max={120} lines={1} />
        </>
      )}
      {lead && (
        <>
          {" "}
          (the most severe and newest;{" "}
          <Link to="/investigations/$id" params={{ id: lead }} search={{ tab: "report" }}>
            its whole report
          </Link>
          ). The other {Math.max(detail.investigations_total - 1, 0)} {detail.investigations_total === 2 ? "investigation has" : "investigations have"} their own reports.
        </>
      )}
    </p>
  );
  const body = (render: (r: NonNullable<typeof first>) => React.ReactNode) =>
    lead === null ? (
      <p className="m-0 text-sm text-muted">The case has no investigation yet.</p>
    ) : reports.isPending ? (
      <Loading what="the lead report" />
    ) : reports.isError ? (
      <Problem error={reports.error} what="The lead report" onRetry={() => void reports.refetch()} />
    ) : first ? (
      render(first)
    ) : (
      <p className="m-0 text-sm text-muted">No report yet: ARGUS has not built the lead investigation&apos;s dossier.</p>
    );
  return (
    <>
      <Section id="evidence" title="Evidence">
        {why}
        {reports.data?.logs_hidden && <p className="m-0 text-sm text-muted">Your account cannot read the logs in ELK, so what the logs said is hidden.</p>}
        {body((r) => <Evidence report={r} bare />)}
      </Section>
      <Section id="hypotheses" title="Hypotheses">
        {body((r) => <Hypotheses report={r} bare />)}
      </Section>
      <Section id="unknowns" title="Unknowns">
        {body((r) => <Unknowns report={r} bare />)}
      </Section>
    </>
  );
}

// ------------------------------------------------------------------ approvals of this case

export function CaseApprovals({ detail }: { detail: CaseDetail }) {
  const items: ApprovalOut[] = detail.approvals;
  return (
    <Section id="approvals" title="Approvals" hint="Requests to close or merge this case. An approver decides them in the approvals queue.">
      {items.length === 0 ? (
        <p className="m-0 text-sm text-muted">None.</p>
      ) : (
        <ul className="m-0 flex list-none flex-col gap-1 p-0 text-sm">
          {items.map((a) => (
            <li key={a.id}>
              <Badge tone={APPROVAL_STATUS_TONE[a.status] ?? "neutral"}>{APPROVAL_STATUS_WORDS[a.status] ?? a.status}</Badge> <Text value={a.words} max={200} lines={1} />: {a.status_words}. Asked <Time value={a.requested_at} />.{" "}
              {a.status === "pending" && <Link to="/approvals">Decide it</Link>}
            </li>
          ))}
          {detail.approvals_total > items.length && <li className="text-muted">{count(detail.approvals_total - items.length)} older requests are not shown.</li>}
        </ul>
      )}
    </Section>
  );
}

// ------------------------------------------------------------------ members and indicators

function IndicatorRow({ i, caseId }: { i: CaseIndicatorOut; caseId: string }) {
  const can = useCan("review");
  const queries = useQueryClient();
  const note = i.kind === "ip" || i.kind === "domain" || i.kind === "host" || i.kind === "user";
  return (
    <li className="flex flex-col gap-1 border-b border-border py-2 last:border-b-0" data-testid="indicator">
      <p className="m-0 text-sm">
        <Badge>{i.role === "c2" ? "command & control" : i.role}</Badge> <span className="font-mono"><Text value={i.value} max={300} lines={1} /></span> <span className="text-xs text-muted">({i.kind})</span>
      </p>
      {i.notes.length > 0 && (
        <ul className="m-0 flex list-none flex-col gap-1 p-0">
          {i.notes.map((n) => (
            <li key={n.id} className="rounded-control border border-dashed border-border-strong px-2 py-1 text-sm">
              <span className="text-xs text-muted">
                Note by <Text value={n.author} max={60} lines={1} />, <Time value={n.created_at} />:{" "}
              </span>
              <Text value={n.body} max={1200} lines={12} />
            </li>
          ))}
          {i.note_count > i.notes.length && <li className="text-xs text-muted">{i.note_count - i.notes.length} older notes are not shown.</li>}
        </ul>
      )}
      {note && can && (
        <details>
          <summary className="cursor-pointer text-sm font-medium">Add a note about this {i.kind}</summary>
          <div className="pt-1">
            <NoteForm
              label={`A note about ${i.kind} ${optionText(i.value, 60)}`}
              compact
              say="Saved: note added about it."
              submit={async (body) => {
                const done = await unwrap(addEntityNote({ body: { kind: i.kind as "ip" | "domain" | "host" | "user", value: i.value, body } }));
                await changedCase(queries, caseId);
                return { duplicate: done.duplicate };
              }}
            />
          </div>
        </details>
      )}
    </li>
  );
}

export function MembersSection({ detail }: { detail: CaseDetail }) {
  const lead = detail.investigations.find((i) => i.investigation_id === detail.lead_investigation_id);
  const hosts = detail.indicators.filter((i) => i.kind === "ip" || i.kind === "domain").map((i) => i.value);
  const leadVersion = lead?.version;
  return (
    <Section id="members" title="Members" hint="The investigations in this case, why each is in it, and the indicators ARGUS tracks.">
      <DataTable
        caption="Investigations in this case"
        rows={detail.investigations}
        rowKey={(r) => r.investigation_id}
        empty="No investigation is in this case."
        columns={[
          {
            key: "rule",
            header: "Investigation",
            cell: (r) => (
              <Link to="/investigations/$id" params={{ id: r.investigation_id }}>
                <Text value={r.rule_name ?? "(no rule name)"} max={120} lines={1} />
              </Link>
            ),
          },
          { key: "alerts", header: "Alerts", numeric: true, cell: (r) => count(r.alert_count) },
          { key: "severity", header: "Severity", cell: (r) => r.severity ?? "unknown" },
          { key: "state", header: "State", cell: (r) => <StateChip state={r.human_state} /> },
          {
            key: "why",
            header: "Why it is in the case",
            cell: (r) => (
              <>
                {r.link}
                {r.link_value ? <> (<Text value={r.link_value} max={120} lines={1} />)</> : null}
                <span className="block text-xs text-muted">
                  added <Time value={r.added_at} /> by <Text value={r.added_by} max={60} lines={1} />
                </span>
              </>
            ),
          },
        ]}
      />
      {detail.investigations_total > detail.investigations.length && (
        <p className="m-0 text-sm text-muted">
          {count(detail.investigations_total - detail.investigations.length)} more are not listed here; the Inbox shows every investigation.
        </p>
      )}
      <h3 className="m-0 mt-2 text-base font-semibold">Indicators</h3>
      {detail.indicators.length === 0 ? (
        <p className="m-0 text-sm text-muted">None tracked.</p>
      ) : (
        <ul className="m-0 list-none p-0" aria-label="Indicators">
          {detail.indicators.map((i) => (
            <IndicatorRow key={`${i.kind}:${i.value}`} i={i} caseId={detail.case.id} />
          ))}
        </ul>
      )}
      {detail.indicators_total > detail.indicators.length && <p className="m-0 text-sm text-muted">{count(detail.indicators_total - detail.indicators.length)} more indicators are not shown.</p>}
      <SuggestionsBlock detail={detail} />
      <WatchBlock detail={detail} />
      {detail.lead_investigation_id && lead && leadVersion !== undefined && (
        <div className="mt-2 rounded-card border border-border bg-surface-2 p-3">
          <p className="m-0 mb-2 text-sm text-muted">
            This check is about the lead investigation, <Text value={lead.rule_name ?? "(no rule name)"} max={100} lines={1} />.
          </p>
          <CheckMore investigationId={detail.lead_investigation_id} version={leadVersion} suggestions={hosts} />
        </div>
      )}
    </Section>
  );
}

// ------------------------------------------------------------------ Kibana

function Finding({ f }: { f: FindingOut }) {
  const comment = f.details.comment;
  return (
    <li className="flex flex-col gap-1 rounded-control border border-border px-3 py-2 text-sm" data-testid="finding">
      <p className="m-0">
        <Badge tone={f.severity === "alarm" ? "danger" : f.severity === "attention" ? "warn" : "neutral"}>{f.severity === "alarm" ? "Alarm" : f.severity === "attention" ? "Needs a person" : "Recorded"}</Badge> {f.words}{" "}
        <span className="text-xs text-muted">
          <Time value={f.found_at} />
          {f.resolved_at ? " (settled)" : ""}
        </span>
        {f.details.by && (
          <>
            {" "}
            by <Text value={f.details.by} max={100} lines={1} />
          </>
        )}
      </p>
      {comment !== undefined && (
        <figure className="m-0 border-l-4 border-dashed border-border-strong pl-3">
          <figcaption className="text-xs text-muted">What the person wrote in Kibana (ARGUS shows it as text, takes no instruction from it and never sends it to a model):</figcaption>
          <blockquote className="m-0">
            <Text value={comment} max={1500} lines={15} />
          </blockquote>
        </figure>
      )}
    </li>
  );
}

export function MirrorSection({ mirror }: { mirror: MirrorOut }) {
  return (
    <Section id="kibana" title="Kibana" hint="ARGUS's case is mirrored to one Kibana case; people's changes there are read back, never overwritten.">
      <p className="m-0 text-sm">
        <Badge tone={mirror.state === "mirrored" ? "ok" : mirror.state === "paused" || mirror.state === "deleted" ? "warn" : "neutral"}>{mirror.state.replaceAll("_", " ")}</Badge> <Text value={mirror.words} max={300} lines={3} />
      </p>
      {mirror.kibana_case_id && (
        <dl className="m-0 grid grid-cols-1 gap-x-6 gap-y-1 text-sm sm:grid-cols-2">
          <div>
            <dt className="text-xs text-muted">Kibana status</dt>
            <dd className="m-0"><Text value={mirror.kibana_status ?? "?"} max={40} lines={1} /></dd>
          </div>
          <div>
            <dt className="text-xs text-muted">Last read back</dt>
            <dd className="m-0"><Time value={mirror.read_at} /></dd>
          </div>
          <div>
            <dt className="text-xs text-muted">Tags</dt>
            <dd className="m-0">
              <Text value={mirror.tags.join(", ")} max={600} lines={4} />
            </dd>
          </div>
          <div>
            <dt className="text-xs text-muted">Made by</dt>
            <dd className="m-0"><Text value={mirror.created_by ?? "?"} max={60} lines={1} /></dd>
          </div>
          {mirror.paused_reason && (
            <div className="sm:col-span-2">
              <dt className="text-xs text-muted">Why ARGUS paused its writes</dt>
              <dd className="m-0"><Text value={mirror.paused_reason} max={300} lines={3} /></dd>
            </div>
          )}
        </dl>
      )}
      {mirror.writes.length > 0 && (
        <details>
          <summary className="cursor-pointer text-sm font-medium">ARGUS&apos;s writes to Kibana for this case ({count(Math.max(mirror.writes_total, mirror.writes.length))})</summary>
          {mirror.writes_total > mirror.writes.length && <p className="m-0 mt-1 text-sm text-muted">{count(mirror.writes_total - mirror.writes.length)} older writes are not shown.</p>}
          <DataTable
            reachable
            caption="Planned and sent writes to Kibana"
            rows={mirror.writes}
            rowKey={(w) => String(w.id)}
            columns={[
              { key: "v", header: "Case version", numeric: true, cell: (w) => w.case_version },
              { key: "what", header: "Write", cell: (w) => `${w.write_class} ${w.op}` },
              { key: "state", header: "State", cell: (w) => <>{w.state}{w.state_reason ? <span className="block text-xs text-muted"><Text value={w.state_reason} max={200} lines={2} /></span> : null}</> },
              { key: "sent", header: "Sent", cell: (w) => <Time value={w.sent_at} /> },
              { key: "verified", header: "Read back", cell: (w) => <Time value={w.verified_at} /> },
            ]}
          />
        </details>
      )}
      <h3 className="m-0 text-base font-semibold">What was seen in Kibana</h3>
      {mirror.findings.length === 0 ? (
        <p className="m-0 text-sm text-muted">Nothing yet.</p>
      ) : (
        <>
          <ul className="m-0 flex list-none flex-col gap-2 p-0" aria-label="What was seen in Kibana">
            {mirror.findings.map((f) => (
              <Finding key={f.id} f={f} />
            ))}
          </ul>
          {mirror.findings_total > mirror.findings.length && <p className="m-0 text-sm text-muted">{count(mirror.findings_total - mirror.findings.length)} older findings are not shown.</p>}
        </>
      )}
    </Section>
  );
}

// ------------------------------------------------------------------ notes and history

export function NotesSection({ detail }: { detail: CaseDetail }) {
  const can = useCan("review");
  const queries = useQueryClient();
  return (
    <Section id="notes" title="Notes" hint="Notes are people's words about the case. ARGUS's models never read them, and they are not sent to Kibana.">
      {can ? (
        <NoteForm
          label="Add a note to this case"
          say="Saved: note added."
          submit={async (body) => {
            const done = await unwrap(addCaseNote({ path: { case_id: detail.case.id }, body: { body } }));
            await changedCase(queries, detail.case.id);
            return { duplicate: done.duplicate };
          }}
        />
      ) : (
        <NeedsCapability what="adding a note" capability="review" />
      )}
      {detail.notes.length === 0 ? (
        <p className="m-0 text-sm text-muted">No notes yet.</p>
      ) : (
        <>
          <ul className="m-0 flex list-none flex-col gap-2 p-0" aria-label="Notes">
            {detail.notes.map((n) => (
              <li key={n.id} className="rounded-control border border-dashed border-border-strong px-3 py-2 text-sm">
                <p className="m-0 text-xs text-muted">
                  <Text value={n.author} max={60} lines={1} />, <Time value={n.created_at} />
                </p>
                <Text value={n.body} max={2000} lines={20} />
              </li>
            ))}
          </ul>
          {detail.notes_total > detail.notes.length && <p className="m-0 text-sm text-muted">{count(detail.notes_total - detail.notes.length)} older notes are not shown.</p>}
        </>
      )}
    </Section>
  );
}

export function HistorySection({ detail }: { detail: CaseDetail }) {
  return (
    <Section id="history" title="History" hint="Every change to the case and every approval, newest first: ARGUS's record.">
      <ol className="m-0 flex list-none flex-col gap-1.5 p-0 text-sm" aria-label="History">
        {detail.history.map((h, i) => (
          <li key={i} className="grid grid-cols-[minmax(8rem,12rem)_1fr] gap-x-3">
            <span className="text-muted">
              <Time value={h.at} />
            </span>
            <span>
              {h.version !== null && h.version !== undefined && <Badge className="mr-1.5">v{h.version}</Badge>}
              <Text value={h.text} />
              {h.detail && (
                <span className="mt-0.5 block border-l-4 border-dashed border-border-strong pl-2 text-muted">
                  <Text value={h.detail} max={1500} lines={12} />
                </span>
              )}
            </span>
          </li>
        ))}
      </ol>
      {detail.history_total > detail.history.length && <p className="m-0 text-sm text-muted">{count(detail.history_total - detail.history.length)} older entries are not shown.</p>}
    </Section>
  );
}

import { Tabs } from "@base-ui/react/tabs";
import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useId, type ReactNode } from "react";
import type { InvestigationDetail } from "../../client/types.gen";
import { useAnnounce } from "../../lib/announce";
import { count } from "../../lib/format";
import { outcomeLabel } from "../../lib/labels";
import { TABS, type Tab } from "../../lib/inboxQuery";
import { investigationOptions, reportsOptions } from "../../lib/queries";
import { keyFacts } from "../../lib/verdict";
import { ApiError } from "../../lib/session";
import { AiChip, StateChip } from "../chips";
import { Loading, Problem } from "../Problem";
import { Time } from "../Time";
import { UntrustedText } from "../UntrustedText";
import { SeverityBadge } from "../ui/badge";
import { Button } from "../ui/button";
import { useAssessmentPoll } from "./actions";
import { Assessments } from "./Assessments";
import { FoundBox } from "./FoundBox";
import { CheckMore } from "./CheckMore";
import { GoldBox } from "./ReviewPanel";
import { VerdictCard } from "./VerdictCard";
import { ReportView } from "./ReportView";
import { Alerts, Checked, Facts, History } from "./Tabs";
import { SigninsCard } from "../signins/SigninsCard";

const TAB_TITLE: Record<Tab, string> = {
  overview: "Overview",
  report: "Report",
  ai: "AI assessment",
  checked: "What ARGUS checked",
  alerts: "Alerts",
  history: "History",
};

function Strip({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="text-xs text-muted">{label}</dt>
      <dd className="m-0 text-sm">{children}</dd>
    </div>
  );
}

function Header({ detail, level }: { detail: InvestigationDetail; level: 1 | 2 }) {
  const inv = detail.investigation;
  const { announce } = useAnnounce();
  const Heading = level === 1 ? "h1" : "h2";
  const last = detail.reviews[0];
  return (
    <header className="flex flex-col gap-2">
      <Heading id="investigation-title" tabIndex={-1} className="page-h page-h-long focus:outline-none">
        <UntrustedText value={inv.rule_name ?? inv.rule_id} limits={{ maxChars: 160, maxLines: 2 }} />
      </Heading>
      <p className="m-0 text-sm">
        {count(inv.alert_count)} {inv.alert_count === 1 ? "alert" : "alerts"}
        {inv.key_fields.length > 0 && (
          <>
            {" "}
            for{" "}
            {inv.key_fields.map((k, i) => (
              <span key={i} className="font-mono">
                {i > 0 && ", "}
                <UntrustedText value={`${k.field} ${String(k.value ?? "")}`} limits={{ maxChars: 120, maxLines: 1 }} />
              </span>
            ))}
          </>
        )}{" "}
        from <Time value={inv.first_event_at} /> to <Time value={inv.last_event_at} />.
      </p>
      <div className="flex flex-wrap items-center gap-2">
        <SeverityBadge severity={inv.severity} />
        <StateChip state={inv.human_state} />
        <AiChip ai={inv.ai} />
      </div>
      {detail.coverage.map((g, i) => (
        <div key={i} role="note" className="rounded-control border border-warn/40 bg-warn-soft px-3 py-2 text-sm text-warn">
          <strong>Alerts may be missing</strong> from <Time value={g.start_at} />
          {g.end_at && (
            <>
              {" "}
              to <Time value={g.end_at} />
            </>
          )}
          : <UntrustedText value={g.text} limits={{ maxChars: 300, maxLines: 3 }} />.
        </div>
      ))}
      <dl className="m-0 grid grid-cols-2 gap-x-4 gap-y-2 rounded-card bg-surface px-5 py-4 sm:grid-cols-3">
        <Strip label="State">
          <StateChip state={inv.human_state} />
          {last && inv.human_state === "reviewed" && (
            <span className="block text-xs text-muted">
              by <UntrustedText value={last.reviewer} limits={{ maxChars: 60, maxLines: 1 }} />, <Time value={last.created_at} />
              {last.outcome ? ` (${outcomeLabel(last.outcome)})` : ""}
            </span>
          )}
        </Strip>
        <Strip label="Severity">
          <UntrustedText value={inv.severity ?? "unknown"} limits={{ maxChars: 20, maxLines: 1 }} />
          {inv.risk_score !== null && inv.risk_score !== undefined ? ` (risk ${inv.risk_score})` : ""}
        </Strip>
        <Strip label="Day">
          from <Time value={inv.bucket_start} />
        </Strip>
        {inv.duplicate_count > 0 && <Strip label="Repeats">{count(inv.duplicate_count)} alerts report a detection already counted</Strip>}
        {inv.continues_id && (
          <Strip label="Continues">
            <Link to="/alert-groups/$id" params={{ id: inv.continues_id }}>
              the same activity the day before
            </Link>
          </Strip>
        )}
      </dl>
      <details className="text-sm" data-testid="ids">
        <summary className="cursor-pointer text-muted">Details: the rule&apos;s and this alert group&apos;s IDs</summary>
        <dl className="m-0 mt-1 grid gap-x-4 gap-y-2 sm:grid-cols-2">
          <Strip label="Rule id">
            <span className="font-mono">
              <UntrustedText value={inv.rule_id} limits={{ maxChars: 120, maxLines: 1 }} />
            </span>
          </Strip>
          <Strip label="Investigation ID">
            <span className="font-mono text-xs break-all" data-testid="investigation-id">
              {inv.id}
            </span>{" "}
            <Button
              size="sm"
              variant="ghost"
              onClick={() => {
                const failed = () => announce("The investigation ID could not be copied; select it and copy by hand.", "warn");
                const copying = navigator.clipboard?.writeText(inv.id);
                if (copying === undefined) failed();
                else copying.then(() => announce("Copied the investigation ID.", "ok"), failed);
              }}
            >
              Copy ID
            </Button>
          </Strip>
        </dl>
      </details>
    </header>
  );
}

function Overview({ detail, id }: { detail: InvestigationDetail; id: string }) {
  const reports = useQuery(reportsOptions(id));
  const inv = detail.investigation;
  const first = reports.data?.items[0];
  // the key facts the card above shows are not said again here (P4-F U18)
  const shown = keyFacts(first, detail.dossier?.facts).map((f) => f.text);
  return (
    <div className="flex flex-col gap-3">
      {first ? (
        <FoundBox report={first} shown={shown} />
      ) : reports.isPending ? (
        <Loading what="what ARGUS found with extra SIEM queries" />
      ) : reports.isError ? (
        <Problem error={reports.error} what="What ARGUS found with extra SIEM queries" onRetry={() => void reports.refetch()} />
      ) : (
        <p className="m-0 text-sm text-muted">No SIEM query result yet: ARGUS has not built this investigation&apos;s dossier.</p>
      )}
      <SigninsCard signins={detail.signins} />
      <section aria-label="Reasons to look" className="flex flex-col gap-1">
        <h3 className="m-0 text-sm font-semibold">Reasons to look</h3>
        {inv.reasons.length > 0 ? (
          <ul className="m-0 pl-5 text-sm">
            {inv.reasons.map((r, i) => (
              <li key={i}>{r}</li>
            ))}
          </ul>
        ) : (
          <p className="m-0 text-sm text-muted">None.</p>
        )}
      </section>
      <CheckMore investigationId={id} version={inv.version} suggestions={(detail.dossier?.addresses ?? []).filter((a) => a.kind !== "invalid").map((a) => a.address)} />
      {detail.dossier ? <Facts dossier={detail.dossier} /> : <p className="m-0 text-sm text-muted">Not looked at yet: ARGUS works through new investigations within minutes.</p>}
    </div>
  );
}

function Reports({ id }: { id: string }) {
  const reports = useQuery(reportsOptions(id));
  if (reports.isPending) return <Loading what="the report" />;
  if (reports.isError) return <Problem error={reports.error} what="The report" onRetry={() => void reports.refetch()} />;
  return (
    <>
      {reports.data.logs_hidden && (
        <p className="m-0 mb-2 text-sm text-muted">Your account cannot read the logs in ELK, so what the logs said is hidden in this report.</p>
      )}
      <ReportView reports={reports.data.items} />
    </>
  );
}

/**
 * One investigation, in tabs: Overview (what the extra SIEM queries found, why to look), Report
 * (report@2 in full), AI assessment, What ARGUS checked, Alerts, History; above them the verdict
 * card (what ARGUS recommends or read, the facts behind it, Confirm, Change and your review) and,
 * for a gold-set item, your answer. `queue`: the investigation's own page, where Next walks the
 * queue and the keys C, 1 to 5 and N work.
 */
export function InvestigationView({ id, tab, onTab, level = 2, queue = false }: { id: string; tab: Tab; onTab: (tab: Tab) => void; level?: 1 | 2; queue?: boolean }) {
  const detail = useQuery(investigationOptions(id));
  useAssessmentPoll(detail.data);
  const tabsId = useId();
  if (detail.isPending) return <Loading what="the investigation" />;
  if (detail.isError) {
    const gone = detail.error instanceof ApiError && detail.error.status === 404;
    return (
      <div className="flex flex-col gap-2">
        <Problem error={detail.error} what="The investigation" onRetry={() => void detail.refetch()} />
        {gone && <p className="m-0 text-sm">It may have been removed after the retention period, or the link is wrong. <Link to="/inbox" search={{ view: "attention" }}>Back to the Inbox</Link>.</p>}
      </div>
    );
  }
  const d = detail.data;
  // keyed by the investigation (review B2-R3): nothing typed, chosen or opened for one carries to the next
  return (
    <article key={d.investigation.id} aria-label="Investigation" className="flex flex-col gap-3" aria-busy={detail.isFetching}>
      <Header detail={d} level={level} />
      <VerdictCard key={`${d.investigation.id}:verdict`} detail={d} queue={queue} />
      <GoldBox key={`${d.investigation.id}:gold`} detail={d} />
      <Tabs.Root value={tab} onValueChange={(v) => TABS.includes(v as Tab) && onTab(v as Tab)}>
        <Tabs.List aria-label="Sections of this investigation" className="flex gap-1 overflow-x-auto py-1" id={tabsId}>
          {TABS.map((t) => (
            <Tabs.Tab
              key={t}
              value={t}
              className="min-h-8 cursor-pointer rounded-full border-0 bg-transparent px-3 text-sm whitespace-nowrap text-muted hover:text-text aria-selected:bg-text aria-selected:font-medium aria-selected:text-bg"
            >
              {TAB_TITLE[t]}
              {t === "ai" && d.assessments.length > 0 ? ` (${d.assessments.length})` : ""}
              {t === "alerts" ? ` (${count(d.investigation.alert_count)})` : ""}
              {t === "history" && d.reviews.length > 0 ? ` (${d.reviews.length})` : ""}
            </Tabs.Tab>
          ))}
        </Tabs.List>
        <Tabs.Panel value="overview" className="pt-3">
          <Overview detail={d} id={id} />
        </Tabs.Panel>
        <Tabs.Panel value="report" className="pt-3">
          <Reports id={id} />
        </Tabs.Panel>
        <Tabs.Panel value="ai" className="pt-3">
          <Assessments detail={d} />
        </Tabs.Panel>
        <Tabs.Panel value="checked" className="pt-3">
          <Checked detail={d} />
        </Tabs.Panel>
        <Tabs.Panel value="alerts" className="pt-3">
          <Alerts detail={d} />
        </Tabs.Panel>
        <Tabs.Panel value="history" className="pt-3">
          <History detail={d} />
        </Tabs.Panel>
      </Tabs.Root>
    </article>
  );
}

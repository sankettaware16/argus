import { Tabs } from "@base-ui/react/tabs";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "@tanstack/react-router";
import { useEffect, useId, useRef, useState, type ReactNode } from "react";
import { getCase } from "../client/sdk.gen";
import type { CaseDetail, CaseReportOut, IncidentReport } from "../client/types.gen";
import { CaseActions } from "../components/cases/CaseActions";
import { KnownSection } from "../components/cases/KnownSections";
import { ReportSection } from "../components/cases/ReportSection";
import { TeamSection } from "../components/cases/TeamSection";
import { CaseApprovals, HistorySection, LeadReportSections, MembersSection, MirrorSection, NotesSection, SummarySection, TimelineSection, WhatsNewSection } from "../components/cases/CaseSections";
import { useDecideKeys } from "../components/decide/Decide";
import { engineOfDetail } from "../components/decide/target";
import { IncidentBar } from "../components/incident/IncidentBar";
import { ActivityTab, AlertGroupsTab, EntitiesTab, EvidenceTab, ReportTab, StoryTab } from "../components/incident/IncidentTabs";
import { Overview } from "../components/incident/Overview";
import { ActivityLine, ChangedStrip, CertaintyWord, PriorityBadge } from "../components/incident/Parts";
import { Loading, Problem } from "../components/Problem";
import { SigninsCard } from "../components/signins/SigninsCard";
import { UntrustedText } from "../components/UntrustedText";
import { Badge } from "../components/ui/badge";
import { Button } from "../components/ui/button";
import { BACKGROUND } from "../lib/api";
import { unwrap } from "../lib/call";
import { shownCertainty, startsWithCertainty, stateWords, type Engine } from "../lib/engine";
import { count, plural } from "../lib/format";
import { againstConfirming } from "../lib/incident";
import { caseOptions, caseReportOptions } from "../lib/queries";
import { ApiError } from "../lib/session";
import { parse } from "../lib/time";
import { useShortcuts } from "../lib/useShortcuts";
import { dayAndTime } from "../lib/when";
import { INCIDENT_TABS, type IncidentTab } from "../lib/incidentTabs";

const TAB_TITLE: Record<Exclude<IncidentTab, "all">, string> = { overview: "Overview", story: "Story", evidence: "Evidence", entities: "Entities", "alert-groups": "Alert groups", report: "Report", activity: "Activity" };

/** The page's single keys (§13): `c` confirm, `d` the dismiss menu; nothing sends on one key. */
function useIncidentKeys(on: boolean, keys: ReturnType<typeof useDecideKeys>) {
  useEffect(() => {
    if (!on) return;
    const press = (e: KeyboardEvent) => {
      if (e.ctrlKey || e.metaKey || e.altKey || e.defaultPrevented) return;
      const t = e.target as HTMLElement | null;
      if (t && (t.isContentEditable || ["INPUT", "TEXTAREA", "SELECT"].includes(t.tagName) || t.closest("[role=dialog],[role=alertdialog],[role=menu]"))) return;
      if (e.key === "c" && keys.confirm.current) {
        e.preventDefault();
        keys.confirm.current();
      } else if (e.key === "d" && keys.dismiss.current) {
        e.preventDefault();
        keys.dismiss.current();
      }
    };
    document.addEventListener("keydown", press);
    return () => document.removeEventListener("keydown", press);
  }, [on, keys]);
}

/** A background read of the case's version every minute (it never keeps the session alive): a new one says so (§7.10). */
function useChangedWhileOpen(id: string, shown: number | undefined): boolean {
  const poll = useQuery({
    queryKey: ["case-poll", id],
    queryFn: () => unwrap(getCase({ path: { case_id: id }, headers: BACKGROUND })),
    refetchInterval: 60_000,
    enabled: shown !== undefined,
    staleTime: 55_000,
  });
  return poll.data !== undefined && shown !== undefined && poll.data.case.version > shown;
}

function Copy({ text, label }: { text: string; label: string }) {
  return (
    <button type="button" role="menuitem" className="rounded-control px-3 py-2 text-left text-sm hover:bg-surface-2" onClick={() => void navigator.clipboard?.writeText(text)}>
      {label}
    </button>
  );
}

/** [⋯]: copy the link, the id and the IR number (a possible incident's IR number lives only here), download the report, see the raw record. UUIDs live only here (I-13). */
function Dots({ detail, report }: { detail: CaseDetail; report: CaseReportOut | undefined }) {
  const [open, setOpen] = useState(false);
  const [raw, setRaw] = useState(false);
  const id = useId();
  const pdf = report?.files.find((f) => f.kind === "pdf" && f.available);
  return (
    <div className="relative">
      <Button aria-haspopup="menu" aria-expanded={open} aria-controls={open ? id : undefined} aria-label="More about this incident" onClick={() => setOpen(!open)}>
        ⋯
      </Button>
      {open && (
        <div id={id} role="menu" aria-label="More about this incident" className="absolute right-0 z-30 mt-1 flex w-60 flex-col rounded-card border border-border bg-surface p-1 shadow-card" onKeyDown={(e) => e.key === "Escape" && setOpen(false)}>
          <Copy text={window.location.href} label="Copy link" />
          <Copy text={detail.case.id} label="Copy ID" />
          {detail.incident_id && <Copy text={detail.incident_id} label="Copy IR number" />}
          {pdf && (
            <a role="menuitem" href={pdf.url} className="rounded-control px-3 py-2 text-sm text-text no-underline hover:bg-surface-2" download>
              Download the report (PDF)
            </a>
          )}
          <Link role="menuitem" to="/incidents/$id" params={{ id: detail.case.id }} search={{ tab: "all" }} className="rounded-control px-3 py-2 text-sm text-text no-underline hover:bg-surface-2" onClick={() => setOpen(false)}>
            Everything on one page
          </Link>
          <button
            type="button"
            role="menuitem"
            className="rounded-control px-3 py-2 text-left text-sm hover:bg-surface-2"
            onClick={() => {
              setRaw(!raw);
              setOpen(false);
            }}
          >
            {raw ? "Hide the raw record" : "Show the raw record"}
          </button>
        </div>
      )}
      {raw && (
        <pre className="absolute right-0 z-20 mt-1 max-h-96 w-[min(40rem,calc(100vw-2rem))] overflow-auto rounded-card border border-border bg-surface p-3 text-xs shadow-card" tabIndex={0} aria-label="The raw record" data-testid="raw-record">
          <UntrustedText value={JSON.stringify(detail.case, null, 2)} limits={{ maxChars: 20000, maxLines: 400 }} block />
        </pre>
      )}
    </div>
  );
}

function Header({ detail, engine, report, id }: { detail: CaseDetail; engine: Engine | null; report: CaseReportOut | undefined; id: string }) {
  const c = detail.case;
  const certainty = shownCertainty(c.state, c.closure_reason, engine);
  const first = parse(engine?.first_seen ?? c.first_alert_at);
  const last = parse(engine?.last_seen ?? c.last_alert_at);
  const groups = engine?.alert_groups ?? c.investigations;
  const alerts = engine?.alerts ?? c.alerts;
  return (
    <header id={id} className="flex flex-col gap-1.5">
      <div className="flex items-center justify-between gap-2">
        <Link to="/incidents" search={{ view: "needs-you" }} className="text-sm">
          ← Needs you
        </Link>
        <Dots detail={detail} report={report} />
      </div>
      <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-1">
        <p className="m-0 flex flex-wrap items-center gap-x-2 gap-y-1 text-sm" data-testid="badge-line">
          <PriorityBadge engine={engine} />
          <span>{stateWords({ state: c.state, number: c.number, taken_by: c.owner ? { username: c.owner.username, name: c.owner.display_name } : null })}</span>
          {engine?.raised_by_ai && <Badge tone="info">Raised by ARGUS&apos;s AI</Badge>}
          {certainty === "Confirmed" && detail.incident_id && <span className="text-muted">{detail.incident_id}</span>}
        </p>
        <p className="m-0 text-sm" data-testid="taken-by">
          Taken by: {c.owner ? <UntrustedText value={c.owner.display_name} limits={{ maxChars: 60, maxLines: 1 }} /> : "nobody"}
        </p>
      </div>
      <h1 id="case-title" tabIndex={-1} className="m-0 text-2xl leading-snug font-semibold text-balance focus:outline-none">
        {certainty !== null && !startsWithCertainty(c.title) && (
          <>
            <CertaintyWord value={certainty} /> ·{" "}
          </>
        )}
        <UntrustedText value={c.title} limits={{ maxChars: 240, maxLines: 3 }} />
      </h1>
      <p className="m-0 flex flex-wrap gap-x-1 text-sm text-muted" data-testid="activity-line">
        {engine && (
          <>
            <ActivityLine engine={engine} capital />
            <span aria-hidden="true">·</span>
          </>
        )}
        {first && <span>first {dayAndTime(first)}</span>}
        {last && (
          <>
            <span aria-hidden="true">·</span>
            <span>last {dayAndTime(last)}</span>
          </>
        )}
        <span aria-hidden="true">·</span>
        <span>
          {count(groups)} {plural(groups, "alert group")}
        </span>
        <span aria-hidden="true">·</span>
        <span>
          {count(alerts)} {plural(alerts, "alert")}
        </span>
      </p>
    </header>
  );
}

function Panel({ value, children }: { value: IncidentTab; children: ReactNode }) {
  return (
    <Tabs.Panel value={value} className="flex flex-col gap-6 pt-4 focus:outline-none">
      {children}
    </Tabs.Panel>
  );
}

/** The other tabs (§7.4–§7.9). */
function OtherTabs({ detail, engine, report }: { detail: CaseDetail; engine: Engine | null; report: { data: CaseReportOut | undefined } }) {
  return (
    <>
      <Panel value="story">
        <StoryTab detail={detail} engine={engine} report={report} />
      </Panel>
      <Panel value="evidence">
        <EvidenceTab detail={detail} report={report} />
      </Panel>
      <Panel value="entities">
        <EntitiesTab detail={detail} engine={engine} report={report} />
      </Panel>
      <Panel value="alert-groups">
        <AlertGroupsTab detail={detail} />
      </Panel>
      <Panel value="report">
        <ReportTab detail={detail} engine={engine} report={report} />
      </Panel>
      <Panel value="activity">
        <ActivityTab detail={detail} />
      </Panel>
    </>
  );
}

/** Every part of the old case page in its order, on one page (the [⋯] menu's "Everything on one page"). */
function Everything({ detail, id }: { detail: CaseDetail; id: string }) {
  return (
    <div className="flex flex-col gap-6" data-testid="everything">
      <p className="m-0 text-sm text-muted">
        Everything on one page.{" "}
        <Link to="/incidents/$id" params={{ id }}>
          Back to the overview
        </Link>
      </p>
      <SummarySection detail={detail} />
      <ReportSection caseId={detail.case.id} incidentId={detail.incident_id ?? null} />
      <TeamSection caseId={detail.case.id} />
      <KnownSection detail={detail} />
      <SigninsCard signins={detail.signins} level={2} />
      <WhatsNewSection detail={detail} />
      <TimelineSection detail={detail} />
      <LeadReportSections detail={detail} />
      <CaseActions detail={detail} />
      <MembersSection detail={detail} />
      <CaseApprovals detail={detail} />
      <MirrorSection mirror={detail.mirror} />
      <NotesSection detail={detail} />
      <HistorySection detail={detail} />
    </div>
  );
}

/**
 * The incident page (docs/p4f-ui-spec.md §7): the header, the sticky decision bar, then tabs —
 * Overview first (≤ 2 screens), then Story, Evidence, Entities, Alert groups, Report, Activity.
 * The case and its report are read in parallel; the header and the bar need only the case.
 */
export function IncidentPage({ id, tab, onTab }: { id: string; tab: IncidentTab; onTab: (tab: IncidentTab) => void }) {
  const found = useQuery(caseOptions(id));
  const report = useQuery(caseReportOptions(id, null));
  const queries = useQueryClient();
  const keys = useDecideKeys();
  const [shortcuts] = useShortcuts();
  const [conflict, setConflict] = useState(false);
  const headId = useId();
  const changed = useChangedWhileOpen(id, found.data?.case.version);
  const lastVersion = useRef<number | null>(null);
  useIncidentKeys(shortcuts && found.data !== undefined, keys);
  useEffect(() => {
    const v = found.data?.case.version ?? null;
    if (lastVersion.current !== null && v !== null && v !== lastVersion.current) setConflict(false);
    lastVersion.current = v;
  }, [found.data?.case.version]);

  if (found.isPending) return <Loading what="the incident" />;
  if (found.isError) {
    const gone = found.error instanceof ApiError && (found.error.status === 404 || found.error.status === 403);
    return gone ? (
      <div className="flex flex-col gap-2">
        <h1 className="m-0 text-2xl font-semibold">Not found</h1>
        <p className="m-0">
          This incident does not exist, or you cannot see it. <Link to="/incidents" search={{ view: "needs-you" }}>Back to Incidents</Link>
        </p>
      </div>
    ) : (
      <Problem error={found.error} what="The incident" onRetry={() => void found.refetch()} />
    );
  }
  const d = found.data;
  const engine = engineOfDetail(d);
  const body = (report.data?.report ?? null) as IncidentReport | null;
  const counts: Partial<Record<IncidentTab, number>> = { evidence: report.data?.report?.evidence.length ?? 0, entities: engine?.objects.length ?? d.indicators_total, "alert-groups": d.investigations_total, activity: d.notes_total + d.history_total };
  return (
    <article key={d.case.id} aria-labelledby="case-title" className="flex flex-col gap-3 pb-28 sm:pb-0" aria-busy={found.isFetching}>
      <Header detail={d} engine={engine} report={report.data} id={headId} />
      {changed && (
        <p role="status" className="m-0 flex flex-wrap items-center gap-2 rounded-control border border-info/40 bg-info-soft px-3 py-2 text-sm text-info">
          This incident changed while you were reading.
          <Button size="sm" onClick={() => void queries.invalidateQueries({ queryKey: ["case", id] })}>
            Show what changed
          </Button>
        </p>
      )}
      {conflict && <ChangedStrip changed={engine?.changed.length ? engine.changed : ["someone else changed it first"]} lead="It changed while you were deciding" testId="conflict-strip" />}
      <IncidentBar detail={d} engine={engine} keys={keys} reportConfirmable={report.data?.confirm.enabled ?? false} verdict={body?.verdict ?? null} alternatives={engine ? [] : againstConfirming(body)} headerId={headId} onConflict={() => setConflict(true)} />
      {tab === "all" ? (
        <Everything detail={d} id={d.case.id} />
      ) : (
      <Tabs.Root value={tab} onValueChange={(v) => (INCIDENT_TABS as readonly string[]).includes(String(v)) && onTab(v as IncidentTab)}>
        <Tabs.List aria-label="Parts of this incident" className="flex gap-1 overflow-x-auto border-b border-border">
          {INCIDENT_TABS.map((t) => (
            <Tabs.Tab key={t} value={t} className="min-h-9 cursor-pointer rounded-t-control border-0 bg-transparent px-3 text-sm whitespace-nowrap text-muted aria-selected:bg-accent-soft aria-selected:font-semibold aria-selected:text-text">
              {TAB_TITLE[t]}
              {counts[t] ? <span className="ml-1 tabular-nums">{counts[t]}</span> : null}
            </Tabs.Tab>
          ))}
        </Tabs.List>
        <Panel value="overview">
          <Overview detail={d} engine={engine} report={report} />
        </Panel>
        <OtherTabs detail={d} engine={engine} report={report} />
      </Tabs.Root>
      )}
    </article>
  );
}

/** The route's wrapper: the tab lives in the address. */
export function IncidentRoute({ id, tab }: { id: string; tab: IncidentTab | undefined }) {
  const navigate = useNavigate();
  return <IncidentPage id={id} tab={tab ?? "overview"} onTab={(next) => void navigate({ to: "/incidents/$id", params: { id }, search: { tab: next }, replace: true })} />;
}

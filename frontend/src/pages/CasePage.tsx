import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { CaseActions } from "../components/cases/CaseActions";
import { KnownSection } from "../components/cases/KnownSections";
import { ReportSection } from "../components/cases/ReportSection";
import { SigninsCard } from "../components/signins/SigninsCard";
import { TeamSection } from "../components/cases/TeamSection";
import {
  CaseApprovals,
  HistorySection,
  LeadReportSections,
  MembersSection,
  MirrorSection,
  NotesSection,
  SummarySection,
  TimelineSection,
  WhatsNewSection,
} from "../components/cases/CaseSections";
import { Loading, Problem } from "../components/Problem";
import { UntrustedText } from "../components/UntrustedText";
import { caseOptions } from "../lib/queries";
import { ApiError } from "../lib/session";

const CONTENTS = [
  ["summary", "Summary"],
  ["report", "Report"],
  ["kibana-case", "Kibana case preview"],
  ["notified", "Owner notified"],
  ["signins", "Who used the devices"],
  ["whats-new", "What's new"],
  ["timeline", "Timeline"],
  ["evidence", "Evidence"],
  ["hypotheses", "Hypotheses"],
  ["unknowns", "Unknowns"],
  ["actions", "Actions"],
  ["members", "Members"],
  ["approvals", "Approvals"],
  ["kibana", "Kibana"],
  ["notes", "Notes"],
  ["history", "History"],
] as const;

/**
 * One case in an analyst's order (plan §5 Q-B3): the summary, what is new, the timeline, evidence,
 * hypotheses and unknowns, what can be done (each action saying why not when it cannot), the
 * members, Kibana's mirror with people's comments as untrusted text, the notes, the history.
 */
export function CasePage({ id }: { id: string }) {
  const found = useQuery(caseOptions(id));
  if (found.isPending) return <Loading what="the case" />;
  if (found.isError) {
    const gone = found.error instanceof ApiError && found.error.status === 404;
    return (
      <div className="flex flex-col gap-2">
        <Problem error={found.error} what="The case" onRetry={() => void found.refetch()} />
        {gone && (
          <p className="m-0 text-sm">
            It may not exist, or the link is wrong. <Link to="/cases" search={{ view: "active" }}>Back to the cases</Link>.
          </p>
        )}
      </div>
    );
  }
  const d = found.data;
  // keyed by the case: nothing typed or opened for one carries to another
  return (
    <article key={d.case.id} aria-label="Case" className="flex flex-col gap-6" aria-busy={found.isFetching}>
      <header className="flex flex-col gap-1">
        <p className="m-0 text-sm">
          <Link to="/cases" search={{ view: "active" }}>
            ← All cases
          </Link>
        </p>
        <h1 id="case-title" tabIndex={-1} className="m-0 text-2xl font-semibold focus:outline-none">
          Case {d.case.number}: <UntrustedText value={d.case.title} limits={{ maxChars: 200, maxLines: 2 }} />
        </h1>
        <nav aria-label="On this page" className="flex flex-wrap gap-x-3 gap-y-1 text-sm">
          {CONTENTS.filter(([anchor]) => (anchor !== "notified" || d.known != null) && (anchor !== "signins" || d.signins != null)).map(([anchor, label]) => (
            <a key={anchor} href={`#${anchor}`}>
              {label}
            </a>
          ))}
        </nav>
      </header>
      <SummarySection detail={d} />
      <ReportSection caseId={d.case.id} />
      <TeamSection caseId={d.case.id} />
      <KnownSection detail={d} />
      <SigninsCard signins={d.signins} level={2} />
      <WhatsNewSection detail={d} />
      <TimelineSection detail={d} />
      <LeadReportSections detail={d} />
      <CaseActions detail={d} />
      <MembersSection detail={d} />
      <CaseApprovals detail={d} />
      <MirrorSection mirror={d.mirror} />
      <NotesSection detail={d} />
      <HistorySection detail={d} />
    </article>
  );
}

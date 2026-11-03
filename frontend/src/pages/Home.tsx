import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useState } from "react";
import { listCases } from "../client/sdk.gen";
import { Loading, Problem } from "../components/Problem";
import { PatternSummaryCard } from "../components/queue/PatternSummary";
import { QueueCase, QueueSingle } from "../components/queue/QueueItems";
import { Button } from "../components/ui/button";
import { Card } from "../components/ui/card";
import { unwrap } from "../lib/call";
import { count, plural } from "../lib/format";
import { approvalsOptions, countsQuery, patternSummaryOptions, queueOptions } from "../lib/queries";
import { useSession } from "../lib/session";

const COUNT = new Intl.NumberFormat("en-IN");

const TILES = [
  { key: "attention", label: "Need attention", view: "attention", hint: "Follow-ups, changed and severe investigations" },
  { key: "open", label: "Not reviewed", view: "open", hint: "Nobody has reviewed these yet" },
  { key: "follow_up", label: "Follow-ups", view: "attention", hint: "Marked for a follow-up by a reviewer" },
  { key: "changed", label: "Changed since review", view: "attention", hint: "New alerts arrived after the review" },
  { key: "reviewed_today", label: "Reviewed in 24 h", view: "reviewed", hint: "Decided in the last 24 hours" },
] as const;

const CASE_TILES = [
  { key: "active", label: "Open cases", view: "active", hint: "Confirmed cases that are open, assigned or contained" },
  { key: "attention", label: "Cases needing attention", view: "attention", hint: "Cases ARGUS wants a person to look at, or that wait for an approval" },
  { key: "mine", label: "Your cases", view: "mine", hint: "Cases you own" },
  { key: "suspected", label: "Suspected", view: "suspected", hint: "Cases ARGUS suspects; a person's true-positive verdict confirms one" },
] as const;

/** Cases and approvals at a glance: the tiles' numbers come from the case list's counts and the approvals queue. */
function CaseTiles() {
  const cases = useQuery({ queryKey: ["cases-counts"], queryFn: () => unwrap(listCases({ query: { view: "active", limit: 1 } })), staleTime: 15_000 });
  const approvals = useQuery(approvalsOptions);
  const number = (n: number | undefined) => (n !== undefined ? COUNT.format(n) : cases.isError ? "?" : "…");
  return (
    <section aria-label="Cases" aria-busy={cases.isPending} className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
      {CASE_TILES.map((tile) => (
        <Link key={tile.key} to="/cases" search={{ view: tile.view }} title={tile.hint} className="rounded-card border border-border bg-surface p-3 text-text no-underline shadow-card hover:border-border-strong">
          <span className="block text-2xl font-semibold tabular-nums">{number(cases.data?.counts[tile.key])}</span>
          <span className="block text-sm text-muted">{tile.label}</span>
        </Link>
      ))}
      <Link to="/approvals" title="Closures and merges waiting for a person to decide" className="rounded-card border border-border bg-surface p-3 text-text no-underline shadow-card hover:border-border-strong">
        <span className="block text-2xl font-semibold tabular-nums">{approvals.data ? COUNT.format(approvals.data.pending_total) : approvals.isError ? "?" : "…"}</span>
        <span className="block text-sm text-muted">Waiting for an approval</span>
      </Link>
    </section>
  );
}

/** The new and the known counts: the API's own (`/counts`), the same numbers as the Inbox and the dashboard. */
function Totals({ notifiedCases }: { notifiedCases: number | undefined }) {
  const counts = useQuery(countsQuery);
  const c = counts.data;
  return (
    <section className="m-0 flex flex-wrap items-baseline gap-x-5 gap-y-1 text-sm" aria-label="New and known work" data-testid="totals">
      <span>
        <Link to="/inbox" search={{ view: "attention" }}>
          Needs attention: <strong className="tabular-nums">{c ? count(c.attention) : counts.isError ? "?" : "…"}</strong>
        </Link>{" "}
        <span className="text-muted">new work</span>
      </span>
      <span>
        <Link to="/inbox" search={{ view: "known" }} title="Investigations of devices whose owner was told: counted, not raised">
          Notified, still active: <strong className="tabular-nums">{c ? count(c.known) : counts.isError ? "?" : "…"}</strong>
        </Link>{" "}
        <span className="text-muted">
          {notifiedCases !== undefined && (
            <>
              ({count(notifiedCases)} {plural(notifiedCases, "case")}:{" "}
              <Link to="/cases" search={{ view: "notified" }}>
                the list
              </Link>
              )
            </>
          )}
        </span>
      </span>
    </section>
  );
}

function Patterns() {
  const summary = useQuery(patternSummaryOptions);
  const [skipped, setSkipped] = useState(0);
  const data = summary.data;
  const items = data?.items ?? [];
  const here = items.length === 0 ? 0 : skipped % items.length;
  const b = items[here];
  return (
    <section aria-labelledby="queue-patterns" className="flex flex-col gap-2">
      <h2 id="queue-patterns" className="m-0 text-lg font-semibold">
        2. Patterns ARGUS recommends closing
      </h2>
      {summary.isPending && <Loading what="the patterns" />}
      {summary.isError && <Problem error={summary.error} what="The patterns" onRetry={() => void summary.refetch()} />}
      {data && b === undefined && (
        <p className="m-0 text-sm text-muted">
          ARGUS recommends closing no pattern now. <Link to="/patterns">All patterns</Link>
        </p>
      )}
      {data && b && (
        <>
          <p className="m-0 text-sm text-muted" data-testid="pattern-count">
            One pattern at a time: pattern {here + 1} of {items.length}
            {data.total > items.length ? `, the ${count(items.length)} largest of ${count(data.total)}` : ""}. Together the {count(data.total)} {plural(data.total, "pattern")} cover {count(data.investigations)} {plural(data.investigations, "investigation")}. <Link to="/patterns">All patterns</Link>
          </p>
          {/* keyed by the pattern: the next one starts with nothing read */}
          <PatternSummaryCard
            key={`${b.pattern}-${b.day}`}
            b={b}
            extra={items.length > 1 ? <Button onClick={() => setSkipped(here + 1)}>Leave it for now, show the next pattern</Button> : null}
          />
        </>
      )}
    </section>
  );
}

function Queue() {
  const queue = useQuery(queueOptions);
  const counts = useQuery(countsQuery);
  const q = queue.data;
  const moreCases = q !== undefined && q.cases_total > q.cases.length;
  const moreSingles = q !== undefined && q.singles_total > q.singles.length;
  // the queue says nothing needs a person while the count of Needs attention says something does:
  // never "empty" then (the two are read apart, so a change between them is possible, and a bug is not)
  const disagrees = q !== undefined && q.cases_total === 0 && q.singles_total === 0 && (counts.data?.attention ?? 0) > 0;
  return (
    <>
      <Totals notifiedCases={q?.notified_cases} />
      {q && (q.cases_total > 0 || q.singles_total > 0) && (
        <p className="m-0 text-sm" data-testid="queue-summary">
          <strong>
            {count(q.cases_total)} {plural(q.cases_total, "case")} and {count(q.singles_total)} single {plural(q.singles_total, "investigation")}
          </strong>{" "}
          need a person ({count(q.order_total)} {plural(q.order_total, "investigation")} to look at).
        </p>
      )}
      {disagrees && (
        <p role="alert" className="m-0 rounded-control border border-warn/40 bg-warn-soft px-3 py-2 text-sm text-warn" data-testid="queue-disagrees">
          The queue shows nothing, but {count(counts.data?.attention ?? 0)} {plural(counts.data?.attention ?? 0, "investigation")} {counts.data?.attention === 1 ? "is" : "are"} in Needs attention. Open the{" "}
          <Link to="/inbox" search={{ view: "attention", sort: "queue" }}>
            Inbox
          </Link>
          ; tell an ARGUS admin if this stays.
        </p>
      )}
      <section aria-labelledby="queue-cases" className="flex flex-col gap-2" aria-busy={queue.isFetching}>
        <h2 id="queue-cases" className="m-0 text-lg font-semibold">
          1. ARGUS&apos;s cases that need a person
        </h2>
        {queue.isPending && <Loading what="the queue" />}
        {queue.isError && <Problem error={queue.error} what="The queue" onRetry={() => void queue.refetch()} />}
        {q && q.cases_total === 0 && <p className="m-0 text-sm text-muted">No case needs a person now.</p>}
        {q && q.cases.length > 0 && (
          <>
            <p className="m-0 text-sm text-muted">
              Suggested cases and cases with a change since the owner was told come first. {moreCases ? `The first ${count(q.cases.length)} of ${count(q.cases_total)} are shown. ` : ""}
              <Link to="/cases" search={{ view: "queue" }}>
                {moreCases ? `All ${count(q.cases_total)} cases that need a person` : "These cases in the cases list"}
              </Link>
            </p>
            <ol className="m-0 flex list-none flex-col gap-3 p-0" aria-label="Cases that need a person">
              {q.cases.map((c) => (
                <QueueCase key={c.id} c={c} />
              ))}
            </ol>
          </>
        )}
      </section>
      <Patterns />
      <section aria-labelledby="queue-singles" className="flex flex-col gap-2">
        <h2 id="queue-singles" className="m-0 text-lg font-semibold">
          3. Single investigations that need attention
        </h2>
        {q && q.singles_total === 0 && q.cases_total <= q.cases.length && <p className="m-0 text-sm text-muted">Every investigation in Needs attention is in a case above.</p>}
        {q && q.singles_total === 0 && q.cases_total > q.cases.length && (
          <p className="m-0 text-sm text-muted">
            Every investigation in Needs attention is in one of the {count(q.cases_total)} cases; the first {count(q.cases.length)} are above, the rest are in the{" "}
            <Link to="/cases" search={{ view: "queue" }}>
              cases list
            </Link>
            .
          </p>
        )}
        {q && q.singles.length > 0 && (
          <>
            <p className="m-0 text-sm text-muted">
              In Needs attention and in no case, in the queue&apos;s order: changed since a notice, then raised by ARGUS&apos;s own evidence, then follow-ups, then the rule&apos;s severity, then the newest. {moreSingles ? `The ${count(q.singles.length)} first of ${count(q.singles_total)} are shown. ` : ""}
              <Link to="/inbox" search={{ view: "attention", sort: "queue" }}>
                {moreSingles ? `All ${count(q.singles_total)} in the Inbox, in the same order` : "In the Inbox, in the same order"}
              </Link>
            </p>
            <ul className="m-0 flex list-none flex-col p-0" aria-label="Single investigations">
              {q.singles.map((s) => (
                <QueueSingle key={s.investigation.id} s={s} />
              ))}
            </ul>
          </>
        )}
      </section>
    </>
  );
}

/** Home: what needs a person today, in order (AR4): ARGUS's cases, the patterns it recommends closing, the single investigations; the counts below. */
export function Home() {
  const session = useSession();
  const counts = useQuery(countsQuery);
  return (
    <>
      <h1 className="m-0 text-2xl font-semibold">Home</h1>
      <p className="m-0 text-muted">{session.data ? "What needs a person today, in order. Notified cases that are still active with nothing changed are not work: they are counted." : null}</p>
      <Queue />
      <h2 className="m-0 mt-2 text-lg font-semibold">At a glance</h2>
      <section aria-label="Investigations" aria-busy={counts.isPending} className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
        {TILES.map((tile) => (
          <Link key={tile.key} to="/inbox" search={{ view: tile.view }} title={tile.hint} className="rounded-card border border-border bg-surface p-3 text-text no-underline shadow-card hover:border-border-strong">
            <span className="block text-2xl font-semibold tabular-nums">{counts.data ? COUNT.format(counts.data[tile.key]) : counts.isError ? "?" : "…"}</span>
            <span className="block text-sm text-muted">{tile.label}</span>
          </Link>
        ))}
      </section>
      <CaseTiles />
      {counts.isError && (
        <p className="m-0 text-sm text-danger" role="alert">
          The numbers could not be read just now; the classic pages still work.
        </p>
      )}
      <Card>
        <h2 className="m-0 mb-1 text-base font-semibold">The ARGUS app</h2>
        <p className="m-0 text-sm">
          Everything is here: this queue, the Dashboard, the Inbox with its two panes, Proposals, the cases and the approvals queue, the reports. The classic pages stay as a read-only fallback at{" "}
          <a href="/classic">Classic pages</a>. Nothing here changes how ARGUS works.
        </p>
      </Card>
    </>
  );
}

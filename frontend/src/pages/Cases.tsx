import { useInfiniteQuery } from "@tanstack/react-query";
import { Link, useNavigate } from "@tanstack/react-router";
import { useId, useState, type FormEvent } from "react";
import type { CaseRowOut } from "../client/types.gen";
import { CaseStateBadge } from "../components/cases/CaseBits";
import { Loading, Problem } from "../components/Problem";
import { Time } from "../components/Time";
import { UntrustedText } from "../components/UntrustedText";
import { Badge } from "../components/ui/badge";
import { SeverityBadge } from "../components/ui/badge";
import { Button } from "../components/ui/button";
import { Field, TextInput } from "../components/ui/field";
import { DataTable } from "../components/ui/table";
import { CASE_VIEW_HINTS, CASE_VIEW_TITLES, CASE_VIEWS, reasonLabel, type CasesSearch } from "../lib/cases";
import { count, plural } from "../lib/format";
import { casesOptions } from "../lib/queries";

function Views({ search, counts }: { search: CasesSearch; counts: Record<string, number> | undefined }) {
  return (
    <nav aria-label="Views" className="flex flex-wrap gap-1">
      {CASE_VIEWS.map((view) => (
        <Link
          key={view}
          to="/cases"
          search={{ view }}
          title={CASE_VIEW_HINTS[view]}
          aria-current={search.view === view && search.q === undefined ? "page" : undefined}
          className="inline-flex min-h-8 items-center gap-1 rounded-control px-2 text-sm text-text no-underline hover:bg-surface-3 aria-[current=page]:bg-accent-soft aria-[current=page]:font-semibold"
        >
          {CASE_VIEW_TITLES[view]}
          <span className="text-xs text-muted tabular-nums">{counts ? count(counts[view] ?? 0) : ""}</span>
        </Link>
      ))}
    </nav>
  );
}

function Find({ search }: { search: CasesSearch }) {
  const id = useId();
  const navigate = useNavigate({ from: "/cases" });
  const [text, setText] = useState(search.q ?? "");
  const [shown, setShown] = useState(search.q ?? "");
  if ((search.q ?? "") !== shown) {
    // the address changed under the box (a view link, Back): the box follows it
    setShown(search.q ?? "");
    setText(search.q ?? "");
  }
  function go(e: FormEvent) {
    e.preventDefault();
    const q = text.trim();
    void navigate({ search: { view: search.view, ...(q !== "" ? { q } : {}) } });
  }
  return (
    <form role="search" aria-label="Find a case" className="flex flex-wrap items-end gap-2" onSubmit={go}>
      <Field label="Find a case" hint="by number or a word of its title" htmlFor={id}>
        <TextInput id={id} value={text} maxLength={120} onChange={(e) => setText(e.target.value)} className="w-64" />
      </Field>
      <Button type="submit">Find</Button>
      {search.q !== undefined && (
        <Button
          onClick={() => {
            setText("");
            void navigate({ search: { view: search.view } });
          }}
        >
          Clear
        </Button>
      )}
    </form>
  );
}

function CaseCell({ c }: { c: CaseRowOut }) {
  return (
    <>
      <Link to="/cases/$id" params={{ id: c.id }}>
        Case {c.number}: <UntrustedText value={c.title} limits={{ maxChars: 120, maxLines: 1 }} />
      </Link>
      {c.closure_reason && <span className="block text-xs text-muted">Closed: {reasonLabel(c.closure_reason)}</span>}
      {c.merged_into && <span className="block text-xs text-muted">Merged into case {c.merged_into.number}</span>}
      {c.notified_at && (
        <span className="block text-xs text-muted">
          Owner told <Time value={c.notified_at} />
          {c.blocked_at ? ", blocked at the network" : ""}
        </span>
      )}
    </>
  );
}

/** The cases, most severe first, in the views a person works through (plan §5 Q-B3). */
export function Cases({ search }: { search: CasesSearch }) {
  const list = useInfiniteQuery(casesOptions(search));
  const rows = list.data?.pages.flatMap((p) => p.items) ?? [];
  const counts = list.data?.pages[0]?.counts;
  return (
    <>
      <h1 className="m-0 text-2xl font-semibold">Cases</h1>
      <p className="m-0 max-w-prose text-sm text-muted">
        A case is one real problem across days, hosts and rules. ARGUS suspects some; a person&apos;s true-positive verdict confirms one. Open a case for its summary, evidence and what you can do with it.
      </p>
      <Views search={search} counts={counts as Record<string, number> | undefined} />
      <Find search={search} />
      {list.isPending && <Loading what="the cases" />}
      {list.isError && <Problem error={list.error} what="The cases" onRetry={() => void list.refetch()} />}
      {list.data && (
        <>
          <p className="m-0 text-sm text-muted" aria-live="polite">
            {rows.length > 0 &&
              `${count(rows.length)}${list.hasNextPage ? " or more" : ""} ${plural(rows.length, "case")}${search.q !== undefined ? ` for “${search.q}”` : ""}.`}
          </p>
          <DataTable
            caption="Cases"
            rows={rows}
            rowKey={(c) => c.id}
            empty={search.q !== undefined ? "Nothing matches that. Try a number or another word." : search.view === "active" ? "No open case. ARGUS opens one when a person's verdict confirms a true positive." : "No case here."}
            columns={[
              { key: "case", header: "Case", cell: (c) => <CaseCell c={c} /> },
              { key: "state", header: "State", cell: (c) => <CaseStateBadge state={c.state} /> },
              { key: "severity", header: "Severity", cell: (c) => <SeverityBadge severity={c.severity} /> },
              {
                key: "owner",
                header: "Owner",
                cell: (c) => (c.owner ? <UntrustedText value={c.owner.display_name} limits={{ maxChars: 60, maxLines: 1 }} /> : <span className="text-muted">nobody</span>),
              },
              { key: "size", header: "Investigations · alerts", numeric: true, cell: (c) => `${count(c.investigations)} · ${count(c.alerts)}` },
              { key: "last", header: "Last alert", cell: (c) => <Time value={c.last_alert_at} /> },
              {
                key: "flags",
                header: "Needs",
                cell: (c) => (
                  <span className="flex flex-wrap gap-1">
                    {c.needs_attention && <Badge tone="warn">attention</Badge>}
                    {c.waiting_for_approval > 0 && <Badge tone="warn">{c.waiting_for_approval} to approve</Badge>}
                    {c.in_kibana ? <Badge tone="info">in Kibana</Badge> : c.kibana_wait ? <Badge>waits for Kibana</Badge> : null}
                  </span>
                ),
              },
            ]}
          />
          {list.hasNextPage && (
            <div>
              <Button aria-disabled={list.isFetchingNextPage} onClick={() => !list.isFetchingNextPage && void list.fetchNextPage()}>
                {list.isFetchingNextPage ? "Loading…" : "Show more cases"}
              </Button>
            </div>
          )}
        </>
      )}
    </>
  );
}

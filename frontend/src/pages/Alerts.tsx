import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { Link, useNavigate } from "@tanstack/react-router";
import { getCounts, listInvestigations } from "../client/sdk.gen";
import type { InvestigationOut } from "../client/types.gen";
import { AiChip, StateChip } from "../components/chips";
import { Loading, Problem } from "../components/Problem";
import { Time } from "../components/Time";
import { UntrustedText } from "../components/UntrustedText";
import { SeverityBadge } from "../components/ui/badge";
import { Button } from "../components/ui/button";
import { Select } from "../components/ui/field";
import { ALERT_STATE_WORDS, ALERT_STATES, alertsLead, alertsQuery, MEMBERSHIP_WORDS, MEMBERSHIPS, type AlertsSearch, type AlertState, type Membership } from "../lib/alerts";
import { unwrap } from "../lib/call";
import { stateWords } from "../lib/engine";
import { count, plural } from "../lib/format";
import { optionText } from "../lib/optionText";
import { rulesOptions } from "../lib/queries";

const PAGE = 50;

/** One choice of a few, as a row of buttons; the chosen one is pressed. */
function Segments<T extends string>({ label, values, words, value, onChange }: { label: string; values: readonly T[]; words: Readonly<Record<T, string>>; value: T; onChange: (next: T) => void }) {
  return (
    <div role="group" aria-label={label} className="flex flex-wrap gap-1">
      {values.map((v) => (
        <Button key={v} size="sm" variant={v === value ? "primary" : "secondary"} aria-pressed={v === value} onClick={() => onChange(v)}>
          {words[v]}
        </Button>
      ))}
    </div>
  );
}

function IncidentCell({ row }: { row: InvestigationOut }) {
  const c = row.case;
  if (c == null) return <span className="text-muted">—</span>;
  return (
    <Link to="/incidents/$id" params={{ id: c.id }} title={c.title} className="inline-flex max-w-full flex-col" data-testid="alert-incident">
      <span className="font-medium">{stateWords({ state: c.state, number: c.number }).split(" · ")[0]}</span>
      <span className="max-w-64 truncate text-xs text-muted">
        <UntrustedText value={c.title} limits={{ maxChars: 120, maxLines: 1 }} />
      </span>
    </Link>
  );
}

function Row({ row }: { row: InvestigationOut }) {
  return (
    <tr className="border-b border-border last:border-b-0 hover:bg-surface-2" data-testid="alert-row">
      <td className="truncate px-3 py-2 align-top whitespace-nowrap text-muted">{row.last_event_at ? <Time value={row.last_event_at} /> : "—"}</td>
      <td className="max-w-0 px-3 py-2 align-top">
        <Link to="/alert-groups/$id" params={{ id: row.id }} className="block truncate font-medium" data-testid="alert-title">
          <UntrustedText value={row.title} limits={{ maxChars: 200, maxLines: 1 }} />
        </Link>
        <span className="block truncate text-xs text-muted">
          <UntrustedText value={row.rule_name ?? row.rule_id} limits={{ maxChars: 200, maxLines: 1 }} />
        </span>
      </td>
      <td className="px-3 py-2 text-right align-top tabular-nums">{count(row.alert_count)}</td>
      <td className="px-3 py-2 align-top">{row.severity ? <SeverityBadge severity={row.severity} /> : <span className="text-muted">—</span>}</td>
      <td className="px-3 py-2 align-top">
        <span className="flex flex-wrap items-center gap-1">
          <StateChip state={row.human_state} />
          <AiChip ai={row.ai} />
        </span>
      </td>
      <td className="px-3 py-2 align-top">
        <IncidentCell row={row} />
      </td>
    </tr>
  );
}

/**
 * Alerts (the menu's third entry): every alert group ARGUS took in, newest first, each with the
 * incident it belongs to; the two halves (in an incident, in none) and the review states are one
 * click apart. A title opens the alert group; the incident's name opens the incident.
 */
export function Alerts({ search }: { search: AlertsSearch }) {
  const navigate = useNavigate();
  const set = (patch: AlertsSearch) => void navigate({ to: "/alerts", search: { ...search, ...patch }, replace: true });
  const asked = alertsQuery(search);
  const list = useInfiniteQuery({
    queryKey: ["alerts", asked.view, asked.incident ?? "any", asked.rule ?? ""],
    queryFn: ({ pageParam }) => unwrap(listInvestigations({ query: { ...asked, sort: "newest", offset: pageParam, limit: PAGE } })),
    initialPageParam: 0,
    getNextPageParam: (last) => (last.has_more ? last.offset + last.limit : undefined),
    staleTime: 30_000,
  });
  const counts = useQuery({ queryKey: ["counts"], queryFn: () => unwrap(getCounts()), staleTime: 60_000 });
  const rules = useQuery(rulesOptions);
  const rows = list.data?.pages.flatMap((p) => p.items) ?? [];
  const membership: Membership = search.in ?? "all";
  const state: AlertState = search.state ?? "all";
  return (
    <>
      <header className="flex flex-col gap-1">
        <div className="flex flex-wrap items-baseline justify-between gap-2">
          <h1 className="m-0 text-3xl font-semibold tracking-tight">Alerts</h1>
          <Link to="/search" search={{ advanced: "1", view: "attention" }} className="text-sm">
            Review them one by one ›
          </Link>
        </div>
        <p className="m-0 max-w-prose text-sm text-muted">{alertsLead(search)}</p>
        {counts.data && (
          <p className="m-0 text-sm" data-testid="alerts-counts">
            {count(counts.data.all)} alert {plural(counts.data.all, "group")} in all · {count(counts.data.attention)} need attention · {count(counts.data.reviewed)} reviewed
          </p>
        )}
      </header>
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
        <Segments label="Incident" values={MEMBERSHIPS} words={MEMBERSHIP_WORDS} value={membership} onChange={(v) => set({ in: v === "all" ? undefined : v })} />
        <Segments label="State" values={ALERT_STATES} words={ALERT_STATE_WORDS} value={state} onChange={(v) => set({ state: v === "all" ? undefined : v })} />
        <Select aria-label="Rule" className="w-auto max-w-72" value={search.rule ?? ""} onChange={(e) => set({ rule: e.target.value === "" ? undefined : e.target.value })}>
          <option value="">All rules</option>
          {search.rule !== undefined && !rules.data?.some((r) => r.rule_id === search.rule) && <option value={search.rule}>{optionText(search.rule)}</option>}
          {(rules.data ?? []).map((r) => (
            <option key={r.rule_id} value={r.rule_id}>
              {optionText(r.rule_name ?? r.rule_id)}
            </option>
          ))}
        </Select>
      </div>
      {list.isPending && <Loading what="the alert groups" />}
      {list.isError && <Problem error={list.error} what="The alert groups" onRetry={() => void list.refetch()} />}
      {list.data && rows.length === 0 && (
        <p className="m-0 text-sm text-muted" data-testid="alerts-empty">
          No alert group matches. {search.in === "incident" ? "ARGUS has put none in an incident yet." : "Change the filters above to see the others."}
        </p>
      )}
      {rows.length > 0 && (
        <div className="overflow-x-auto rounded-card bg-surface">
          <table className="w-full min-w-[52rem] table-fixed border-collapse text-sm">
            <caption className="sr-only">Alert groups, newest alert first</caption>
            <colgroup>
              <col className="w-52" />
              <col />
              <col className="w-20" />
              <col className="w-24" />
              <col className="w-52" />
              <col className="w-64" />
            </colgroup>
            <thead>
              <tr className="text-left text-xs font-medium text-muted">
                <th scope="col" className="border-b border-border px-3 py-2">
                  Last alert
                </th>
                <th scope="col" className="border-b border-border px-3 py-2">
                  Alert group
                </th>
                <th scope="col" className="border-b border-border px-3 py-2 text-right">
                  Alerts
                </th>
                <th scope="col" className="border-b border-border px-3 py-2">
                  Severity
                </th>
                <th scope="col" className="border-b border-border px-3 py-2">
                  State
                </th>
                <th scope="col" className="border-b border-border px-3 py-2">
                  Incident
                </th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <Row key={row.id} row={row} />
              ))}
            </tbody>
          </table>
        </div>
      )}
      {list.hasNextPage && (
        <div>
          <Button onClick={() => void list.fetchNextPage()} aria-disabled={list.isFetchingNextPage}>
            {list.isFetchingNextPage ? "Loading…" : `Show ${PAGE} more`}
          </Button>
        </div>
      )}
    </>
  );
}

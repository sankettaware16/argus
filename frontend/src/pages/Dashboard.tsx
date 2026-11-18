import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { Link, useNavigate } from "@tanstack/react-router";
import { useId, type ReactNode } from "react";
import type { DashboardOut, InvestigationBrief, NotifiedBrief, SinceOut, ThreatTileOut } from "../client/types.gen";
import { SplitBar, AI_FILL, SEVERITY_FILL, STATE_FILL, VERDICT_FILL } from "../components/charts/SplitBar";
import { StackedBars } from "../components/charts/StackedBars";
import { SeverityBadge } from "../components/ui/badge";
import { Button } from "../components/ui/button";
import { Card, CardTitle } from "../components/ui/card";
import { Check, Field, Select, TextInput } from "../components/ui/field";
import { DataTable, type Column } from "../components/ui/table";
import { StateChip } from "../components/chips";
import { Loading, Problem } from "../components/Problem";
import { Time } from "../components/Time";
import { UntrustedText } from "../components/UntrustedText";
import { sum } from "../lib/chart";
import { adding, chips, cleared, parseFilters, toSearch, validList, type Filters, type ListName } from "../lib/dashboardFilters";
import { capped, count, duration, percent, plural, versusBefore } from "../lib/format";
import { AI_TITLES, KIND_TITLES, RANGE_TITLES, SEVERITIES, STATE_TITLES, VERDICT_TITLES, OUTCOMES } from "../lib/labels";
import { optionText } from "../lib/optionText";
import { dashboardOptions, sinceOptions, threatOptions } from "../lib/queries";
import { parseSearch } from "../lib/search";
import { zoneLabel } from "../lib/site";

const OPEN_STATES = ["unreviewed", "follow_up", "changed_since_review"];
const TITLES: Record<ListName, Readonly<Record<string, string>>> = { severity: {}, state: STATE_TITLES, verdict: VERDICT_TITLES, ai: AI_TITLES };

function withState(f: Filters, patch: Partial<Filters>): Filters {
  return { ...f, ...patch };
}

function DashLink({ filters, children, title }: { filters: Filters; children: ReactNode; title?: string }) {
  return (
    <Link to="/dashboard" search={toSearch(filters)} title={title}>
      {children}
    </Link>
  );
}

function SinceCard() {
  const since = useQuery(sinceOptions);
  return (
    <Card aria-labelledby="since-title">
      <CardTitle id="since-title">Since your last visit</CardTitle>
      {since.isPending && <Loading what="what changed" />}
      {since.isError && <Problem error={since.error} what="What changed since your last visit" onRetry={() => void since.refetch()} />}
      {since.data && <SinceBody s={since.data} />}
    </Card>
  );
}

function SinceBody({ s }: { s: SinceOut }) {
  if (s.since === null || s.since === undefined) {
    return <p className="m-0 text-sm">This is your first visit, so there is nothing to compare with yet. Next time this shows what changed in between.</p>;
  }
  const n = (v: number) => capped(v, s.cap);
  return (
    <>
      <p className="m-0 mb-2 text-sm text-muted">
        Your previous visit ended <Time value={s.since} relative />.
      </p>
      <ul className="m-0 flex list-none flex-col gap-1 p-0 text-sm">
        <li>
          <strong>{n(s.new_investigations)}</strong> new {plural(s.new_investigations, "investigation")}
          {s.new_severe > 0 && <> ({n(s.new_severe)} rated critical or high)</>}.{" "}
          <Link to="/inbox" search={{ view: "all", sort: "newest" }}>
            Open the Inbox
          </Link>
        </li>
        <li>
          <strong>{n(s.reviewed_by_others)}</strong> {plural(s.reviewed_by_others, "investigation was", "investigations were")} decided by someone else.
        </li>
        <li>
          <strong>{n(s.new_proposals)}</strong> new {plural(s.new_proposals, "proposal")} from ARGUS.{" "}
          <Link to="/proposals">See the proposals</Link>
        </li>
      </ul>
    </>
  );
}

function ThreatCard({ f, open }: { f: Filters; open: number | undefined }) {
  const tile = useQuery({ ...threatOptions(f), placeholderData: keepPreviousData });
  return (
    <Card aria-labelledby="threat-title" aria-busy={tile.isFetching}>
      <CardTitle id="threat-title">Threat lists</CardTitle>
      {tile.isPending && <Loading what="the threat-list check" />}
      {tile.isError && <Problem error={tile.error} what="The threat-list check" onRetry={() => void tile.refetch()} />}
      {tile.data && <ThreatBody t={tile.data} open={open} />}
    </Card>
  );
}

function ThreatBody({ t, open }: { t: ThreatTileOut; open: number | undefined }) {
  if (t.examined === 0) return <p className="m-0 text-sm">No open investigation in this span, so nothing to check against the threat lists.</p>;
  return (
    <>
      <p className="m-0 mb-2 text-sm text-muted">
        The {count(t.examined)} most urgent open {plural(t.examined, "investigation")}
        {open !== undefined && open > t.examined ? ` (of ${count(open)})` : ""}, from what ARGUS already checked. It sends nothing to the SIEM.
      </p>
      <ul className="m-0 flex list-none flex-col gap-1 p-0 text-sm">
        <li>
          <strong>{count(t.on_a_list)}</strong> with an address or domain on a threat list
        </li>
        <li>
          <strong>{count(t.clear)}</strong> checked, nothing found
        </li>
        <li>
          <strong>{count(t.could_not_tell)}</strong> could not be told (a list was out of date, or a lookup did not finish): not the same as clear
        </li>
        <li>
          <strong>{count(t.not_checked)}</strong> not checked yet
        </li>
      </ul>
      {t.listed.length > 0 && (
        <ul className="m-0 mt-2 flex list-none flex-col gap-1 p-0 text-sm">
          {t.listed.map((c) => (
            <li key={c.id}>
              <Link to="/alert-groups/$id" params={{ id: c.id }}>
                <UntrustedText value={c.rule} limits={{ maxChars: 120, maxLines: 1 }} />
              </Link>{" "}
              <SeverityBadge severity={c.severity} />
            </li>
          ))}
        </ul>
      )}
    </>
  );
}

function Kpi({ label, value, sub, wrap }: { label: string; value: string; sub: ReactNode; wrap?: (children: ReactNode) => ReactNode }) {
  const body = (
    <>
      <span className="block text-xs font-medium text-muted">{label}</span>
      <strong className="block text-2xl font-semibold tabular-nums">{value}</strong>
      <span className="block text-xs text-muted">{sub}</span>
    </>
  );
  return <li className="rounded-card bg-surface p-3">{wrap ? wrap(body) : body}</li>;
}

function Kpis({ d, f }: { d: DashboardOut; f: Filters }) {
  const k = d.kpis;
  const link = (filters: Filters) => (children: ReactNode) => <DashLink filters={filters}>{children}</DashLink>;
  const reviewed = percent(k.reviewed, k.investigations, 1);
  return (
    <ul aria-label="Key numbers" className="m-0 grid list-none grid-cols-2 gap-3 p-0 sm:grid-cols-3 lg:grid-cols-5">
      <Kpi
        label="Incidents"
        value={count(k.incident_cases)}
        sub="confirmed cases not closed, now"
        wrap={(children) => (
          <Link to="/cases" search={{ view: "incidents" }}>
            {children}
          </Link>
        )}
      />
      <Kpi
        label="Possible incidents"
        value={count(k.possible_incidents)}
        sub="for a person to confirm or dismiss, now"
        wrap={(children) => (
          <Link to="/cases" search={{ view: "suspected" }}>
            {children}
          </Link>
        )}
      />
      <Kpi label="Alerts" value={count(k.alerts)} sub={versusBefore(k.alerts, k.alerts_before)} />
      <Kpi label="Investigations" value={count(k.investigations)} sub="active in the span" />
      <Kpi label="Open investigations" value={count(k.open)} sub="not reviewed, follow-up or changed" wrap={link(withState(f, { state: OPEN_STATES }))} />
      <Kpi
        label="Needs attention"
        value={count(k.attention)}
        sub="severe, follow-up or changed"
        wrap={(children) => (
          <Link to="/inbox" search={{ view: "attention" }}>
            {children}
          </Link>
        )}
      />
      <Kpi
        label="Notified, still active"
        value={count(k.known)}
        sub={`known, counted and not raised (${count(d.notified.length)} ${plural(d.notified.length, "case")})`}
        wrap={(children) => (
          <Link to="/inbox" search={{ view: "known" }}>
            {children}
          </Link>
        )}
      />
      <Kpi label="Open critical" value={count(k.open_critical)} sub="critical investigations not yet reviewed" wrap={link(withState(f, { severity: ["critical"], state: OPEN_STATES }))} />
      <Kpi label="Called real by a person" value={count(k.incidents)} sub="investigations decided “Real: act on it”" wrap={link(withState(f, { verdict: ["true_positive"] }))} />
      <Kpi label="Called real by ARGUS" value={count(k.suspected)} sub="investigations ARGUS calls real; nobody decided yet" wrap={link(withState(f, { ai: ["proposed_tp"], state: OPEN_STATES }))} />
      <Kpi label="Reviewed" value={count(k.reviewed)} sub={reviewed ? `${reviewed} of the investigations` : "—"} />
      <Kpi label="Time to first review" value={duration(k.median_review_s)} sub="median, from the first alert" />
      <Kpi label="Assessed by ARGUS" value={percent(k.assessed, k.investigations) ?? "—"} sub={`${count(k.assessed)} of ${count(k.investigations)} investigations`} />
    </ul>
  );
}

function TimeChart({ d }: { d: DashboardOut }) {
  const hourly = d.bucket === "hour";
  const rows = d.series;
  const columns: Column<(typeof rows)[number]>[] = [
    { key: "at", header: `${hourly ? "Hour" : "Day"} (${zoneLabel()})`, cell: (r) => <Time value={r.at} /> },
    ...SEVERITIES.map((s) => ({ key: s, header: s, numeric: true, cell: (r: (typeof rows)[number]) => count(r.counts[s] ?? 0) })),
    { key: "all", header: "All", numeric: true, cell: (r) => count(sum(Object.values(r.counts))) },
  ];
  return (
    <Card aria-labelledby="time-title">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <CardTitle id="time-title">Alerts over time</CardTitle>
        <ul aria-hidden="true" className="m-0 flex list-none gap-3 p-0 text-xs text-muted">
          {SEVERITIES.map((s) => (
            <li key={s}>{s}</li>
          ))}
        </ul>
      </div>
      <StackedBars series={rows.map((r) => ({ at: r.at, counts: r.counts }))} order={["low", "medium", "high", "critical", "unknown"]} hourly={hourly} label={`Alerts per ${d.bucket} by severity`} />
      <details className="mt-2">
        <summary className="cursor-pointer text-sm font-medium">As a table</summary>
        <DataTable reachable caption={`Alerts per ${d.bucket} by severity`} columns={columns} rows={rows} rowKey={(r) => r.at} />
      </details>
    </Card>
  );
}

function Breakdown({ title, counts, name, titles, fills, f }: { title: string; counts: Record<string, number>; name: ListName; titles: Readonly<Record<string, string>>; fills: Readonly<Record<string, string>>; f: Filters }) {
  const total = sum(Object.values(counts));
  const rows = Object.entries(counts).sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1));
  return (
    <Card aria-label={title}>
      <CardTitle>{title}</CardTitle>
      <SplitBar counts={counts} titles={titles} fills={fills} label={`${title}: ${count(total)} in all`} />
      <DataTable
        className="mt-2"
        caption={title}
        rows={rows}
        rowKey={([key]) => key}
        empty="None."
        columns={[
          {
            key: "name",
            header: "Name",
            cell: ([key]) => (
              <DashLink filters={adding(f, name, key)}>
                {titles[key] ?? <UntrustedText value={key.replaceAll("_", " ")} limits={{ maxChars: 60, maxLines: 1 }} />}
              </DashLink>
            ),
          },
          { key: "n", header: "Investigations", numeric: true, cell: ([, n]) => count(n) },
        ]}
      />
    </Card>
  );
}

function Briefs({ title, hint, items, caption, empty, footer }: { title: string; hint?: string; items: InvestigationBrief[]; caption: string; empty: string; footer?: ReactNode }) {
  return (
    <Card aria-label={title}>
      <CardTitle>{title}</CardTitle>
      {hint && <p className="m-0 mb-2 text-sm text-muted">{hint}</p>}
      <DataTable
        caption={caption}
        rows={items}
        rowKey={(c) => c.id}
        empty={empty}
        columns={[
          {
            key: "inv",
            header: "Investigation",
            cell: (c) => (
              <>
                <Link to="/alert-groups/$id" params={{ id: c.id }}>
                  <UntrustedText value={c.rule} limits={{ maxChars: 120, maxLines: 1 }} />
                </Link>
                <div className="text-xs text-muted">
                  {c.key_fields.length === 0 ? "single alert" : c.key_fields.map((k, i) => (
                    <span key={i} className="font-mono">
                      {i > 0 && " · "}
                      <UntrustedText value={`${k.field} ${String(k.value ?? "")}`} limits={{ maxChars: 120, maxLines: 1 }} />
                    </span>
                  ))}
                </div>
              </>
            ),
          },
          { key: "sev", header: "Severity", cell: (c) => <SeverityBadge severity={c.severity} /> },
          { key: "last", header: "Last alert", cell: (c) => <Time value={c.last_event_at} /> },
          { key: "alerts", header: "Alerts", numeric: true, cell: (c) => count(c.alert_count) },
          { key: "state", header: "State", cell: (c) => <StateChip state={c.state} /> },
          { key: "inc", header: "Called real", cell: (c) => (c.verdict === "true_positive" ? "by a person" : c.ai === "proposed_tp" ? "by ARGUS" : "—") },
        ]}
      />
      {footer}
    </Card>
  );
}

const REMINDER_WORDS: Record<NotifiedBrief["reminders"][number], string> = {
  notify_again: "Tell the owner again: it is still active",
  network_action: "Ask for a block at the network: it is still active",
};

/** AR4b: the devices whose owner was told. They stay infected until the owner acts, so their alerts keep coming; ARGUS counts them and raises one again only if something changes. */
function NotifiedTable({ rows }: { rows: NotifiedBrief[] }) {
  return (
    <Card aria-label="Notified, still active">
      <CardTitle>Notified, still active</CardTitle>
      <p className="m-0 mb-2 text-sm text-muted">Devices whose owner was told. They stay infected until the owner acts, so their alerts keep coming; ARGUS counts them here and raises one again only if something changes.</p>
      <DataTable
        caption="Notified cases"
        rows={rows}
        rowKey={(c) => c.case_id}
        columns={[
          {
            key: "case",
            header: "Case",
            cell: (c) => (
              <>
                <Link to="/cases/$id" params={{ id: c.case_id }}>
                  Case {c.case_number}
                </Link>
                <div className="text-xs text-muted">
                  <UntrustedText value={c.title} limits={{ maxChars: 120, maxLines: 1 }} />
                </div>
              </>
            ),
          },
          { key: "told", header: "Owner told", cell: (c) => <Time value={c.notified_at} /> },
          { key: "days", header: "Days", numeric: true, cell: (c) => count(c.days) },
          { key: "alerts", header: "Alerts since", numeric: true, cell: (c) => count(c.alerts) },
          { key: "trend", header: "Alerts a day", cell: (c) => c.trend },
          { key: "block", header: "Network block", cell: (c) => (c.blocked ? "recorded" : <span className="text-muted">none yet</span>) },
          { key: "due", header: "Suggestions", cell: (c) => (c.reminders.length === 0 ? <span className="text-muted">none due</span> : c.reminders.map((r) => <div key={r}>{REMINDER_WORDS[r]}</div>)) },
        ]}
      />
    </Card>
  );
}

function FilterForm({ d, f }: { d: DashboardOut | undefined; f: Filters }) {
  const navigate = useNavigate();
  const id = useId();
  const more = f.verdict.length > 0 || f.ai.length > 0 || f.kind !== null || f.start !== null;
  const rules = d?.rule_choices ?? [];
  const rule = f.rule !== null && !rules.some((r) => r.rule_id === f.rule) ? [{ rule_id: f.rule, rule: f.rule }, ...rules] : rules;
  return (
    <form
      key={JSON.stringify(toSearch(f))}
      aria-label="Filters"
      className="flex flex-col gap-3 rounded-card bg-surface p-3"
      onSubmit={(e) => {
        e.preventDefault();
        const next = parseFilters(parseSearch(new URLSearchParams(new FormData(e.currentTarget) as unknown as Record<string, string>).toString()));
        void navigate({ to: "/dashboard", search: toSearch(next) });
      }}
    >
      <div className="flex flex-wrap items-end gap-x-4 gap-y-2">
        <Field label="Time" htmlFor={`${id}-range`}>
          <Select id={`${id}-range`} name="range" defaultValue={f.range}>
            {Object.entries(RANGE_TITLES).map(([key, title]) => (
              <option key={key} value={key}>
                {title}
              </option>
            ))}
          </Select>
        </Field>
        <fieldset className="m-0 flex flex-wrap gap-x-3 border-0 p-0">
          <legend className="mb-1 p-0 text-sm font-medium">Severity</legend>
          {SEVERITIES.map((s) => (
            <Check key={s} name="severity" value={s} defaultChecked={f.severity.includes(s)}>
              {s}
            </Check>
          ))}
        </fieldset>
        <fieldset className="m-0 flex flex-wrap gap-x-3 border-0 p-0">
          <legend className="mb-1 p-0 text-sm font-medium">State</legend>
          {validList("state").map((s) => (
            <Check key={s} name="state" value={s} defaultChecked={f.state.includes(s)}>
              {STATE_TITLES[s]}
            </Check>
          ))}
        </fieldset>
        <Field label="Rule" htmlFor={`${id}-rule`} className="min-w-48 flex-1">
          <Select id={`${id}-rule`} name="rule" defaultValue={f.rule ?? ""}>
            <option value="">All rules</option>
            {rule.map((r) => (
              <option key={r.rule_id} value={r.rule_id}>
                {optionText(r.rule)}
              </option>
            ))}
          </Select>
        </Field>
      </div>
      <details open={more}>
        <summary className="cursor-pointer text-sm font-medium">More filters: verdict, AI, host or IP, dates</summary>
        <div className="mt-2 flex flex-wrap items-end gap-x-4 gap-y-2">
          <fieldset className="m-0 flex flex-wrap gap-x-3 border-0 p-0">
            <legend className="mb-1 p-0 text-sm font-medium">Person&apos;s verdict</legend>
            {validList("verdict").map((v) => (
              <Check key={v} name="verdict" value={v} defaultChecked={f.verdict.includes(v)}>
                {v === "none" ? "No verdict yet" : OUTCOMES[v]}
              </Check>
            ))}
          </fieldset>
          <fieldset className="m-0 flex flex-wrap gap-x-3 border-0 p-0">
            <legend className="mb-1 p-0 text-sm font-medium">ARGUS&apos;s assessment</legend>
            {validList("ai").map((a) => (
              <Check key={a} name="ai" value={a} defaultChecked={f.ai.includes(a)}>
                {AI_TITLES[a]}
              </Check>
            ))}
          </fieldset>
          <Field label="Kind" htmlFor={`${id}-kind`}>
            <Select id={`${id}-kind`} name="kind" defaultValue={f.kind ?? ""}>
              <option value="">—</option>
              {Object.entries(KIND_TITLES).map(([key, title]) => (
                <option key={key} value={key}>
                  {title}
                </option>
              ))}
            </Select>
          </Field>
          <Field label="Value" htmlFor={`${id}-value`} className="min-w-48 flex-1">
            <TextInput id={`${id}-value`} name="value" maxLength={300} defaultValue={f.value ?? ""} placeholder="e.g. 10.201.7.13" />
          </Field>
          <Field label="From" htmlFor={`${id}-start`}>
            <TextInput id={`${id}-start`} type="date" name="start" defaultValue={f.start ?? ""} />
          </Field>
          <Field label="To" htmlFor={`${id}-end`}>
            <TextInput id={`${id}-end`} type="date" name="end" defaultValue={f.end ?? ""} />
          </Field>
        </div>
        <p className="m-0 mt-1 text-xs text-muted">Both dates set a custom span ({zoneLabel()} days) instead of the time menu.</p>
      </details>
      <div className="flex gap-2">
        <Button type="submit" variant="primary">
          Apply
        </Button>
        <Link to="/dashboard" className="inline-flex min-h-8 items-center px-2">
          Reset
        </Link>
      </div>
    </form>
  );
}

/** The SOC dashboard (D-103) in the app: the classic page's numbers from /api/v1/dashboard, a table for every chart. */
export function Dashboard({ search }: { search: Record<string, unknown> }) {
  const f = parseFilters(search);
  const dash = useQuery({ ...dashboardOptions(f), placeholderData: keepPreviousData });
  const d = dash.data;
  const active = chips(f, TITLES);
  return (
    <>
      <div>
        <h1 className="page-h">Dashboard</h1>
        <p className="m-0 text-sm text-muted">
          {d ? (
            <>
              {f.start !== null && f.end !== null ? `From ${f.start} to ${f.end} (${zoneLabel()})` : RANGE_TITLES[f.range]}: <Time value={d.start} /> to <Time value={d.end} />. From ARGUS&apos;s own records; opening or filtering this page sends nothing to the SIEM.
            </>
          ) : (
            "From ARGUS's own records; opening or filtering this page sends nothing to the SIEM."
          )}
        </p>
      </div>
      <FilterForm d={d} f={f} />
      {active.length > 0 && (
        <ul aria-label="Active filters" className="m-0 flex list-none flex-wrap items-center gap-2 p-0 text-sm">
          {active.map((c) => (
            <li key={`${c.name}:${c.value}`} className="inline-flex items-center gap-1 rounded-full bg-surface-2 py-0.5 pr-1 pl-2">
              <span>
                {c.name}: <UntrustedText value={c.value} limits={{ maxChars: 120, maxLines: 1 }} />
              </span>
              <Link to="/dashboard" search={toSearch(c.without)} aria-label={`Remove ${c.name}: ${optionText(c.value, 120)}`} className="px-1 no-underline">
                ×
              </Link>
            </li>
          ))}
          <li>
            <DashLink filters={cleared(f)}>Clear all</DashLink>
          </li>
        </ul>
      )}
      {dash.isError && <Problem error={dash.error} what="The dashboard" onRetry={() => void dash.refetch()} />}
      {dash.isPending && <Loading what="the dashboard" />}
      <div className="grid gap-4 lg:grid-cols-2">
        <SinceCard />
        <ThreatCard f={f} open={d?.kpis.open} />
      </div>
      {d && (
        <div className="flex flex-col gap-4" aria-busy={dash.isFetching}>
          <Kpis d={d} f={f} />
          <TimeChart d={d} />
          <div className="grid gap-4 md:grid-cols-2">
            <Breakdown title="Investigations by state" counts={d.states} name="state" titles={STATE_TITLES} fills={STATE_FILL} f={f} />
            <Breakdown title="Investigations by severity" counts={d.severities} name="severity" titles={{}} fills={SEVERITY_FILL} f={f} />
            <Breakdown title="Person's verdict" counts={d.verdicts} name="verdict" titles={VERDICT_TITLES} fills={VERDICT_FILL} f={f} />
            <Breakdown title="ARGUS's assessment" counts={d.ai} name="ai" titles={AI_TITLES} fills={AI_FILL} f={f} />
          </div>
          <Card aria-label="Top rules by alerts">
            <CardTitle>Top rules by alerts</CardTitle>
            <DataTable
              caption="Top rules by alerts"
              rows={d.rules}
              rowKey={(r) => r.rule_id}
              empty="No rule in this span."
              columns={[
                { key: "rule", header: "Rule", cell: (r) => <DashLink filters={adding(f, "rule", r.rule_id)}><UntrustedText value={r.rule} limits={{ maxChars: 120, maxLines: 1 }} /></DashLink> },
                { key: "sev", header: "Severity", cell: (r) => (r.severity ? <SeverityBadge severity={r.severity} /> : null) },
                { key: "alerts", header: "Alerts", numeric: true, cell: (r) => count(r.alerts) },
                { key: "inv", header: "Investigations", numeric: true, cell: (r) => count(r.investigations) },
                { key: "open", header: "Open", numeric: true, cell: (r) => count(r.open) },
                { key: "incidents", header: "Real (a person)", numeric: true, cell: (r) => count(r.incidents) },
                { key: "suspected", header: "Real (ARGUS)", numeric: true, cell: (r) => count(r.suspected) },
                { key: "go", header: <span className="sr-only">Inbox</span>, cell: (r) => <Link to="/inbox" search={{ view: "open", rule: r.rule_id }}>open investigations</Link> },
              ]}
            />
          </Card>
          <div className="grid gap-4 md:grid-cols-2">
            {(["ip", "host", "domain", "user"] as const).map((kind) => (
              <Card key={kind} aria-label={`Top ${KIND_TITLES[kind]}s`}>
                <CardTitle>{`Top ${kind === "ip" ? "IP addresses" : `${kind}s`}`}</CardTitle>
                <DataTable
                  caption={`Top ${kind === "ip" ? "IP addresses" : `${kind}s`}`}
                  rows={d.entities[kind] ?? []}
                  rowKey={(e) => e.value}
                  empty="None in this span."
                  columns={[
                    { key: "v", header: KIND_TITLES[kind] ?? kind, cell: (e) => <DashLink filters={adding(f, "entity", e.value, kind)}><span className="font-mono"><UntrustedText value={e.value} limits={{ maxChars: 80, maxLines: 1 }} /></span></DashLink> },
                    { key: "inv", header: "Investigations", numeric: true, cell: (e) => count(e.investigations) },
                    { key: "open", header: "Open", numeric: true, cell: (e) => count(e.open) },
                    { key: "alerts", header: "Alerts", numeric: true, cell: (e) => count(e.alerts) },
                  ]}
                />
              </Card>
            ))}
          </div>
          <Briefs title="Investigations called real" hint="By a person: their decision is “Real: act on it”. By ARGUS: ARGUS calls it real and nobody has decided yet; decide it on the investigation. Incidents themselves are cases: see Cases." items={d.incidents} caption="Investigations called real" empty="None in this span." />
          {d.notified.length > 0 && <NotifiedTable rows={d.notified} />}
          <Briefs
            title="Open investigations, most urgent first"
            items={d.open_investigations}
            caption="Open investigations"
            empty="No open investigation in this span."
            footer={d.open_investigations.length > 0 ? <p className="m-0 mt-2 text-sm"><Link to="/inbox" search={{ view: "open", sort: "urgent" }}>All open investigations in the Inbox</Link></p> : undefined}
          />
        </div>
      )}
    </>
  );
}

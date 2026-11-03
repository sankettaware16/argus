// Health, Glossary and Metrics (the classic pages /health, /glossary and /metrics). Gap details and
// provider names come from SIEM and model data: untrusted text.
import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import type { ReactNode } from "react";
import type { GapOut, HealthOut, MetricsOut } from "../client/types.gen";
import { Loading, Problem } from "../components/Problem";
import { Time } from "../components/Time";
import { UntrustedText } from "../components/UntrustedText";
import { Badge, type Tone } from "../components/ui/badge";
import { Card, CardTitle } from "../components/ui/card";
import { DataTable } from "../components/ui/table";
import { count } from "../lib/format";
import { OUTCOMES } from "../lib/labels";
import { own } from "../lib/site";
import { glossaryOptions, healthPageOptions, metricsOptions } from "../lib/queries";
import { SIEM } from "../shell/Status";

function Row({ term, children }: { term: string; children: ReactNode }) {
  return (
    <div className="grid gap-x-4 gap-y-0.5 border-b border-border py-2 last:border-b-0 sm:grid-cols-[14rem_1fr]">
      <dt className="text-sm font-medium">{term}</dt>
      <dd className="m-0 min-w-0 text-sm">{children}</dd>
    </div>
  );
}

function Gap({ g }: { g: GapOut }) {
  return (
    <li>
      <strong>{g.kind.replaceAll("_", " ")}</strong> since <Time value={g.start_at} />
      {g.detail != null && g.detail !== "" && (
        <>
          {" "}
          (<UntrustedText value={g.detail} limits={{ maxChars: 80, maxLines: 1 }} />)
        </>
      )}
      : alerts from this time may be missing until it closes.
    </li>
  );
}

function HealthBody({ h }: { h: HealthOut }) {
  const [tone, word] = SIEM[h.siem_state] ?? (["neutral", "unknown"] as [Tone, string]);
  const r = h.last_reconciliation;
  return (
    <>
      <dl className="m-0">
        <Row term="SIEM">
          <Badge tone={tone}>{word}</Badge>
          {h.siem_reasons.length > 0 && <> ({h.siem_reasons.join(", ")})</>}
          {h.siem_probed_at != null && (
            <>
              , checked <Time value={h.siem_probed_at} />
            </>
          )}
        </Row>
        <Row term="Alerts collected up to">{h.live_cursor != null ? <Time value={h.live_cursor} /> : <span className="text-muted">not yet</span>}</Row>
        <Row term="History loaded back to">{h.backfill_cursor != null ? <Time value={h.backfill_cursor} /> : <span className="text-muted">not yet</span>}</Row>
        <Row term="Stored">
          {count(h.alerts)} alerts ({count(h.quarantined)} could not be read), {count(h.investigations)} investigations, {count(h.jobs_waiting)} waiting for work
        </Row>
        <Row term="Investigation work">
          {count(h.dossiers)} dossiers written
          {h.jobs_deferred > 0 && <>, {count(h.jobs_deferred)} waiting for the SIEM to be available</>}
          {h.jobs_failed > 0 && <>, {count(h.jobs_failed)} could not be completed</>}; {count(h.checkpoint_threads)} runs in progress ({count(Math.round(h.checkpoint_bytes / 1024))} KiB)
        </Row>
        {r != null && (
          <Row term="Last check against the SIEM">
            <Time value={r.finished_at} />: {count(r.hours)} hours, {count(r.hours_mismatched)} differed, {count(r.recovered)} recovered ({r.outcome})
          </Row>
        )}
      </dl>
      <h2 className="m-0 mt-2 text-lg font-semibold">Coverage gaps</h2>
      {h.open_gaps.length > 0 ? (
        <ul className="m-0 pl-5 text-sm">
          {h.open_gaps.map((g, i) => (
            <Gap key={`${g.kind}-${g.subject}-${i}`} g={g} />
          ))}
        </ul>
      ) : (
        <p className="m-0 text-sm text-muted">None open.</p>
      )}
    </>
  );
}

export function Health() {
  const health = useQuery(healthPageOptions);
  return (
    <>
      <h1 className="m-0 text-2xl font-semibold">Health</h1>
      <p className="m-0 max-w-prose text-sm text-muted">Whether data is arriving from the SIEM and any gaps. A gap means unknown, never clean.</p>
      {health.isPending && <Loading what="the health" />}
      {health.isError && <Problem error={health.error} what="The health" onRetry={() => void health.refetch()} />}
      {health.data && <HealthBody h={health.data} />}
    </>
  );
}

const PAGES: [ReactNode, string][] = [
  [<Link to="/">Home</Link>, "What needs you today: cases, approvals and the investigations that need a look."],
  [<Link to="/inbox" search={{ view: "attention" }}>Needs attention</Link>, "Start here. Follow-ups, investigations that changed since someone reviewed them, and unreviewed ones the rule rates high or critical."],
  [<Link to="/inbox" search={{ view: "open" }}>Not reviewed</Link>, "Every investigation nobody has reviewed yet. The AI column shows ARGUS's assessment."],
  [<Link to="/inbox" search={{ view: "reviewed" }}>Reviewed</Link>, "Investigations already decided: the decision, who made it, when."],
  [<Link to="/inbox" search={{ view: "all" }}>All</Link>, 'Every investigation. Lists are sorted newest first by default (by the last alert); "most urgent first" and "oldest first" are a click away.'],
  [<><Link to="/rules">By rule</Link> · <Link to="/hosts">By host or IP</Link></>, "The same investigations, per detection rule, or per host, IP address, domain or user."],
  [<Link to="/patterns">Patterns</Link>, "Groups of investigations that look alike (same rule, same step results, same key values), to review in one go."],
  [<Link to="/cases" search={{ view: "active" }}>Cases</Link>, "Confirmed cases and what is being done about them: who owns each, what is new, what to ask next."],
  [<Link to="/approvals">Approvals</Link>, "Closures and merges that wait for a second person to look at the exact changes and decide."],
  [<Link to="/proposals">Proposals</Link>, "Outcomes ARGUS proposes, grouped by rule; open the random audit sample of a group, then confirm the group. Nothing is closed in Kibana by confirming."],
  [<Link to="/reports">Reports</Link>, "The daily and weekly reports: what waits for a person, what happened, what went wrong. Every figure says how it was counted."],
  [<Link to="/tuning">Tuning</Link>, "Each rule's weekly report: how much it fires, how often a run hit its alert limit, your verdicts, and suggested changes backed by them. You apply them in Kibana; ARGUS never edits a rule."],
  [<Link to="/gold">Gold set</Link>, "The answer key: real investigations whose correct outcome you confirmed. ARGUS's scores are measured against it."],
  [<Link to="/health">Health</Link>, "Whether data is arriving from the SIEM and any gaps (a gap means unknown, never clean)."],
  [<Link to="/metrics">Metrics</Link>, "How the assessments and the AI connection are doing: results, waiting work, refusals, fallbacks, cost and limits."],
  ["AI cost (the bar at the top)", "What the paid AI provider has cost this month against the $10 cap. From $8 on, normal work uses only the free providers."],
];

const assessment = (): [string, string][] => [
  ["Decision engine", "Proposes an outcome only when at least 5 of people's past verdicts on the same kind of alert agree (95%), none older than 30 days. No AI involved."],
  ["AI investigator", `Reads the evidence with ${own("names")} and addresses hidden, may ask the SIEM for more (a fixed list of read-only checks), weighs hypotheses with the facts for and against each, and must quote the facts it relies on. Its tab shows all of it.`],
  ["No proposal", "ARGUS could not decide, or was not allowed to: it never proposes a harmless outcome while a danger sign (a threat-list hit, success after an attack, a beacon, a rare destination, high severity, something new) is present or unknown. The page says which."],
  ["Ask the AI investigator now", "On any investigation, reviewed or not: the AI looks at it within a few minutes. The free AI providers are asked first, the paid one only if none can answer (about a US cent)."],
];

const REPORT: [string, string][] = [
  ["E-numbers (E1, E2 …)", 'Each request ARGUS made to the SIEM for an investigation has its own number, kept for good. Every fact in the report names the requests it comes from; "the alerts" means ARGUS\'s own store of them.'],
  ["What ARGUS found with extra SIEM queries", "What the SIEM checks added to what the alerts alone say: new facts, checks that found nothing, checks that could not tell (a zero from logs ARGUS cannot yet trust, an out-of-date threat list, a check that waits for another), checks that failed or were not checked, and what is still open, with who can resolve it."],
  ["Evidence strength", "A count of what ARGUS could check (the signals that block a harmless proposal, the SIEM checks, the rule's steps, the alerts read), separate from any confidence."],
  ["Where each fact came from", "One line per request: the check, the logs or list it read and the time window, how many rows, whether the answer was complete, the SIEM's server time."],
];

const CHECKED: [ReactNode, string][] = [
  [<Badge tone="ok">Answered</Badge>, "A step of the rule's own note that the stored alerts (or a check ARGUS made) answer; the values are shown."],
  [<Badge>Not checked yet</Badge>, "The step needs logs or threat intel that ARGUS does not query yet; it says which check will answer it."],
  [<Badge tone="info">For you</Badge>, "An action or a judgement for a person, such as blocking an address or notifying an owner."],
  [<Badge>No data</Badge>, "The step names a field that none of the alerts carries."],
  ["“Could not be told”", 'ARGUS does not know, for the reason given: never read it as "no" or "none".'],
  ["“At least”", "A count from incomplete data: the real number may be higher."],
];

function Entry({ term, children }: { term: ReactNode; children: ReactNode }) {
  return (
    <div className="grid gap-x-4 gap-y-0.5 border-b border-border py-2 last:border-b-0 sm:grid-cols-[14rem_1fr]">
      <dt className="text-sm font-medium">{term}</dt>
      <dd className="m-0 min-w-0 text-sm">{children}</dd>
    </div>
  );
}

function Section({ title, rows }: { title: string; rows: [ReactNode, string][] }) {
  return (
    <section aria-label={title} className="flex flex-col gap-1">
      <h2 className="m-0 text-lg font-semibold">{title}</h2>
      <dl className="m-0">
        {rows.map(([term, text], i) => (
          <Entry key={i} term={term}>
            {text}
          </Entry>
        ))}
      </dl>
    </section>
  );
}

export function Glossary() {
  const terms = useQuery(glossaryOptions);
  return (
    <>
      <h1 className="m-0 text-2xl font-semibold">Glossary</h1>
      <Section title="The pages" rows={PAGES} />
      <Section title="ARGUS's assessment of an investigation" rows={assessment()} />
      <Section title="The full report" rows={REPORT} />
      <Section title="What ARGUS checked" rows={CHECKED} />
      <section aria-label="Facts and signals" className="flex flex-col gap-1">
        <h2 className="m-0 text-lg font-semibold">Facts and signals</h2>
        {terms.isPending && <Loading what="the terms" />}
        {terms.isError && <Problem error={terms.error} what="The terms" onRetry={() => void terms.refetch()} />}
        {terms.data && (
          <dl className="m-0">
            {terms.data.map((t) => (
              <Entry key={t.name} term={t.label}>
                {t.how}
              </Entry>
            ))}
          </dl>
        )}
      </section>
    </>
  );
}

const MONEY4 = (n: number) => `$${n.toFixed(4)}`;
const word = (key: string) => (OUTCOMES[key] ?? key.replaceAll("_", " ")).replaceAll("_", " ");

function Assessments({ m }: { m: MetricsOut }) {
  const by = new Map<string, string[]>();
  for (const o of m.outcomes) by.set(o.assessor, [...(by.get(o.assessor) ?? []), `${word(o.label)} ${count(o.count)}`]);
  const rows = [...by.entries()];
  return (
    <Card aria-label="Assessments">
      <CardTitle>Assessments (7 days)</CardTitle>
      <DataTable<[string, string[]]>
        caption="Assessments by assessor"
        rows={rows}
        rowKey={(r) => r[0]}
        empty="None yet."
        columns={[
          { key: "assessor", header: "Assessor", cell: (r) => <UntrustedText value={r[0]} limits={{ maxChars: 40, maxLines: 1 }} /> },
          { key: "results", header: "Results", cell: (r) => r[1].join(", ") },
        ]}
      />
      <p className="m-0 mt-2 text-sm">Benign answers stopped by the safety floor: {count(m.floor_hits)}.</p>
      <h3 className="m-0 mt-2 text-sm font-semibold">Waiting</h3>
      {m.backlog.length > 0 ? (
        <ul className="m-0 pl-5 text-sm">
          {m.backlog.map((b) => (
            <li key={b.assessor}>
              <UntrustedText value={b.assessor} limits={{ maxChars: 40, maxLines: 1 }} />: {count(b.waiting)}
              {b.oldest_wait_s != null && <>, the oldest for {count(Math.floor(b.oldest_wait_s / 60))} minutes</>}
            </li>
          ))}
        </ul>
      ) : (
        <p className="m-0 text-sm text-muted">Nothing waiting.</p>
      )}
    </Card>
  );
}

function Models({ m }: { m: MetricsOut }) {
  return (
    <Card aria-label="AI models">
      <CardTitle>AI models</CardTitle>
      <p className="m-0 text-sm">
        {m.stopped ? (
          <>
            <Badge tone="danger">Stopped by the kill switch</Badge> (<code>argus llm resume</code>).
          </>
        ) : (
          "Calls allowed."
        )}{" "}
        This month: {MONEY4(m.month_cost_usd)}.
      </p>
      <p className="m-0 mb-2 text-sm">
        Requests the leak validator refused (7 days): {count(m.validator_blocks)}. Answers that came from a fallback provider (24 h): {count(m.fallbacks)}.
      </p>
      {m.calls.length > 0 && (
        <DataTable<MetricsOut["calls"][number]>
          caption="Calls by provider, last 24 hours"
          rows={m.calls}
          rowKey={(c) => c.provider}
          columns={[
            { key: "provider", header: "Provider (24 h)", cell: (c) => <UntrustedText value={c.provider} limits={{ maxChars: 40, maxLines: 1 }} /> },
            { key: "attempts", header: "Attempts", numeric: true, cell: (c) => count(c.attempts) },
            { key: "ok", header: "Answered", numeric: true, cell: (c) => count(c.ok) },
            { key: "cost", header: "Cost", numeric: true, cell: (c) => MONEY4(c.cost_usd) },
          ]}
        />
      )}
      {m.quota.length > 0 && (
        <>
          <h3 className="m-0 mt-2 text-sm font-semibold">Today against the limits</h3>
          <ul className="m-0 pl-5 text-sm">
            {m.quota.map((q) => (
              <li key={q.bucket}>
                <UntrustedText value={q.bucket} limits={{ maxChars: 80, maxLines: 1 }} />: <UntrustedText value={q.usage} limits={{ maxChars: 80, maxLines: 1 }} />
              </li>
            ))}
          </ul>
        </>
      )}
    </Card>
  );
}

export function Metrics() {
  const metrics = useQuery(metricsOptions);
  return (
    <>
      <h1 className="m-0 text-2xl font-semibold">Metrics</h1>
      <p className="m-0 max-w-prose text-sm text-muted">How ARGUS&apos;s assessments and its connection to AI models are doing.</p>
      {metrics.isPending && <Loading what="the metrics" />}
      {metrics.isError && <Problem error={metrics.error} what="The metrics" onRetry={() => void metrics.refetch()} />}
      {metrics.data && (
        <>
          <Assessments m={metrics.data} />
          <Models m={metrics.data} />
        </>
      )}
    </>
  );
}

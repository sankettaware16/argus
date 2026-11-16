import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useMemo, useState, type ReactNode } from "react";
import { addCaseNote } from "../../client/sdk.gen";
import type { CaseDetail, CaseMemberOut, CaseReportOut, HistoryItemOut, IncidentReport, ReportEvidenceLine } from "../../client/types.gen";
import { useAnnounce } from "../../lib/announce";
import { unwrap } from "../../lib/call";
import { entityKind, isPrivateIp, nounFor, side, sidesWithoutEngine, stateWords, type Engine, type EngineObject } from "../../lib/engine";
import { callWords } from "../../lib/incident";
import { plainWords } from "../../lib/plainWords";
import { count, plural } from "../../lib/format";
import { OUTCOMES } from "../../lib/labels";
import { changed, changedCase, investigationOptions } from "../../lib/queries";
import { can, useSession } from "../../lib/session";
import { parse } from "../../lib/time";
import { clock, dayAndTime, weekdayDay } from "../../lib/when";
import { CaseActions } from "../cases/CaseActions";
import { MirrorSection } from "../cases/CaseSections";
import { NeedsCapability } from "../investigation/actions";
import { KnownSection } from "../cases/KnownSections";
import { NoteForm } from "../cases/NoteForm";
import { ReportSection } from "../cases/ReportSection";
import { TeamSection } from "../cases/TeamSection";
import { CheckMore } from "../investigation/CheckMore";
import { sendShown } from "../decide/target";
import { Time } from "../Time";
import { UntrustedText } from "../UntrustedText";
import { Button } from "../ui/button";
import { cisoSent } from "./Ciso";
import { Glance } from "./Glance";

type ReportRead = { data: CaseReportOut | undefined };

function Chips<T extends string>({ value, onChange, options, label }: { value: T; onChange: (v: T) => void; options: readonly [T, string][]; label: string }) {
  return (
    <div role="group" aria-label={label} className="flex flex-wrap gap-1">
      {options.map(([v, words]) => (
        <Button key={v} size="sm" variant={value === v ? "primary" : "secondary"} aria-pressed={value === v} onClick={() => onChange(v)}>
          {words}
        </Button>
      ))}
    </div>
  );
}

// ------------------------------------------------------------------ Story (§7.4)

/** Why an alert group is in the incident, in words (§7.4's table). */
export function linkWords(m: Pick<CaseMemberOut, "link" | "link_value" | "added_by">): string {
  const v = m.link_value ?? "";
  switch (m.link) {
    case "actor":
      return `same outside address ${v}`.trim();
    case "indicator":
      return `same indicator ${v}`.trim();
    case "c2":
      return `same command server ${v}`.trim();
    case "verdict":
      return "a person called it real";
    case "proposal":
      return "ARGUS proposed it";
    case "person":
      return `added by ${m.added_by}`;
    case "merge":
      return "came with a merged incident";
    default:
      return m.link_value && m.link_value.includes(" ") ? m.link_value : "linked by ARGUS";
  }
}

type Who = "groups" | "argus" | "people";
interface Line {
  at: string;
  who: Who;
  text: string;
  why: string | null;
  group: string | null;
}

function TalkedTo({ engine, report }: { engine: Engine | null; report: IncidentReport | null }) {
  const [list, setList] = useState(false);
  const left = engine ? side(engine, "affected") : (report?.assets ?? []).map((a) => ({ kind: "device" as const, label: a.value, role: "affected" as const }));
  const right = engine ? side(engine, "actor") : (report?.actors ?? []).filter((a) => !a.inside && !isPrivateIp(a.value)).map((a) => ({ kind: "device" as const, label: a.value, role: "actor" as const }));
  if (left.length === 0 || right.length === 0) return null;
  const L = left.slice(0, 8);
  const R = right.slice(0, 8);
  const rowH = 28;
  const h = Math.max(L.length, R.length) * rowH + 8;
  const y = (i: number, n: number) => 4 + (i + 0.5) * ((h - 8) / n);
  return (
    <section aria-labelledby="talked-h" data-testid="talked-to" className="flex flex-col gap-2">
      <div className="flex items-baseline justify-between gap-2">
        <h2 id="talked-h" className="m-0 text-base font-semibold">
          Who talked to what
        </h2>
        <Button size="sm" variant="ghost" aria-pressed={list} onClick={() => setList(!list)}>
          {list ? "Show as a picture" : "Show as a list"}
        </Button>
      </div>
      {list ? (
        <table className="w-full max-w-2xl border-collapse text-sm" data-testid="talked-list">
          <thead>
            <tr className="border-b border-border text-left text-muted">
              <th className="py-1 font-medium">Campus side</th>
              <th className="py-1 font-medium">Other side</th>
            </tr>
          </thead>
          <tbody>
            {Array.from({ length: Math.max(left.length, right.length) }, (_, i) => (
              <tr key={i} className="border-b border-border">
                <td className="py-1">{left[i] ? `${nounFor(left[i])} ${left[i].label}` : ""}</td>
                <td className="py-1">{right[i] ? `${nounFor(right[i])} ${right[i].label}` : ""}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <svg viewBox={`0 0 600 ${h}`} width="100%" height={h} role="img" aria-label={`${left.length} campus ${plural(left.length, "object")} and ${right.length} outside ${plural(right.length, "object")}; the list has the names`} className="max-w-2xl">
          {L.map((_, i) => R.map((__, j) => <line key={`${i}-${j}`} x1="200" y1={y(i, L.length)} x2="400" y2={y(j, R.length)} className="stroke-border-strong" strokeWidth="1" />))}
          {L.map((o, i) => (
            <text key={o.label} x="192" y={y(i, L.length) + 4} textAnchor="end" className="fill-text text-xs">
              {o.label.length > 28 ? `${o.label.slice(0, 27)}…` : o.label}
            </text>
          ))}
          {R.map((o, j) => (
            <text key={o.label} x="408" y={y(j, R.length) + 4} className="fill-text text-xs">
              {o.label.length > 28 ? `${o.label.slice(0, 27)}…` : o.label}
            </text>
          ))}
          {left.length > 8 && (
            <text x="192" y={h - 2} textAnchor="end" className="fill-muted text-xs">
              +{left.length - 8}
            </text>
          )}
          {right.length > 8 && (
            <text x="408" y={h - 2} className="fill-muted text-xs">
              +{right.length - 8}
            </text>
          )}
        </svg>
      )}
    </section>
  );
}

export function StoryTab({ detail, engine, report }: { detail: CaseDetail; engine: Engine | null; report: ReportRead }) {
  const [who, setWho] = useState<"all" | Who>("all");
  const members = useMemo(() => new Map(detail.investigations.map((m) => [m.investigation_id, m])), [detail.investigations]);
  const lines: Line[] = [
    ...detail.timeline.map((t): Line => {
      const m = t.investigation_id ? members.get(t.investigation_id) : undefined;
      return { at: t.at, who: t.kind === "alerts" ? "groups" : t.by ? "people" : "argus", text: t.text, why: m ? linkWords(m) : null, group: t.investigation_id };
    }),
    ...detail.history.map((h): Line => ({ at: h.at, who: historyKind(h) === "people" ? "people" : "argus", text: historyWords(h.text), why: null, group: null })),
  ].sort((a, b) => b.at.localeCompare(a.at));
  const shown = lines.filter((l) => who === "all" || l.who === who);
  const days = new Map<string, Line[]>();
  for (const l of shown) {
    const d = parse(l.at);
    const key = d ? weekdayDay(d) : "Unknown day";
    days.set(key, [...(days.get(key) ?? []), l]);
  }
  const body = (report.data?.report ?? null) as IncidentReport | null;
  return (
    <>
      <Glance data={report.data} />
      <TalkedTo engine={engine} report={body} />
      <section aria-labelledby="story-h" className="flex flex-col gap-2" data-testid="story-timeline">
        <div className="flex flex-wrap items-baseline justify-between gap-2">
          <h2 id="story-h" className="m-0 text-base font-semibold">
            Timeline
          </h2>
          <Chips value={who} onChange={setWho} label="Show" options={[["all", "All"], ["groups", "Alert groups"], ["argus", "ARGUS"], ["people", "People"]]} />
        </div>
        {detail.investigations_total <= 1 && <p className="m-0 text-sm text-muted">Only one alert group so far: the timeline grows as activity continues.</p>}
        {[...days.entries()].map(([day, items]) => (
          <div key={day} className="flex flex-col gap-1">
            <h3 className="m-0 text-sm font-semibold text-muted">{day}</h3>
            <ul className="m-0 flex list-none flex-col gap-1 p-0">
              {items.map((l, i) => {
                const at = parse(l.at);
                return (
                  <li key={i} className="grid grid-cols-[4.5rem_1fr] gap-2 text-sm" data-who={l.who}>
                    <span className="text-muted tabular-nums">{at ? clock(at) : ""}</span>
                    <span>
                      <UntrustedText value={l.text} limits={{ maxChars: 300, maxLines: 3 }} />
                      {l.why && <span className="text-muted"> — {l.why}</span>}
                    </span>
                  </li>
                );
              })}
            </ul>
          </div>
        ))}
      </section>
    </>
  );
}

// ------------------------------------------------------------------ Evidence (§7.5)

/** The evidence, one line per query: a repeated query says what else it was asked for. */
export function dedupeEvidence(lines: readonly ReportEvidenceLine[]): { line: ReportEvidenceLine; also: string[] }[] {
  const out: { line: ReportEvidenceLine; also: string[] }[] = [];
  for (const l of lines) {
    const same = out.find((o) => o.line.query.text.trim() !== "" && o.line.query.text.trim() === l.query.text.trim());
    if (same) same.also.push(...l.asked.filter((a) => !same.line.asked.includes(a)), ...(l.asked.length === 0 ? [l.title] : []));
    else out.push({ line: l, also: [] });
  }
  return out;
}

export function EvidenceTab({ detail, report }: { detail: CaseDetail; report: ReportRead }) {
  const body = (report.data?.report ?? null) as IncidentReport | null;
  const items = dedupeEvidence(body?.evidence ?? []);
  const factText = new Map((body?.facts ?? []).map((f) => [f.id, f.text]));
  const lead = useQuery({ ...investigationOptions(detail.lead_investigation_id ?? ""), enabled: detail.lead_investigation_id !== null });
  const hosts = detail.indicators.filter((i) => i.kind === "ip" || i.kind === "domain").map((i) => i.value);
  return (
    <>
      <section aria-labelledby="evidence-h" className="flex flex-col gap-2">
        <h2 id="evidence-h" className="m-0 text-base font-semibold">
          Evidence
        </h2>
        {items.length === 0 && <p className="m-0 text-sm text-muted">The incident report has no evidence lines yet.</p>}
        <ul className="m-0 flex list-none flex-col gap-2 p-0" data-testid="evidence-list">
          {items.map(({ line, also }) => (
            <li key={line.id} className="flex flex-col gap-1 rounded-card border border-border bg-surface p-3 text-sm" data-testid="evidence-item">
              <p className="m-0 font-medium">
                <span aria-hidden="true" title={line.id} className="mr-1 text-muted">
                  ◆
                </span>
                <UntrustedText value={line.title} limits={{ maxChars: 200, maxLines: 2 }} />
              </p>
              <p className="m-0">
                <UntrustedText value={factText.get(line.fact) ?? ""} limits={{ maxChars: 600, maxLines: 6 }} />
              </p>
              {line.details.length > 0 && (
                <div className="flex flex-col gap-0.5" data-testid="evidence-details">
                  <p className="m-0 text-muted">
                    <UntrustedText value={`${line.shows ?? "What the stored answer showed"}:`} limits={{ maxChars: 200, maxLines: 2 }} />
                  </p>
                  <ul className="m-0 flex list-disc flex-col gap-0.5 pl-5">
                    {line.details.map((d, i) => (
                      <li key={i}>
                        <code className="break-all text-xs">
                          <UntrustedText value={d.text} limits={{ maxChars: 300, maxLines: 2 }} />
                        </code>
                        {d.count !== null && <span className="text-muted"> · {count(d.count)} {plural(d.count, "time")}</span>}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
              <p className="m-0 text-muted">
                <UntrustedText value={line.source} limits={{ maxChars: 120, maxLines: 1 }} />
                {line.at && (
                  <>
                    {" "}
                    · <Time value={line.at} />
                  </>
                )}{" "}
                · <UntrustedText value={line.status} limits={{ maxChars: 60, maxLines: 1 }} />
                {also.length > 0 && (
                  <>
                    {" "}
                    · also for <UntrustedText value={also.join("; ")} limits={{ maxChars: 200, maxLines: 2 }} />
                  </>
                )}
              </p>
              <details>
                <summary className="cursor-pointer">Show the query</summary>
                <pre className="m-0 mt-1 max-w-full overflow-x-auto rounded-control bg-surface-2 p-2 text-xs" tabIndex={0}>
                  <UntrustedText value={line.query.text} limits={{ maxChars: 8000, maxLines: 200 }} block />
                </pre>
              </details>
              {line.count !== null && (
                <details>
                  <summary className="cursor-pointer">Show the rows ({count(line.count)})</summary>
                  <p className="m-0 mt-1 text-muted">
                    The rows stay in the SIEM.{" "}
                    {line.query.url && (
                      <a href={line.query.url} target="_blank" rel="noopener noreferrer">
                        Open them in Kibana Discover
                      </a>
                    )}
                  </p>
                </details>
              )}
            </li>
          ))}
        </ul>
      </section>
      {detail.lead_investigation_id && lead.data && (
        <section aria-label="Ask ARGUS to check something else" className="flex flex-col gap-2">
          <h2 className="m-0 text-base font-semibold">Ask ARGUS to check something else</h2>
          <CheckMore investigationId={detail.lead_investigation_id} version={lead.data.investigation.version} suggestions={hosts} />
        </section>
      )}
    </>
  );
}

// ------------------------------------------------------------------ Entities (§7.6)

function EntityCard({ o, facts, did, note }: { o: EngineObject; facts: string[]; did: string | null; note: string | null }) {
  return (
    <li className="flex flex-col gap-1 rounded-card border border-border bg-surface p-3 text-sm" data-testid="entity-card" data-role={o.role}>
      <p className="m-0">
        <span className="text-muted">{nounFor(o)}</span> <strong className="break-all"><UntrustedText value={o.label} limits={{ maxChars: 120, maxLines: 1 }} /></strong>
      </p>
      {facts.length > 0 && <p className="m-0 italic">{facts.join(" · ")}</p>}
      {did && <p className="m-0 text-muted">{did}</p>}
      {note && (
        <p className="m-0">
          Note: <UntrustedText value={note} limits={{ maxChars: 200, maxLines: 2 }} />
        </p>
      )}
      <p className="m-0">
        <Link to="/entities/$kind/$value" params={{ kind: entityKind(o), value: o.label }}>
          Open page
        </Link>
      </p>
    </li>
  );
}

export function EntitiesTab({ detail, engine, report }: { detail: CaseDetail; engine: Engine | null; report: ReportRead }) {
  const body = (report.data?.report ?? null) as IncidentReport | null;
  const sides = engine ? engine.objects : sidesWithoutEngine(detail.indicators, body);
  const campus = sides.filter((o) => o.role === "affected");
  const other = sides.filter((o) => o.role === "actor");
  const factsOf = (o: EngineObject): string[] => {
    const out: string[] = [];
    const ind = detail.indicators.find((i) => i.value === o.label);
    const actor = body?.actors.find((a) => a.value === o.label);
    if (ind?.source === "threat_intel" || actor?.listed) out.push("on a threat list");
    const target = body?.targets.find((t) => t.value === o.label);
    if (target?.shared) out.push("shared address");
    return out;
  };
  const didOf = (o: EngineObject): string | null => {
    const n = body?.actors.find((a) => a.value === o.label)?.alerts ?? body?.assets.find((a) => a.value === o.label)?.alerts ?? body?.targets.find((t) => t.value === o.label)?.alerts;
    return n ? `${count(n)} ${plural(n, "alert")} in this incident` : null;
  };
  const noteOf = (o: EngineObject): string | null => detail.indicators.find((i) => i.value === o.label)?.notes[0]?.body ?? null;
  const column = (title: string, items: EngineObject[], testId: string) => (
    <section aria-label={title} className="flex min-w-0 flex-col gap-2" data-testid={testId}>
      <h2 className="m-0 text-base font-semibold">{title}</h2>
      {items.length === 0 ? (
        <p className="m-0 text-sm text-muted">None known.</p>
      ) : (
        <ul className="m-0 flex list-none flex-col gap-2 p-0">
          {items.map((o) => (
            <EntityCard key={`${o.role}:${o.label}`} o={o} facts={factsOf(o)} did={didOf(o)} note={noteOf(o)} />
          ))}
        </ul>
      )}
    </section>
  );
  return (
    <div className="grid gap-4 md:grid-cols-2">
      {column("Campus side", campus, "campus-side")}
      {column("Other side", other, "other-side")}
    </div>
  );
}

// ------------------------------------------------------------------ Alert groups (§7.7)

export function AlertGroupsTab({ detail }: { detail: CaseDetail }) {
  const session = useSession();
  const queries = useQueryClient();
  const { announce } = useAnnounce();
  const mayReview = can(session.data, "review");
  const confirmed = ["open", "assigned", "contained"].includes(detail.case.state);
  const [chosen, setChosen] = useState<Set<string>>(new Set());
  const [outcome, setOutcome] = useState("");
  const [progress, setProgress] = useState<string | null>(null);
  const outcomes = Object.keys(OUTCOMES).filter((o) => o !== "true_positive" || confirmed);
  async function mark() {
    if (outcome === "" || chosen.size === 0 || progress !== null) return;
    const ids = [...chosen];
    let done = 0;
    for (const id of ids) {
      setProgress(`Saving ${done + 1} of ${ids.length}…`);
      try {
        const inv = await queries.fetchQuery({ ...investigationOptions(id), staleTime: 0 });
        await sendShown({ method: "POST", path: `/api/v1/investigations/${id}/reviews`, body: { action: outcome === "inconclusive" ? "follow_up" : "reviewed", outcome, seen_review: inv.investigation.latest_review, seen_version: inv.investigation.version } });
        done++;
      } catch (e) {
        announce(`Stopped after ${done}: ${e instanceof Error ? e.message : "it was refused"}.`, "danger");
        break;
      }
    }
    setProgress(null);
    if (done === ids.length) announce(`Saved: ${done} ${plural(done, "alert group")} marked ${OUTCOMES[outcome]}.`, "ok");
    setChosen(new Set());
    await Promise.all([changedCase(queries, detail.case.id), changed(queries)]);
  }
  return (
    <section aria-labelledby="groups-h" className="flex flex-col gap-2">
      <h2 id="groups-h" className="m-0 text-base font-semibold">
        Alert groups · {detail.investigations_total}
      </h2>
      {mayReview && chosen.size > 0 && (
        <div className="flex flex-wrap items-center gap-2 text-sm" data-testid="groups-bulk">
          <label className="flex items-center gap-2">
            Mark the {chosen.size} selected as
            <select value={outcome} onChange={(e) => setOutcome(e.target.value)} className="min-h-8 rounded-control border border-border-strong bg-surface px-2 text-sm text-text">
              <option value="">Choose…</option>
              {outcomes.map((o) => (
                <option key={o} value={o}>
                  {OUTCOMES[o]}
                </option>
              ))}
            </select>
          </label>
          <Button variant="primary" aria-disabled={outcome === "" || progress !== null} onClick={() => void mark()}>
            Save
          </Button>
          {progress && <span role="status">{progress}</span>}
        </div>
      )}
      <div className="overflow-x-auto">
        <table className="w-full border-collapse text-sm" data-testid="groups-table">
          <thead>
            <tr className="border-b border-border text-left text-muted">
              <th className="w-8 py-1">{mayReview && <span className="sr-only">Select</span>}</th>
              <th className="py-1 pr-3 font-medium">Alert group</th>
              <th className="py-1 pr-3 font-medium">Why linked</th>
              <th className="py-1 pr-3 font-medium">Alerts</th>
              <th className="py-1 font-medium">Your decision</th>
            </tr>
          </thead>
          <tbody>
            {detail.investigations.map((m) => {
              const first = parse(m.first_event_at);
              const last = parse(m.last_event_at);
              return (
                <tr key={m.investigation_id} className="border-b border-border" data-testid="group-row">
                  <td className="py-1.5">
                    {mayReview && (
                      <input
                        type="checkbox"
                        className="size-4 accent-accent"
                        aria-label={`Select ${m.rule_name ?? "this alert group"}`}
                        checked={chosen.has(m.investigation_id)}
                        onChange={(e) =>
                          setChosen((old) => {
                            const next = new Set(old);
                            if (e.target.checked) next.add(m.investigation_id);
                            else next.delete(m.investigation_id);
                            return next;
                          })
                        }
                      />
                    )}
                  </td>
                  <td className="py-1.5 pr-3">
                    <Link to="/alert-groups/$id" params={{ id: m.investigation_id }}>
                      <UntrustedText value={m.rule_name ?? "An alert group"} limits={{ maxChars: 160, maxLines: 2 }} />
                    </Link>
                  </td>
                  <td className="py-1.5 pr-3" data-testid="why-linked">
                    <UntrustedText value={linkWords(m)} limits={{ maxChars: 160, maxLines: 2 }} />
                  </td>
                  <td className="py-1.5 pr-3 tabular-nums">
                    {count(m.alert_count)}
                    {first && last && <span className="block text-muted">{`${dayAndTime(first)} – ${dayAndTime(last)}`}</span>}
                  </td>
                  <td className="py-1.5">{m.last_outcome ? (OUTCOMES[m.last_outcome] ?? "—") : "—"}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      {detail.investigations_total > detail.investigations.length && <p className="m-0 text-sm text-muted">{count(detail.investigations_total - detail.investigations.length)} more are not shown here.</p>}
    </section>
  );
}

// ------------------------------------------------------------------ Report (§7.8)

export function ReportTab({ detail, engine, report }: { detail: CaseDetail; engine: Engine | null; report: ReportRead }) {
  const verdict = ((report.data?.report ?? null) as IncidentReport | null)?.verdict ?? null;
  const state = stateWords({ state: detail.case.state, number: null }).replace(/ · .*/, "");
  const sent = cisoSent(detail);
  const mirror = detail.mirror;
  return (
    <>
      <div className="flex flex-col gap-1 text-sm" data-testid="report-tab-head">
        <p className="m-0 text-base font-semibold" data-testid="report-v2-headline">
          {state} · {callWords(detail, engine, verdict)}
        </p>
        <p className="m-0">
          Kibana:{" "}
          {detail.case.in_kibana ? (
            <>In Kibana{mirror.read_at ? <> (read back <Time value={mirror.read_at} />)</> : null}</>
          ) : detail.case.kibana_wait ? (
            <>Not in Kibana yet: <UntrustedText value={detail.case.kibana_wait} limits={{ maxChars: 200, maxLines: 2 }} /></>
          ) : (
            "possible incidents never go to Kibana"
          )}
        </p>
        {sent && (
          <p className="m-0" data-testid="ciso-sent">
            Sent to the CISO: v{sent.version} · <Time value={sent.at} /> by <UntrustedText value={sent.by} limits={{ maxChars: 60, maxLines: 1 }} />
            {report.data?.version != null && report.data.version !== sent.version && " · a newer version exists"}
          </p>
        )}
      </div>
      <ReportSection caseId={detail.case.id} incidentId={detail.incident_id ?? null} />
      <TeamSection caseId={detail.case.id} />
      <MirrorSection mirror={detail.mirror} />
    </>
  );
}

// ------------------------------------------------------------------ Activity (§7.9)

type Kind = "people" | "argus" | "ai" | "kibana";
interface Entry {
  at: string;
  kind: Kind;
  who: string;
  body: ReactNode;
  /** the body goes on from the name ("asha recorded …"), with no colon between */
  joined?: boolean;
}

/** Whose a history line is (§7.9): ARGUS's own (by "ARGUS (…)" or by nobody), its AI's, or a person's. */
export function historyKind(h: Pick<HistoryItemOut, "by" | "text">): Exclude<Kind, "kibana"> {
  if (h.by !== null && !/^ARGUS\b/.test(h.by)) return "people";
  return /model|AI\b/i.test(h.text) ? "ai" : "argus";
}

/** A history line in the page's words (§3.1): alert groups, never investigations; no true positive. */
export function historyWords(text: string): string {
  return plainWords(text)
    .replace(/\binvestigations\b/g, "alert groups")
    .replace(/\binvestigation\b/g, "alert group")
    .replace(/\bInvestigations\b/g, "Alert groups")
    .replace(/\bInvestigation\b/g, "Alert group");
}

export function ActivityTab({ detail }: { detail: CaseDetail }) {
  const [show, setShow] = useState<"all" | Kind>("all");
  const queries = useQueryClient();
  const mayReview = can(useSession().data, "review");
  const entries: Entry[] = [
    ...detail.notes.map((n): Entry => ({ at: n.created_at, kind: "people", who: n.author, body: <UntrustedText value={n.body} limits={{ maxChars: 2000, maxLines: 20 }} /> })),
    ...detail.history.map((h): Entry => {
      const who = h.by ?? "ARGUS";
      const text = historyWords(h.text);
      const said = text.startsWith(`${who} `) ? text.slice(who.length) : null; // "asha recorded …": the name once
      return { at: h.at, kind: historyKind(h), who, body: said !== null ? <UntrustedText value={said.trimStart()} limits={{ maxChars: 400, maxLines: 4 }} /> : <UntrustedText value={text} limits={{ maxChars: 400, maxLines: 4 }} />, joined: said !== null };
    }),
    ...detail.approvals.map((a): Entry => ({ at: a.requested_at, kind: "people", who: a.requested_by?.display_name ?? "someone", body: <>Asked: <UntrustedText value={a.words} limits={{ maxChars: 300, maxLines: 3 }} /> ({a.status_words})</> })),
    ...detail.mirror.writes.map((w): Entry => ({ at: w.verified_at ?? w.sent_at ?? w.planned_at, kind: "kibana", who: "Kibana", body: <>ARGUS {w.op} in Kibana: {w.state}{w.state_reason ? ` (${w.state_reason})` : ""}</> })),
  ].sort((a, b) => b.at.localeCompare(a.at));
  const shown = entries.filter((e) => show === "all" || e.kind === show);
  const known = detail.known !== null || detail.case.notified_at !== null;
  return (
    <>
      {!mayReview && <NeedsCapability what="adding a note" capability="review" />}
      {mayReview && (
        <NoteForm
          label="Add a note to this incident"
          say="Saved: note added."
          submit={async (body) => {
            const done = await unwrap(addCaseNote({ path: { case_id: detail.case.id }, body: { body } }));
            await changedCase(queries, detail.case.id);
            return { duplicate: done.duplicate };
          }}
        />
      )}
      <section aria-labelledby="activity-h" className="flex flex-col gap-2" data-testid="activity-log">
        <div className="flex flex-wrap items-baseline justify-between gap-2">
          <h2 id="activity-h" className="m-0 text-base font-semibold">
            Activity
          </h2>
          <Chips value={show} onChange={setShow} label="Show" options={[["all", "All"], ["people", "People"], ["argus", "ARGUS"], ["ai", "AI"], ["kibana", "Kibana"]]} />
        </div>
        {shown.length === 0 ? (
          <p className="m-0 text-sm text-muted">Nothing here yet.</p>
        ) : (
          <ul className="m-0 flex list-none flex-col gap-1 p-0">
            {shown.map((e, i) => (
              <li key={i} className="grid grid-cols-[9rem_1fr] gap-2 border-b border-border py-1 text-sm" data-kind={e.kind}>
                <span className="text-muted">
                  <Time value={e.at} />
                </span>
                <span>
                  <span className="font-medium">
                    <UntrustedText value={e.who} limits={{ maxChars: 60, maxLines: 1 }} />
                  </span>
                  {e.joined ? " " : ": "}
                  {e.body}
                </span>
              </li>
            ))}
          </ul>
        )}
      </section>
      <details open={known} className="flex flex-col gap-2">
        <summary className="cursor-pointer text-base font-semibold">Owner and containment</summary>
        <div className="mt-2 flex flex-col gap-6">
          <KnownSection detail={detail} />
          <CaseActions detail={detail} />
        </div>
      </details>
    </>
  );
}


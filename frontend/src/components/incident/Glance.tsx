import { useState } from "react";
import type { CaseReportOut, IncidentReport, ReportActor, ReportTarget } from "../../client/types.gen";
import { count, plural } from "../../lib/format";
import { isIp, isPrivateIp, type EngineObject } from "../../lib/engine";
import { parse } from "../../lib/time";
import { dayAndTime } from "../../lib/when";
import { UntrustedText } from "../UntrustedText";
import { Button } from "../ui/button";
import { EntityChip } from "./Parts";

const TOP = 10;
const BAR_W = 220;

interface Slice {
  object: EngineObject;
  value: number;
}

function actorObject(a: ReportActor): EngineObject {
  if (a.kind === "user") return { kind: "account", label: a.value, role: a.inside ? "affected" : "actor" };
  if (a.inside || (isIp(a.value) && isPrivateIp(a.value))) return { kind: "device", label: a.value, role: "affected" };
  return { kind: "device", label: a.value, role: "actor" };
}

function targetObject(t: ReportTarget): EngineObject {
  return { kind: t.kind === "site" ? "site" : "device", label: t.value, role: "affected" };
}

/** One panel of the glance: a bar per item with its count, the entity chip as its label; a list when fewer than two. */
function Panel({ title, items, unit }: { title: string; items: Slice[]; unit: string }) {
  const [list, setList] = useState(false);
  if (items.length === 0) return null;
  const max = Math.max(1, ...items.map((s) => s.value));
  const chart = items.length >= 2 && !list;
  return (
    <section aria-label={title} className="flex min-w-0 flex-col gap-1.5">
      <div className="flex items-baseline justify-between gap-2">
        <h3 className="m-0 text-sm font-semibold">{title}</h3>
        {items.length >= 2 && (
          <Button size="sm" variant="ghost" aria-pressed={list} onClick={() => setList(!list)}>
            {list ? "Show as bars" : "Show as a list"}
          </Button>
        )}
      </div>
      <ul className="m-0 flex list-none flex-col gap-1 p-0 text-sm">
        {items.map((s) => (
          <li key={`${s.object.role}:${s.object.label}`} className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-2">
            <span className="flex min-w-0 flex-col gap-0.5">
              <EntityChip object={s.object} />
              {chart && (
                <svg width="100%" height="8" viewBox={`0 0 ${BAR_W} 8`} preserveAspectRatio="none" aria-hidden="true" className="max-w-56">
                  <rect x="0" y="0" width={Math.max(2, (s.value / max) * BAR_W)} height="8" rx="2" className="fill-accent" />
                </svg>
              )}
            </span>
            <span className="tabular-nums text-muted">
              {count(s.value)} {plural(s.value, unit)}
            </span>
          </li>
        ))}
      </ul>
    </section>
  );
}

/** Alerts a day, every day from the first to the last (a quiet day is a gap, never left out). */
function Days({ report }: { report: IncidentReport }) {
  const [list, setList] = useState(false);
  const days = report.timeline.days;
  if (days.length === 0) return null;
  const max = Math.max(1, ...days.map((d) => d.total));
  const w = 12;
  const h = 64;
  return (
    <section aria-label="Alerts a day" className="flex min-w-0 flex-col gap-1.5">
      <div className="flex items-baseline justify-between gap-2">
        <h3 className="m-0 text-sm font-semibold">Alerts a day</h3>
        <Button size="sm" variant="ghost" aria-pressed={list} onClick={() => setList(!list)}>
          {list ? "Show as bars" : "Show as a list"}
        </Button>
      </div>
      {list ? (
        <table className="w-full max-w-sm border-collapse text-sm">
          <tbody>
            {days.map((d) => (
              <tr key={d.day} className="border-b border-border">
                <td className="py-0.5">{d.day}</td>
                <td className="py-0.5 text-right tabular-nums">{count(d.total)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <svg width="100%" height={h + 2} viewBox={`0 0 ${days.length * w} ${h + 2}`} preserveAspectRatio="none" role="img" aria-label={`Alerts a day, ${days[0]?.day} to ${days.at(-1)?.day}: at most ${count(max)} a day`} className="max-w-xl">
          {days.map((d, i) => {
            const bh = d.total === 0 ? 0 : Math.max(2, (d.total / max) * h);
            return (
              <rect key={d.day} x={i * w + 1} y={h - bh + 1} width={w - 2} height={bh} rx="1" className="fill-accent">
                <title>{`${d.day}: ${count(d.total)} ${plural(d.total, "alert")}`}</title>
              </rect>
            );
          })}
          <line x1="0" x2={days.length * w} y1={h + 1} y2={h + 1} className="stroke-border-strong" strokeWidth="1" />
        </svg>
      )}
    </section>
  );
}

/**
 * The incident at a glance on ARGUS's own page (the Visualiser's V5, docs/p4f-plan.md §7), drawn
 * from the same incident report as its dashboard: the numbers, the alerts a day, the top outside
 * sources and the top campus targets, each a link to its entity. The dashboard itself is the
 * report PDF's second part.
 */
export function Glance({ data }: { data: CaseReportOut | undefined }) {
  const report = (data?.report ?? null) as IncidentReport | null;
  const pdf = data?.files.find((f) => f.kind === "pdf" && f.available) ?? null;
  if (report === null) return null;
  const actors: Slice[] = report.actors
    .filter((a) => !a.inside)
    .slice(0, TOP)
    .map((a) => ({ object: actorObject(a), value: a.alerts }));
  const targets: Slice[] = (report.targets.length > 0 ? report.targets.map((t) => ({ object: targetObject(t), value: t.alerts })) : report.assets.map((a) => ({ object: { kind: a.kind === "account" ? "account" : "device", label: a.value, role: "affected" } as EngineObject, value: a.alerts }))).slice(0, TOP);
  const first = parse(report.timeline.first_seen ?? report.header.first_alert_at);
  const last = parse(report.timeline.last_seen ?? report.header.last_alert_at);
  const outside = report.outsiders_total || report.actors.filter((a) => !a.inside).length;
  const campus = report.targets_total || report.assets_total;
  const listed = report.actors.filter((a) => a.listed).length;
  const numbers: [string, string][] = [
    ["Alerts", count(report.timeline.alerts || report.meta.alerts_total)],
    ["Outside sources", count(outside)],
    ["Campus targets", count(campus)],
    ["On a threat list", count(listed)],
    ["Activity", report.summary.standing_words],
  ];
  if (report.timeline.dwell_words) numbers.push(["First to last", report.timeline.dwell_words]);
  return (
    <section aria-labelledby="glance-h" data-testid="glance" className="flex flex-col gap-3 rounded-card border border-border bg-surface p-4">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h2 id="glance-h" className="m-0 text-base font-semibold">
          At a glance
        </h2>
        {first && last && (
          <span className="text-sm text-muted">
            {dayAndTime(first)} to {dayAndTime(last)}
          </span>
        )}
      </div>
      <dl className="m-0 flex flex-wrap gap-x-6 gap-y-2 text-sm">
        {numbers.map(([k, v]) => (
          <div key={k} className="flex flex-col">
            <dt className="text-muted">{k}</dt>
            <dd className="m-0 font-semibold tabular-nums">
              <UntrustedText value={v} limits={{ maxChars: 80, maxLines: 1 }} />
            </dd>
          </div>
        ))}
      </dl>
      <Days report={report} />
      <div className="grid gap-4 md:grid-cols-2">
        <Panel title="Top outside sources" items={actors} unit="alert" />
        <Panel title="Top campus targets" items={targets} unit="alert" />
      </div>
      <p className="m-0 text-sm" data-testid="dashboard-pdf">
        The Visualiser&apos;s dashboard is the second part of the incident report.{" "}
        {pdf ? (
          <a href={pdf.url} download>
            Download the PDF
          </a>
        ) : (
          <span className="text-muted">The PDF needs log access.</span>
        )}
      </p>
    </section>
  );
}

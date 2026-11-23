import { Link } from "@tanstack/react-router";
import { useState, type ReactNode } from "react";
import { cn } from "../../lib/cn";
import { count } from "../../lib/format";
import { compact, type Change } from "../../lib/viz";
import { UntrustedText } from "../UntrustedText";
import { Button } from "../ui/button";
import { useWidth } from "./useWidth";

/** Where a figure or a mark leads: a page of the app, with the search that narrows it. */
export interface Target {
  to: string;
  params?: Record<string, string>;
  search?: Record<string, string | string[]>;
}

function Go({ target, className, children, label }: { target: Target; className?: string; children: ReactNode; label?: string }) {
  return (
    <Link to={target.to} params={target.params as never} search={target.search as never} className={className} aria-label={label}>
      {children}
    </Link>
  );
}

/**
 * A chart's card: what it shows, one line on how to read it, and its table: every chart can be
 * read as numbers (the same figures, for a screen reader or a copy).
 */
export function ChartCard({ title, hint, action, table, children, testId, className }: { title: string; hint?: ReactNode; action?: ReactNode; table?: ReactNode; children: ReactNode; testId?: string; className?: string }) {
  const [asTable, setAsTable] = useState(false);
  return (
    <section aria-label={title} className={cn("flex min-w-0 flex-col gap-3 rounded-card bg-surface p-4", className)} data-testid={testId}>
      <header className="flex flex-col gap-0.5">
        <div className="flex min-h-8 flex-wrap items-center justify-between gap-x-3 gap-y-1">
          <h2 className="m-0 min-w-0 text-base font-semibold">{title}</h2>
          <div className="flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1">
            {action}
            {table && (
              <Button size="sm" variant="ghost" aria-pressed={asTable} onClick={() => setAsTable(!asTable)}>
                {asTable ? "Show the chart" : "Show as a table"}
              </Button>
            )}
          </div>
        </div>
        {hint && <p className="m-0 text-sm text-muted">{hint}</p>}
      </header>
      {asTable && table ? table : children}
    </section>
  );
}

const SPARK_W = 112;
const SPARK_H = 28;

/** A figure's recent run: a thin grey line whose last point is the figure itself. Decoration: the tile says the number. */
function Sparkline({ values }: { values: readonly number[] }) {
  if (values.length < 2) return null;
  const top = Math.max(...values, 1);
  const step = (SPARK_W - 8) / (values.length - 1);
  const points = values.map((v, i) => [4 + i * step, SPARK_H - 4 - (v / top) * (SPARK_H - 8)] as const);
  const last = points[points.length - 1] as readonly [number, number];
  return (
    <svg aria-hidden="true" viewBox={`0 0 ${SPARK_W} ${SPARK_H}`} preserveAspectRatio="xMaxYMid meet" className="h-7 max-w-28 min-w-0 flex-1" data-testid="sparkline">
      <polyline points={points.map(([x, y]) => `${x.toFixed(1)},${y.toFixed(1)}`).join(" ")} fill="none" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="stroke-viz-rest" />
      <circle cx={last[0]} cy={last[1]} r="4" strokeWidth="2" className="fill-viz-1 stroke-surface" />
    </svg>
  );
}

const MOVED: Record<Change["direction"], string> = { up: "▲", down: "▼", flat: "＝" };

/**
 * One figure a dashboard leads with: its name, the number, how it moved against the span
 * before (an arrow and words; the colour only says whether that is good), its recent run, and,
 * with `target`, the list behind it one click away.
 */
export function Stat({ label, value, note, moved, movedNote, rising = "neutral", trend, target, testId }: { label: string; value: string; note?: ReactNode; moved?: Change | null; movedNote?: string; rising?: "good" | "bad" | "neutral"; trend?: readonly number[]; target?: Target; testId?: string }) {
  const tone = moved == null || moved.direction === "flat" || rising === "neutral" ? "text-muted" : (moved.direction === "up") === (rising === "good") ? "text-ok" : "text-danger";
  const body = (
    <>
      <span className="text-sm text-muted">{label}</span>
      <span className="flex items-end justify-between gap-2">
        <span className={cn("shrink-0 leading-none font-semibold tracking-tight", /\d|—/.test(value) ? "text-3xl" : "text-xl min-[360px]:text-2xl")}>{value}</span>
        {trend && <Sparkline values={trend} />}
      </span>
      {moved != null && (
        <span className={cn("text-xs", tone)} data-testid="stat-moved">
          <span aria-hidden="true">{MOVED[moved.direction]} </span>
          {moved.words}
          {movedNote ? ` ${movedNote}` : ""}
        </span>
      )}
      {note && <span className="text-xs text-muted">{note}</span>}
    </>
  );
  const frame = "flex min-w-0 flex-col gap-1.5 rounded-card bg-surface p-4 text-text no-underline";
  if (target) {
    return (
      <Go target={target} className={cn(frame, "transition-colors hover:bg-surface-2")}>
        <span className="contents" data-testid={testId}>
          {body}
        </span>
      </Go>
    );
  }
  return (
    <div className={frame} data-testid={testId}>
      {body}
    </div>
  );
}

/** A figure against its limit: the bar fills toward the limit and turns to a warning near it. */
export function Meter({ label, value, limit, words, testId, good = "low" }: { label: ReactNode; value: number; limit: number | null; words: string; testId?: string; /** a figure against a cap is good low (the usual); a share kept is good high */ good?: "low" | "high" }) {
  const ratio = limit !== null && limit > 0 ? Math.min(1, Math.max(0, value / limit)) : 0;
  const fill = good === "high" ? (ratio >= 0.9 ? "fill-ok" : ratio >= 0.7 ? "fill-warn" : "fill-danger") : ratio >= 0.9 ? "fill-danger" : ratio >= 0.7 ? "fill-warn" : "fill-viz-1";
  const name = typeof label === "string" ? label : "";
  return (
    <div className="flex flex-col gap-1" data-testid={testId}>
      <div className="flex items-baseline justify-between gap-2 text-sm">
        <span>{label}</span>
        <span className="text-muted tabular-nums">{words}</span>
      </div>
      <svg role="img" aria-label={`${name ? `${name}: ` : ""}${words}`} className="h-2 w-full" preserveAspectRatio="none">
        <rect width="100%" height="100%" rx="4" className="fill-viz-track" />
        {ratio > 0 && <rect width={`${(ratio * 100).toFixed(1)}%`} height="100%" rx="4" className={fill} />}
      </svg>
    </div>
  );
}

export interface RankRow {
  key: string;
  label: string;
  value: number;
  /** this row's own colour, where the rows are different things with colours of their own */
  fill?: string;
  /** said after the figure, in the muted ink: "3 open", "1 in 14" */
  note?: string | null;
  target?: Target;
}

/**
 * The most of something, largest first: a name, a thin bar and the figure at its end. One
 * series, one colour; a row with a target opens the list behind it.
 */
export function Rank({ rows, fill = "fill-viz-1", empty, label, top }: { rows: readonly RankRow[]; fill?: string; empty: string; label: string; top?: number }) {
  if (rows.length === 0) return <p className="m-0 text-sm text-muted">{empty}</p>;
  const most = top ?? Math.max(...rows.map((r) => r.value), 1);
  return (
    <ol className="m-0 flex list-none flex-col gap-0.5 p-0" aria-label={label} data-testid="rank">
      {rows.map((row) => {
        const share = Math.max(0, Math.min(100, (row.value / most) * 100));
        const body = (
          <>
            <span className="flex items-baseline justify-between gap-3 text-sm">
              <span className="min-w-0 truncate">
                <UntrustedText value={row.label} limits={{ maxChars: 160, maxLines: 1 }} />
              </span>
              <span className="shrink-0 tabular-nums">
                <span className="font-medium">{count(row.value)}</span>
                {row.note && <span className="text-muted"> · {row.note}</span>}
              </span>
            </span>
            <svg aria-hidden="true" className="h-2 w-full">
              {/* square at the baseline, round at the data end */}
              {share > 0 && <rect width="4" height="100%" className={row.fill ?? fill} />}
              {share > 0 && <rect width={`${Math.max(share, 0.6).toFixed(2)}%`} height="100%" rx="4" className={row.fill ?? fill} />}
            </svg>
          </>
        );
        return (
          <li key={row.key}>
            {row.target ? (
              <Go target={row.target} className="-mx-2 flex flex-col gap-1 rounded-control px-2 py-1.5 text-text no-underline transition-colors hover:bg-surface-2">
                {body}
              </Go>
            ) : (
              <div className="flex flex-col gap-1 py-1.5">{body}</div>
            )}
          </li>
        );
      })}
    </ol>
  );
}

export interface SharePart {
  key: string;
  label: string;
  value: number;
  fill: string;
  /** the same colour as a small square beside the label: "bg-viz-1" */
  swatch: string;
  target?: Target;
}

const SHARE_H = 12;
const GAP = 2;

/**
 * The parts of a whole on one bar, with the surface showing between them, and under it every
 * part by name with its figure and its share: the legend is the reading, the bar the glance.
 */
export function Share({ parts, label, empty, zeros = false }: { parts: readonly SharePart[]; label: string; empty: string; zeros?: boolean }) {
  const [ref, width] = useWidth<HTMLDivElement>(480);
  const shown = parts.filter((p) => p.value > 0);
  const whole = shown.reduce((n, p) => n + p.value, 0);
  if (whole === 0) return <p className="m-0 text-sm text-muted">{empty}</p>;
  const room = Math.max(1, width - GAP * (shown.length - 1));
  const widths = shown.map((p) => Math.max(2, (p.value / whole) * room));
  const scale = room / widths.reduce((a, b) => a + b, 0);
  const marks = widths.reduce<{ x: number; w: number }[]>((out, w) => {
    const last = out.at(-1);
    return [...out, { x: last ? last.x + last.w + GAP : 0, w: w * scale }];
  }, []);
  return (
    <div ref={ref} className="flex flex-col gap-2" data-testid="share">
      <svg aria-hidden="true" width={width} height={SHARE_H} className="block">
        {shown.map((p, i) => (
          <rect key={p.key} x={marks[i]?.x ?? 0} width={marks[i]?.w ?? 0} height={SHARE_H} rx="3" className={p.fill}>
            <title>{`${p.label}: ${count(p.value)}`}</title>
          </rect>
        ))}
      </svg>
      <ul className="m-0 flex list-none flex-wrap gap-x-4 gap-y-1 p-0 text-sm" aria-label={label}>
        {(zeros ? parts : shown).map((p) => {
          const text = (
            <>
              <span aria-hidden="true" className={cn("inline-block size-2.5 rounded-[3px]", p.swatch)} />
              <span>{p.label}</span>
              <span className="font-medium tabular-nums">{count(p.value)}</span>
              <span className="text-muted tabular-nums">{Math.round((p.value / whole) * 100)}%</span>
            </>
          );
          return (
            <li key={p.key}>
              {p.target ? (
                <Go target={p.target} className="inline-flex items-center gap-1.5 text-text no-underline hover:underline">
                  {text}
                </Go>
              ) : (
                <span className="inline-flex items-center gap-1.5">{text}</span>
              )}
            </li>
          );
        })}
      </ul>
    </div>
  );
}

/** A table for a chart's "Show as a table": plain rows, numbers to the right. */
export function FigureTable({ caption, head, rows }: { caption: string; head: readonly string[]; rows: readonly (readonly (string | number)[])[] }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse text-sm">
        <caption className="sr-only">{caption}</caption>
        <thead>
          <tr>
            {head.map((h, i) => (
              <th key={h} scope="col" className={cn("border-b border-border px-2 py-1.5 text-xs font-medium text-muted", i === 0 ? "text-left" : "text-right")}>
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, r) => (
            <tr key={r} className="border-b border-border last:border-b-0">
              {row.map((cell, i) => (
                <td key={i} className={cn("px-2 py-1.5", i === 0 ? "text-left" : "text-right tabular-nums")}>
                  {typeof cell === "number" ? count(cell) : <UntrustedText value={cell} limits={{ maxChars: 160, maxLines: 1 }} />}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export { compact };

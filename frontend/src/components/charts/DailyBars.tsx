import { useId, useState, type KeyboardEvent } from "react";
import { geometry, H, niceCeil, niceMax, PAD_B, PAD_L, PAD_T, sum, tickLabel, W, type Point } from "../../lib/chart";

/** Calm fills for series that carry no severity (providers, sources), in this order. */
export const SERIES_FILLS = ["fill-accent", "fill-marker", "fill-medium", "fill-ok", "fill-border-strong"] as const;
export const fillOf = (order: readonly string[], name: string) => SERIES_FILLS[Math.max(order.indexOf(name), 0) % SERIES_FILLS.length] ?? "fill-border-strong";

const TIP_W = 250;
const TIP_LINE = 17;

/** "Tue 17 Nov" for a day's bar. */
export function dayWords(at: string): string {
  const day = Date.parse(`${at.slice(0, 10)}T00:00:00Z`);
  if (Number.isNaN(day)) return at.slice(0, 10);
  return new Date(day).toLocaleDateString("en-GB", { weekday: "short", day: "2-digit", month: "short", timeZone: "UTC" });
}

/**
 * A value a day as bars, stacked by `order` (SVG drawn here, like StackedBars). `money` puts the
 * axis in dollars; `limit` draws the daily limit as a dashed line, the axis tall enough to show it.
 * Hovering a bar, or focusing the chart and moving with the arrow keys, shows that day in a box
 * (`details` gives its lines) and says it to a screen reader. `palette` keeps a series' colour
 * when another is hidden.
 */
export function DailyBars({ series, order, label, format, money = false, limit = null, unit, details, palette }: { series: readonly Point[]; order: readonly string[]; label: string; format: (n: number) => string; money?: boolean; limit?: number | null; unit: string; details?: (index: number) => string[]; palette?: readonly string[] }) {
  const id = useId();
  const [active, setActive] = useState<number | null>(null);
  const colours = palette ?? order;
  const tallest = Math.max(0, ...series.map((p) => sum(order.map((o) => p.counts[o] ?? 0))), limit ?? 0);
  const g = geometry(series, order, money ? niceCeil(tallest) : niceMax(tallest));
  const plotH = H - PAD_B - PAD_T;
  const limitY = limit === null ? null : PAD_T + plotH - (plotH * limit) / g.top;
  const lineOf = (i: number) => {
    const bar = g.bars[i];
    if (bar === undefined) return [];
    const head = `${dayWords(bar.point.at)}: ${format(bar.total)} ${unit}${limit !== null ? ` of ${format(limit)} a day` : ""}`;
    return [head, ...(details ? details(i) : [])];
  };
  const shown = active === null ? null : g.bars[active];
  const lines = active === null ? [] : lineOf(active);
  const tipH = lines.length * TIP_LINE + 12;
  const tipX = shown ? Math.min(Math.max(shown.x + shown.width / 2 - TIP_W / 2, PAD_L), W - TIP_W - 8) : 0;
  function keys(e: KeyboardEvent<SVGSVGElement>) {
    const last = g.bars.length - 1;
    const now = active ?? last;
    const to = { ArrowLeft: now - 1, ArrowRight: now + 1, Home: 0, End: last }[e.key];
    if (to === undefined) {
      if (e.key === "Escape") setActive(null);
      return;
    }
    e.preventDefault();
    setActive(Math.min(Math.max(to, 0), last));
  }
  return (
    <div className="relative">
      <svg
        viewBox={`0 0 ${W} ${H}`}
        role="img"
        aria-label={`${label}. Use the arrow keys to read a day.`}
        aria-describedby={`${id}-said`}
        tabIndex={0}
        className="h-auto w-full rounded-control focus-visible:outline-2 focus-visible:outline-focus"
        onKeyDown={keys}
        onFocus={() => setActive((a) => a ?? g.bars.length - 1)}
        onBlur={() => setActive(null)}
        onMouseLeave={() => setActive(null)}
      >
        {g.grid.map((line) => (
          <g key={line.y}>
            <line x1={PAD_L} x2={W - 8} y1={line.y} y2={line.y} className="stroke-border" />
            <text x={PAD_L - 6} y={line.y + 4} textAnchor="end" className="fill-muted text-[11px]">
              {format(line.value)}
            </text>
          </g>
        ))}
        {g.bars.map((bar) => (
          <g key={bar.point.at} className={active !== null && active !== bar.index ? "opacity-55" : undefined} onMouseEnter={() => setActive(bar.index)}>
            {bar.parts.map((part) => (
              <rect key={part.name} x={bar.x} y={part.y} width={bar.width} height={part.height} className={`${fillOf(colours, part.name)} bar-grow`} />
            ))}
            <rect x={bar.x} y={PAD_T} width={bar.width} height={plotH} className="fill-transparent" />
            {bar.index % g.every === 0 && (
              <text x={bar.x + bar.width / 2} y={H - 8} textAnchor="middle" className="fill-muted text-[11px]">
                {tickLabel(bar.point.at, false)}
              </text>
            )}
          </g>
        ))}
        {limitY !== null && limit !== null && (
          <g>
            <line x1={PAD_L} x2={W - 8} y1={limitY} y2={limitY} strokeDasharray="6 4" className="stroke-warn" />
            <text x={W - 10} y={limitY - 4} textAnchor="end" className="fill-warn text-[11px]">
              limit {format(limit)} a day
            </text>
          </g>
        )}
        {shown && (
          <g data-testid="bar-tip" pointerEvents="none">
            <rect x={tipX} y={PAD_T} width={TIP_W} height={tipH} rx={8} className="fill-surface stroke-border-strong" />
            {lines.map((text, i) => (
              <text key={i} x={tipX + 10} y={PAD_T + 20 + i * TIP_LINE} className={i === 0 ? "fill-text text-[12px] font-semibold" : "fill-text text-[12px]"}>
                {text}
              </text>
            ))}
          </g>
        )}
      </svg>
      <p id={`${id}-said`} className="sr-only" aria-live="polite">
        {lines.join(". ")}
      </p>
    </div>
  );
}

/**
 * The series' names with their colour and their total in the period (the colour is never alone).
 * With `onToggle`, each is a button that shows or hides its series.
 */
export function Legend({ order, totals, format, hidden, onToggle }: { order: readonly string[]; totals: Readonly<Record<string, number>>; format: (n: number) => string; hidden?: ReadonlySet<string>; onToggle?: (name: string) => void }) {
  return (
    <ul className="m-0 flex list-none flex-wrap gap-x-2 gap-y-1 p-0 text-sm" aria-label="Legend">
      {order.map((name) => {
        const off = hidden?.has(name) === true;
        const inner = (
          <>
            <svg viewBox="0 0 10 10" className="size-3" aria-hidden="true">
              <rect width="10" height="10" rx="2" className={off ? "fill-transparent stroke-border-strong" : fillOf(order, name)} />
            </svg>
            <span className={off ? "text-muted line-through" : undefined}>{name}</span>
            <span className="text-muted">{format(totals[name] ?? 0)}</span>
          </>
        );
        return (
          <li key={name}>
            {onToggle ? (
              <button type="button" aria-pressed={!off} title={off ? `Show ${name}` : `Hide ${name}`} onClick={() => onToggle(name)} className="flex cursor-pointer items-center gap-1.5 rounded-full border border-border bg-surface px-2 py-0.5 text-text hover:bg-surface-2">
                {inner}
              </button>
            ) : (
              <span className="flex items-center gap-1.5 px-2 py-0.5">{inner}</span>
            )}
          </li>
        );
      })}
    </ul>
  );
}

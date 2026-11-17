import { geometry, H, niceCeil, niceMax, PAD_B, PAD_L, PAD_T, sum, tickLabel, W, type Point } from "../../lib/chart";

/** Calm fills for series that carry no severity (providers, sources), in this order. */
export const SERIES_FILLS = ["fill-accent", "fill-marker", "fill-medium", "fill-ok", "fill-border-strong"] as const;
export const fillOf = (order: readonly string[], name: string) => SERIES_FILLS[Math.max(order.indexOf(name), 0) % SERIES_FILLS.length] ?? "fill-border-strong";

/**
 * A value a day as bars, stacked by `order` (SVG drawn here, like StackedBars). `money` puts the
 * axis in dollars; `limit` draws the daily limit as a dashed line, the axis tall enough to show it.
 */
export function DailyBars({ series, order, label, format, money = false, limit = null, unit }: { series: readonly Point[]; order: readonly string[]; label: string; format: (n: number) => string; money?: boolean; limit?: number | null; unit: string }) {
  const tallest = Math.max(0, ...series.map((p) => sum(Object.values(p.counts))), limit ?? 0);
  const g = geometry(series, order, money ? niceCeil(tallest) : niceMax(tallest));
  const plotH = H - PAD_B - PAD_T;
  const limitY = limit === null ? null : PAD_T + plotH - (plotH * limit) / g.top;
  return (
    <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label={label} className="h-auto w-full">
      {g.grid.map((line) => (
        <g key={line.y}>
          <line x1={PAD_L} x2={W - 8} y1={line.y} y2={line.y} className="stroke-border" />
          <text x={PAD_L - 6} y={line.y + 4} textAnchor="end" className="fill-muted text-[11px]">
            {format(line.value)}
          </text>
        </g>
      ))}
      {g.bars.map((bar) => {
        const day = bar.point.at.slice(0, 10);
        const parts = order.filter((s) => (bar.point.counts[s] ?? 0) > 0);
        const tip = `${day}: ${format(bar.total)} ${unit}${order.length > 1 ? parts.map((s) => `, ${s} ${format(bar.point.counts[s] ?? 0)}`).join("") : ""}`;
        return (
          <g key={bar.point.at}>
            <title>{tip}</title>
            {bar.parts.map((part) => (
              <rect key={part.name} x={bar.x} y={part.y} width={bar.width} height={part.height} className={fillOf(order, part.name)} />
            ))}
            <rect x={bar.x} y={PAD_T} width={bar.width} height={plotH} className="fill-transparent" />
            {bar.index % g.every === 0 && (
              <text x={bar.x + bar.width / 2} y={H - 8} textAnchor="middle" className="fill-muted text-[11px]">
                {tickLabel(bar.point.at, false)}
              </text>
            )}
          </g>
        );
      })}
      {limitY !== null && limit !== null && (
        <g>
          <line x1={PAD_L} x2={W - 8} y1={limitY} y2={limitY} strokeDasharray="6 4" className="stroke-warn" />
          <text x={W - 10} y={limitY - 4} textAnchor="end" className="fill-warn text-[11px]">
            limit {format(limit)} a day
          </text>
        </g>
      )}
    </svg>
  );
}

/** The series' names with their colour and their total in the period (the colour is never alone). */
export function Legend({ order, totals, format }: { order: readonly string[]; totals: Readonly<Record<string, number>>; format: (n: number) => string }) {
  return (
    <ul className="m-0 flex list-none flex-wrap gap-x-4 gap-y-1 p-0 text-sm" aria-label="Legend">
      {order.map((name) => (
        <li key={name} className="flex items-center gap-1.5">
          <svg viewBox="0 0 10 10" className="size-3" aria-hidden="true">
            <rect width="10" height="10" rx="2" className={fillOf(order, name)} />
          </svg>
          <span>{name}</span>
          <span className="text-muted">{format(totals[name] ?? 0)}</span>
        </li>
      ))}
    </ul>
  );
}

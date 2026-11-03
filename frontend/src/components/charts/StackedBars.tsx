import { bucketLabel, geometry, H, PAD_B, PAD_L, PAD_T, tickLabel, W, type Point } from "../../lib/chart";
import { count } from "../../lib/format";
import { zoneLabel } from "../../lib/site";

// full class names, so Tailwind finds them
const FILL: Record<string, string> = {
  critical: "fill-critical",
  high: "fill-high",
  medium: "fill-medium",
  low: "fill-low",
  unknown: "fill-border-strong",
};

/** Alerts per bucket, stacked by severity: SVG drawn here (no script-built markup, no style). */
export function StackedBars({ series, order, hourly, label }: { series: readonly Point[]; order: readonly string[]; hourly: boolean; label: string }) {
  const g = geometry(series, order);
  const plotH = H - PAD_B - PAD_T;
  return (
    <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label={label} className="h-auto w-full">
      {g.grid.map((line) => (
        <g key={line.y}>
          <line x1={PAD_L} x2={W - 8} y1={line.y} y2={line.y} className="stroke-border" />
          <text x={PAD_L - 6} y={line.y + 4} textAnchor="end" className="fill-muted text-[11px]">
            {count(Math.trunc(line.value))}
          </text>
        </g>
      ))}
      {g.bars.map((bar) => {
        const point = bar.point;
        const tip = `${bucketLabel(point.at, hourly)} ${zoneLabel()}: ${count(bar.total)} alerts${order.filter((s) => (point.counts[s] ?? 0) > 0).map((s) => `, ${count(point.counts[s] ?? 0)} ${s}`).join("")}`;
        return (
          <g key={point.at}>
            <title>{tip}</title>
            {bar.parts.map((part) => (
              <rect key={part.name} x={bar.x} y={part.y} width={bar.width} height={part.height} className={FILL[part.name] ?? FILL.unknown} />
            ))}
            {bar.total === 0 && <rect x={bar.x} y={PAD_T} width={bar.width} height={plotH} className="fill-transparent" />}
            {bar.index % g.every === 0 && (
              <text x={bar.x + bar.width / 2} y={H - 8} textAnchor="middle" className="fill-muted text-[11px]">
                {tickLabel(point.at, hourly)}
              </text>
            )}
          </g>
        );
      })}
    </svg>
  );
}

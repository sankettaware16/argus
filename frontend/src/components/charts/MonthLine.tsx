import { niceCeil } from "../../lib/chart";
import type { MonthToDate } from "../../lib/usage";

const W = 960;
const H = 150;
const L = 52;
const R = 12;
const T = 12;
const B = 24;

/**
 * The month so far as a line of the spend to date, the rest of the month as a dashed projection
 * at the same daily rate, and the monthly cap as a line (SVG drawn here; the words beside it).
 */
export function MonthLine({ m, cap, format, label }: { m: MonthToDate; cap: number | null; format: (n: number) => string; label: string }) {
  const spent = m.cumulative[m.cumulative.length - 1] ?? 0;
  const top = niceCeil(Math.max(spent, m.projected, cap ?? 0));
  const x = (day: number) => L + ((W - L - R) * (day - 1)) / Math.max(m.length - 1, 1);
  const y = (v: number) => T + (H - T - B) * (1 - v / top);
  const path = m.cumulative.map((v, i) => `${i === 0 ? "M" : "L"}${x(i + 1).toFixed(1)},${y(v).toFixed(1)}`).join(" ");
  const ticks = [1, Math.ceil(m.length / 2), m.length];
  return (
    <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label={label} className="h-auto w-full">
      {[0, top / 2, top].map((v) => (
        <g key={v}>
          <line x1={L} x2={W - R} y1={y(v)} y2={y(v)} className="stroke-border" />
          <text x={L - 6} y={y(v) + 4} textAnchor="end" className="fill-muted text-[11px]">
            {format(v)}
          </text>
        </g>
      ))}
      {cap !== null && (
        <g>
          <line x1={L} x2={W - R} y1={y(cap)} y2={y(cap)} strokeDasharray="6 4" className="stroke-warn" />
          <text x={W - R - 2} y={y(cap) - 4} textAnchor="end" className="fill-warn text-[11px]">
            monthly cap {format(cap)}
          </text>
        </g>
      )}
      <path d={path} fill="none" strokeWidth={2.5} className="stroke-accent" />
      {m.today < m.length && <line x1={x(m.today)} y1={y(spent)} x2={x(m.length)} y2={y(m.projected)} strokeWidth={2} strokeDasharray="3 5" className="stroke-muted" />}
      <circle cx={x(m.today)} cy={y(spent)} r={4} className="fill-accent" />
      {ticks.map((d) => (
        <text key={d} x={x(d)} y={H - 6} textAnchor={d === 1 ? "start" : d === m.length ? "end" : "middle"} className="fill-muted text-[11px]">
          day {d}
        </text>
      ))}
    </svg>
  );
}

import { useState, type KeyboardEvent, type PointerEvent } from "react";
import { bucketLabel, tickLabel } from "../../lib/chart";
import { cn } from "../../lib/cn";
import { count } from "../../lib/format";
import { zoneLabel } from "../../lib/site";
import { amountTicks, compact, ticks, total, type Bucket, type Series } from "../../lib/viz";
import { useWidth } from "./useWidth";

const H = 236;
const PAD_L = 44;
const PAD_R = 8;
const PAD_T = 12;
const PAD_B = 24;
const BAR = 24; // a column is never thicker than this: the rest of its slot is air
const GAP = 2; // the surface shows between the parts of a column, and between columns
const TIP_W = 196;
const ROW = 18;

/** The top part of a column: round at the data end, square where it meets the part below. */
function capped(x: number, y: number, w: number, h: number): string {
  const r = Math.min(4, w / 2, h);
  return `M${x},${y + h}V${y + r}Q${x},${y} ${x + r},${y}H${x + w - r}Q${x + w},${y} ${x + w},${y + r}V${y + h}Z`;
}

/**
 * Counts over time, one thin column a bucket, stacked by an ordered set of series (the bottom
 * one first). The pointer, or the arrow keys once the chart has the focus, picks a bucket: a
 * hairline marks it and one readout lists every series there. The legend below names the
 * colours; the card's table has the same numbers.
 */
export function Columns({ buckets, series, hourly, label, unit, amount }: { buckets: readonly Bucket[]; series: readonly Series[]; hourly: boolean; label: string; unit: string; /** the values are amounts, not counts: how one is written ("$0.42") */ amount?: (value: number) => string }) {
  const say = amount ?? count;
  const tick = amount ?? compact;
  const [ref, width] = useWidth<HTMLDivElement>(720);
  const [active, setActive] = useState<number | null>(null);
  const plotW = Math.max(40, width - PAD_L - PAD_R);
  const plotH = H - PAD_T - PAD_B;
  const totals = buckets.map((b) => total(b, series));
  const axis = (amount ? amountTicks : ticks)(Math.max(0, ...totals));
  const top = axis[axis.length - 1] ?? 1;
  const slot = plotW / Math.max(1, buckets.length);
  const bar = Math.max(1, Math.min(BAR, slot - GAP));
  const every = Math.max(1, Math.ceil(buckets.length / Math.max(1, Math.floor(plotW / 64))));
  const y = (value: number) => PAD_T + plotH - (value / top) * plotH;
  const centre = (i: number) => PAD_L + slot * i + slot / 2;
  const sum = totals.reduce((a, b) => a + b, 0);
  const peak = totals.indexOf(Math.max(...totals, 0));
  const peakBucket = buckets[peak];
  const summary = buckets.length === 0 ? `${label}: nothing in this span` : `${label}: ${say(sum)}${unit ? ` ${unit}` : ""} in ${buckets.length} ${hourly ? "hours" : "days"}${peakBucket && sum > 0 ? `; the most, ${say(totals[peak] ?? 0)}, on ${bucketLabel(peakBucket.at, hourly)}` : ""}`;

  function pick(e: PointerEvent<SVGSVGElement>) {
    const box = e.currentTarget.getBoundingClientRect();
    const i = Math.floor((e.clientX - box.left - PAD_L) / slot);
    setActive(buckets.length === 0 ? null : Math.max(0, Math.min(buckets.length - 1, i)));
  }
  function onKeyDown(e: KeyboardEvent<HTMLDivElement>) {
    if (buckets.length === 0) return;
    const last = buckets.length - 1;
    const at = active ?? last;
    const next = e.key === "ArrowLeft" ? Math.max(0, at - 1) : e.key === "ArrowRight" ? (active === null ? last : Math.min(last, at + 1)) : e.key === "Home" ? 0 : e.key === "End" ? last : e.key === "Escape" ? null : undefined;
    if (next === undefined) return;
    e.preventDefault();
    setActive(next);
  }

  const shown = active !== null ? buckets[active] : undefined;
  const tipRows = shown ? [...series].reverse() : [];
  const tipH = 44 + ROW * tipRows.length;
  const tipX = active === null ? 0 : centre(active) + 12 + TIP_W > width ? centre(active) - 12 - TIP_W : centre(active) + 12;
  return (
    <div className="flex flex-col gap-2">
      <div ref={ref} role="group" tabIndex={0} aria-label={`${label}. Use the left and right arrow keys to read each ${hourly ? "hour" : "day"}.`} className="rounded-control focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus" onKeyDown={onKeyDown} onBlur={() => setActive(null)} data-testid="columns">
        <svg width={width} height={H} role="img" aria-label={summary} className="block touch-pan-y" onPointerMove={pick} onPointerDown={pick} onPointerLeave={() => setActive(null)}>
          {axis.map((value) => (
            <g key={value}>
              <line x1={PAD_L} x2={width - PAD_R} y1={y(value)} y2={y(value)} strokeWidth="1" className={value === 0 ? "stroke-viz-axis" : "stroke-viz-grid"} />
              <text x={PAD_L - 6} y={y(value) + 4} textAnchor="end" className="fill-muted text-[11px] tabular-nums">
                {tick(value)}
              </text>
            </g>
          ))}
          {buckets.map((bucket, i) => {
            let below = 0;
            const parts = series.filter((s) => (bucket.counts[s.key] ?? 0) > 0);
            const x = centre(i) - bar / 2;
            return (
              <g key={bucket.at} className={cn("transition-opacity", active !== null && active !== i && "opacity-45")} data-testid="column">
                {parts.map((s, n) => {
                  const value = bucket.counts[s.key] ?? 0;
                  const from = y(below);
                  below += value;
                  const to = y(below);
                  const h = Math.max(1, from - to - (n === parts.length - 1 ? 0 : GAP));
                  return n === parts.length - 1 ? <path key={s.key} d={capped(x, to, bar, from - to)} className={s.fill} /> : <rect key={s.key} x={x} y={from - h} width={bar} height={h} className={s.fill} />;
                })}
                {i % every === 0 && (
                  <text x={centre(i)} y={H - 6} textAnchor="middle" className="fill-muted text-[11px]">
                    {tickLabel(bucket.at, hourly)}
                  </text>
                )}
              </g>
            );
          })}
          {active !== null && shown && (
            <g data-testid="readout" pointerEvents="none">
              <line x1={centre(active)} x2={centre(active)} y1={PAD_T} y2={PAD_T + plotH} strokeWidth="1" className="stroke-border-strong" />
              <rect x={tipX} y={PAD_T} width={TIP_W} height={tipH} rx="10" strokeWidth="1" className="fill-raised stroke-border" />
              <text x={tipX + 12} y={PAD_T + 18} className="fill-muted text-[11px]">
                {bucketLabel(shown.at, hourly)} {zoneLabel()}
              </text>
              <text x={tipX + 12} y={PAD_T + 36} className="fill-text text-[13px] font-semibold">
                {say(totals[active] ?? 0)} {unit}
              </text>
              {tipRows.map((s, n) => (
                <g key={s.key}>
                  <rect x={tipX + 12} y={PAD_T + 48 + ROW * n} width="10" height="3" rx="1.5" className={s.fill} />
                  <text x={tipX + 28} y={PAD_T + 54 + ROW * n} className="fill-muted text-[12px]">
                    {s.label}
                  </text>
                  <text x={tipX + TIP_W - 12} y={PAD_T + 54 + ROW * n} textAnchor="end" className="fill-text text-[12px] font-medium tabular-nums">
                    {say(shown.counts[s.key] ?? 0)}
                  </text>
                </g>
              ))}
            </g>
          )}
        </svg>
      </div>
      {series.length > 1 && (
        <ul className="m-0 flex list-none flex-wrap gap-x-4 gap-y-1 p-0 text-sm text-muted" aria-label="Legend" data-testid="legend">
          {series.map((s) => (
            <li key={s.key} className="inline-flex items-center gap-1.5">
              <svg aria-hidden="true" width="10" height="10">
                <rect width="10" height="10" rx="3" className={s.fill} />
              </svg>
              {s.label}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

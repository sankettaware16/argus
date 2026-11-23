/**
 * The numbers behind the dashboards' charts: clean axis ticks, compact figures, the change
 * against the span before, a stack's parts. Pure (tests/viz.test.ts).
 */

/** 1,284 → "1,284"; 12,940 → "12.9K"; 4,200,000 → "4.2M": an axis tick or a tile's figure. */
export function compact(n: number): string {
  const abs = Math.abs(n);
  if (abs < 10_000) return Math.round(n).toLocaleString("en-US");
  const [unit, size] = abs >= 1_000_000_000 ? ["B", 1_000_000_000] : abs >= 1_000_000 ? ["M", 1_000_000] : ["K", 1_000];
  const value = n / size;
  return `${value.toFixed(Math.abs(value) >= 100 ? 0 : 1).replace(/\.0$/, "")}${unit}`;
}

/** The axis's top and its ticks: round numbers at or above `top`, never fewer than two lines. */
export function ticks(top: number, lines = 4): number[] {
  if (!(top > 0)) return [0, 1];
  const rough = top / lines;
  const power = 10 ** Math.floor(Math.log10(rough));
  // counts of things: a tick is never a fraction
  const step = [1, 2, 2.5, 5, 10].map((m) => m * power).find((s) => s >= rough && Number.isInteger(s)) ?? 10 * power;
  const whole = Math.max(1, Math.ceil(step));
  const out: number[] = [];
  for (let v = 0; v < top + whole; v += whole) out.push(v);
  return out;
}

/** An axis for amounts (money): round steps that may be fractions, from zero to at or above `top`. */
export function amountTicks(top: number, lines = 4): number[] {
  if (!(top > 0)) return [0, 1];
  const rough = top / lines;
  const power = 10 ** Math.floor(Math.log10(rough));
  const step = [1, 2, 2.5, 5, 10].map((m) => m * power).find((s) => s >= rough) ?? 10 * power;
  const out: number[] = [];
  for (let i = 0; i * step < top + step - step * 1e-9 && out.length < 12; i++) out.push(Number((i * step).toPrecision(12)));
  return out;
}

export interface Change {
  /** "+17%", "−4%", "no change"; "new" when there was nothing before */
  words: string;
  direction: "up" | "down" | "flat";
}

/** How a figure moved against the same span before; null when neither span had anything. */
export function change(now: number, before: number): Change | null {
  if (now === 0 && before === 0) return null;
  if (before === 0) return { words: "new", direction: "up" };
  const moved = Math.round(((now - before) / before) * 100);
  if (moved === 0) return { words: "no change", direction: "flat" };
  return { words: `${moved > 0 ? "+" : "−"}${Math.abs(moved)}%`, direction: moved > 0 ? "up" : "down" };
}

/** A span of seconds as people say it: "45 s", "12 min", "3.5 h", "2 days". */
export function span(seconds: number): string {
  if (seconds < 90) return `${Math.round(seconds)} s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)} min`;
  if (seconds < 172_800) return `${(seconds / 3600).toFixed(1).replace(/\.0$/, "")} h`;
  return `${Math.round(seconds / 86_400)} days`;
}

export interface Series {
  key: string;
  label: string;
  /** a full Tailwind class, so the build finds it: "fill-viz-1" */
  fill: string;
}

export interface Bucket {
  at: string;
  counts: Readonly<Record<string, number>>;
}

/** A bucket's total over the series shown. */
export function total(bucket: Bucket, series: readonly Series[]): number {
  return series.reduce((n, s) => n + (bucket.counts[s.key] ?? 0), 0);
}

/** "1 in 14": how much a step of a funnel keeps of the one before; null when it cannot be said. */
export function oneIn(part: number, whole: number): string | null {
  if (part <= 0 || whole <= 0 || part > whole) return null;
  const n = whole / part;
  return n < 1.5 ? "nearly all" : `1 in ${compact(Math.round(n))}`;
}

/**
 * Charts as plain SVG drawn by React (Q-B2 decision: ECharts' painter assigns innerHTML, which
 * /app's Trusted Types refuse). The geometry is here, pure: the classic page's own numbers
 * (src/argus/web/charts.py) so both pages draw the same chart (tests/chart.test.ts).
 */
import { hourWords } from "./time";
export const W = 960;
export const H = 220;
export const PAD_L = 44;
export const PAD_B = 26;
export const PAD_T = 10;
const STEPS = [1, 1.2, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10];

/** A round number at or above `top` for the axis. */
export function niceMax(top: number): number {
  const t = Math.max(top, 5);
  const power = 10 ** (String(Math.trunc(t)).length - 1);
  return Math.round((STEPS.find((m) => t <= m * power) ?? 10) * power);
}

export interface Point {
  at: string;
  counts: Record<string, number>;
}

export interface Bar {
  index: number;
  point: Point;
  x: number;
  width: number;
  total: number;
  /** from the bottom: one rectangle per severity present */
  parts: { name: string; y: number; height: number; count: number }[];
  /** the whole slot's height, for the hover and focus target of an empty bar */
  top: number;
}

export interface Geometry {
  top: number;
  grid: { y: number; value: number }[];
  bars: Bar[];
  /** every n-th bar is labelled on the axis */
  every: number;
}

/** A round number at or above `top` (and `least`), for an axis of small values such as dollars. */
export function niceCeil(top: number, least = 0.01): number {
  const t = Math.max(top, least);
  const power = 10 ** Math.floor(Math.log10(t));
  const raw = (STEPS.find((m) => t <= m * power) ?? 10) * power;
  const round = Number(raw.toPrecision(12)); // 0.15000000000000002 reads 0.15, unless that is below t
  return round >= t ? round : raw;
}

/** The bars' geometry; `fixedTop` sets the axis' top (else a round count at or above the tallest bar). */
export function geometry(series: readonly Point[], order: readonly string[], fixedTop?: number): Geometry {
  const totals = series.map((p) => sum(Object.values(p.counts)));
  const top = fixedTop ?? niceMax(Math.max(0, ...totals));
  const n = Math.max(series.length, 1);
  const plotW = W - PAD_L - 8;
  const plotH = H - PAD_B - PAD_T;
  const slot = plotW / n;
  const width = Math.max(Math.min(slot * 0.72, 48), 1.5);
  const grid = [0, 1, 2, 3, 4].map((k) => ({ y: PAD_T + plotH - (plotH * k) / 4, value: (top * k) / 4 }));
  const bars = series.map((point, index): Bar => {
    const x = PAD_L + slot * index + (slot - width) / 2;
    let y = PAD_T + plotH;
    const parts: Bar["parts"] = [];
    for (const name of order) {
      const count = point.counts[name] ?? 0;
      if (count <= 0) continue;
      const height = (plotH * count) / top;
      y -= height;
      parts.push({ name, y, height, count });
    }
    return { index, point, x, width, total: totals[index] ?? 0, parts, top: PAD_T };
  });
  return { top, grid, bars, every: Math.max(1, Math.round(n / 12)) };
}

export function sum(values: readonly number[]): number {
  return values.reduce((a, b) => a + b, 0);
}

export interface Part {
  key: string;
  count: number;
  /** left edge and width in the 1,000-unit bar */
  x: number;
  width: number;
}

/** One bar split into parts, largest first (ties by name), for a share at a glance. */
export function shares(counts: Readonly<Record<string, number>>): Part[] {
  const entries = Object.entries(counts).sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  const total = sum(entries.map(([, n]) => n));
  let x = 0;
  const out: Part[] = [];
  for (const [key, count] of entries) {
    if (count <= 0) continue;
    const width = (1000 * count) / total;
    out.push({ key, count, x, width });
    x += width;
  }
  return out;
}

/** "Mon 12 Oct" or, for an hourly bucket, "12 Oct 2 PM" (the bucket's start in IST, as the server wrote it). */
export function bucketLabel(at: string, hourly: boolean): string {
  const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})/.exec(at);
  if (!m) return at;
  const day = Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3]));
  const weekday = new Date(day).toLocaleDateString("en-GB", { weekday: "short", timeZone: "UTC" });
  const month = new Date(day).toLocaleDateString("en-GB", { month: "short", timeZone: "UTC" });
  const d = String(Number(m[3])).padStart(2, "0");
  return hourly ? `${d} ${month} ${hourWords(Number(m[4]))}` : `${weekday} ${d} ${month}`;
}

/** The tick under a bar: "2 PM" for an hourly bucket, "12 Oct" for a daily one. */
export function tickLabel(at: string, hourly: boolean): string {
  const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):/.exec(at);
  if (!m) return at;
  if (hourly) return hourWords(Number(m[4]));
  const month = new Date(Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3]))).toLocaleDateString("en-GB", { month: "short", timeZone: "UTC" });
  return `${String(Number(m[3])).padStart(2, "0")} ${month}`;
}

/**
 * The Reports page's words (Q-H3): a figure said the way the server's plain-text report says it
 * (src/argus/reporter/render.py), a report's title and file names, and the download. Pure except
 * `save`.
 */
import type { ReportMetricOut, ReportOut, ReportRowOut } from "../client/types.gen";
import { isMarked } from "./untrusted";

export const UNAVAILABLE = "n/a";

/** 3903 as "1 h 5 min 3 s": exact, zero parts left out ("0 s" for none). */
export function duration(seconds: number): string {
  const total = Math.max(Math.trunc(seconds), 0);
  const hours = Math.floor(total / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  const secs = total % 60;
  const parts = [
    [hours, "h"],
    [minutes, "min"],
    [secs, "s"],
  ]
    .filter(([n]) => n !== 0)
    .map(([n, u]) => `${n} ${u}`);
  return parts.join(" ") || "0 s";
}

/** 3903250 as "1 h 5 min 3 s 250 ms". */
export function durationMs(ms: number): string {
  const total = Math.max(Math.trunc(ms), 0);
  const seconds = Math.floor(total / 1000);
  const rest = total % 1000;
  const parts = seconds > 0 ? [duration(seconds)] : [];
  if (rest !== 0 || parts.length === 0) parts.push(`${rest} ms`);
  return parts.join(" ");
}

/** A figure as the page shows it, word for word as the server's text says it: counts as they are (no grouping), percentages to their one decimal, durations in whole units. */
export function shown(m: Pick<ReportMetricOut, "value" | "unit">): string {
  const v = m.value;
  if (v === null || v === undefined) return UNAVAILABLE;
  if (typeof v === "string") return v;
  switch (m.unit) {
    case "percent":
      return `${Number.isInteger(v) ? v.toFixed(1) : v}%`;
    case "ms":
      return durationMs(v);
    case "seconds":
      return duration(v);
    case "hours":
      return `${v} hour${v === 1 ? "" : "s"}`;
    default:
      return String(v);
  }
}

const DAY = 86_400_000;
const MOST = BigInt("4611686018427387904"); // 2^62: the largest id the API takes

/** A report id the API accepts (1 to 2^62, no sign, no leading zero). */
export function validReportId(id: string): boolean {
  return /^[1-9][0-9]{0,18}$/.test(id) && BigInt(id) <= MOST;
}

/** The UTC date (YYYY-MM-DD) of the last day a report covers. */
export function lastDay(r: Pick<ReportRowOut, "period_end">): string {
  return new Date(new Date(r.period_end).getTime() - DAY).toISOString().slice(0, 10);
}

function dayWords(iso: string): string {
  const d = new Date(`${iso}T00:00:00Z`);
  return d.toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric", timeZone: "UTC" });
}

/** "Daily report for 20 Oct 2026" or "Weekly report, 14 Oct 2026 to 20 Oct 2026" (UTC days). */
export function title(r: Pick<ReportRowOut, "kind" | "period_start" | "period_end">): string {
  const last = lastDay(r);
  if (r.kind === "daily") return `Daily report for ${dayWords(last)}`;
  return `Weekly report, ${dayWords(new Date(r.period_start).toISOString().slice(0, 10))} to ${dayWords(last)}`;
}

/** argus-daily-report-2026-10-20.txt: named by its last UTC day. */
export function fileName(r: Pick<ReportRowOut, "kind" | "period_end">, extension: "txt" | "json"): string {
  return `argus-${r.kind}-report-${lastDay(r)}.${extension}`;
}

/** `text` with every hidden character (bidi controls, zero-width and tag characters, other controls but
 * tab and newline) written out as an escape, as the server writes the names in its own text. */
export function escapeHidden(text: string): string {
  let out = "";
  for (const char of text) {
    const code = char.codePointAt(0) as number;
    if (!isMarked(code)) out += char;
    else if (code <= 0xff) out += `\\x${code.toString(16).padStart(2, "0")}`;
    else if (code <= 0xffff) out += `\\u${code.toString(16).padStart(4, "0")}`;
    else out += `\\U${code.toString(16).padStart(8, "0")}`;
  }
  return out;
}

/** The report as a downloaded text file: the server's own text (already escaped), and the summary
 * above it, escaped the same way. */
export function asText(r: ReportOut): string {
  return r.prose === null || r.prose === undefined ? r.text : `${escapeHidden(r.prose)}\n\n${r.text}`;
}

export function asJson(r: ReportOut): string {
  return `${JSON.stringify(r, null, 2)}\n`;
}

/** Hand `body` to the browser as a file. */
export function save(name: string, type: string, body: string): void {
  const url = URL.createObjectURL(new Blob([body], { type }));
  const link = document.createElement("a");
  link.href = url;
  link.download = name;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

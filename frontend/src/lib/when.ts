/**
 * The short times of the UI v2's cards and rows, in the site's zone, 12-hour (docs/p4f-ui-spec.md
 * §0.2): "4 Nov", "5 Nov 2:00 PM", "6:55 PM", "Thu 6 Nov", and how long something has waited.
 * The full time with UTC stays the `Time` component's hover. Pure but for the site's zone.
 */
import { zone } from "./site";

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const FULL_DAYS = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];

interface Parts {
  year: number;
  month: number;
  day: number;
  weekday: number;
  hour: number;
  minute: number;
}

const FORMATS = new Map<string, Intl.DateTimeFormat>();
function format(): Intl.DateTimeFormat {
  const tz = zone();
  let f = FORMATS.get(tz);
  if (f === undefined) {
    const options: Intl.DateTimeFormatOptions = { year: "numeric", month: "numeric", day: "numeric", weekday: "short", hour: "numeric", minute: "2-digit", hourCycle: "h23" };
    try {
      f = new Intl.DateTimeFormat("en-US", { ...options, timeZone: tz });
    } catch {
      f = new Intl.DateTimeFormat("en-US", { ...options, timeZone: "UTC" });
    }
    FORMATS.set(tz, f);
  }
  return f;
}

export function partsOf(date: Date): Parts {
  const p: Record<string, string> = {};
  for (const part of format().formatToParts(date)) p[part.type] = part.value;
  return {
    year: Number(p.year),
    month: Number(p.month) - 1,
    day: Number(p.day),
    weekday: Math.max(0, DAYS.indexOf(p.weekday ?? "")),
    hour: Number(p.hour) % 24,
    minute: Number(p.minute),
  };
}

/** "6:55 PM" */
export function clock(date: Date): string {
  const { hour, minute } = partsOf(date);
  const h = hour % 12 === 0 ? 12 : hour % 12;
  return `${h}:${String(minute).padStart(2, "0")} ${hour < 12 ? "AM" : "PM"}`;
}

/** "4 Nov" */
export function shortDay(date: Date): string {
  const p = partsOf(date);
  return `${p.day} ${MONTHS[p.month]}`;
}

/** "5 Nov 2:00 PM" */
export function dayAndTime(date: Date): string {
  return `${shortDay(date)} ${clock(date)}`;
}

/** "Thu 6 Nov" */
export function weekdayDay(date: Date): string {
  const p = partsOf(date);
  return `${DAYS[p.weekday]} ${p.day} ${MONTHS[p.month]}`;
}

/** "Thursday 6 Nov" */
export function longDay(date: Date): string {
  const p = partsOf(date);
  return `${FULL_DAYS[p.weekday]} ${p.day} ${MONTHS[p.month]}`;
}

/** Days between two local calendar days (b after a: positive). */
export function dayDiff(a: Date, b: Date): number {
  const pa = partsOf(a);
  const pb = partsOf(b);
  return Math.round((Date.UTC(pb.year, pb.month, pb.day) - Date.UTC(pa.year, pa.month, pa.day)) / 86_400_000);
}

/** "today 4:10 PM", "yesterday", "Mon", or "2 Nov": how a past moment reads next to now. */
export function sinceWords(date: Date, now: Date = new Date()): string {
  const d = dayDiff(date, now);
  if (d <= 0) return `today ${clock(date)}`;
  if (d === 1) return "yesterday";
  if (d < 7) return DAYS[partsOf(date).weekday] ?? shortDay(date);
  return shortDay(date);
}

/** "3 days", "5 hours", "under an hour": how long since `date`. */
export function waited(date: Date, now: Date = new Date()): string {
  const hours = Math.floor((now.getTime() - date.getTime()) / 3_600_000);
  if (hours < 1) return "under an hour";
  if (hours < 24) return `${hours} ${hours === 1 ? "hour" : "hours"}`;
  const days = Math.floor(hours / 24);
  return `${days} ${days === 1 ? "day" : "days"}`;
}

/** "Tue 4:10 PM" (the summary's "since"). */
export function roundWords(date: Date, now: Date = new Date()): string {
  const d = dayDiff(date, now);
  if (d <= 0) return `today ${clock(date)}`;
  if (d < 7) return `${DAYS[partsOf(date).weekday]} ${clock(date)}`;
  return dayAndTime(date);
}

import { zone, zoneLabel } from "./site";

/**
 * Times as the reviewers read them: the site's zone in 12-hour form ("29 Oct 2026, 7:20 PM IST"
 * for a site in Asia/Kolkata). The rule is the site's zone, 12-hour, everywhere a time
 * is shown; UTC is only the hover's second reading (plan §7.5), in the same 12-hour form. The
 * zone and its label come from the server (`lib/site.ts`, D-284).
 */
const PARTS = (timeZone: string, seconds: boolean) =>
  new Intl.DateTimeFormat("en-GB", {
    timeZone,
    day: "numeric",
    month: "numeric",
    year: "numeric",
    hour: "numeric",
    minute: "2-digit",
    ...(seconds ? { second: "2-digit" } : {}),
    hour12: true,
  });
const FORMATS = new Map<string, Intl.DateTimeFormat>();
function formatFor(timeZone: string, seconds: boolean): Intl.DateTimeFormat {
  const key = `${timeZone}|${seconds}`;
  let format = FORMATS.get(key);
  if (format === undefined) {
    try {
      format = PARTS(timeZone, seconds);
    } catch {
      // a zone this browser's tz data does not know: a time must still be drawable (in UTC, labelled so)
      format = PARTS("UTC", seconds);
    }
    FORMATS.set(key, format);
  }
  return format;
}

// fixed, not the browser's: a locale writes September as "Sept" or "Sep", and the pages say "Sep"
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

function spoken(format: Intl.DateTimeFormat, date: Date): string {
  const p: Record<string, string> = {};
  for (const part of format.formatToParts(date)) p[part.type] = part.value;
  const clock = p.second !== undefined ? `${p.hour}:${p.minute}:${p.second}` : `${p.hour}:${p.minute}`;
  return `${Number(p.day)} ${MONTHS[Number(p.month) - 1]} ${p.year}, ${clock} ${(p.dayPeriod ?? "").toUpperCase()}`;
}

export function parse(value: string | Date | null | undefined): Date | null {
  if (value == null) return null;
  const date = value instanceof Date ? value : new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

/** "23 Oct 2026, 3:00 PM IST": the site's zone and its label (the name is from when the zone was India's). */
export function ist(date: Date): string {
  return `${spoken(formatFor(zone(), false), date)} ${zoneLabel(date)}`;
}

/** "23 Oct 2026, 9:30:00 AM UTC": the hover's second reading, in the same 12-hour form. */
export function utc(date: Date): string {
  return `${spoken(formatFor("UTC", true), date)} UTC`;
}

/** "5:30 AM": the site's clock when a UTC day begins (the reports' day). */
export function utcDayStart(): string {
  const p: Record<string, string> = {};
  for (const part of formatFor(zone(), false).formatToParts(new Date(Date.UTC(2026, 0, 1)))) p[part.type] = part.value;
  return `${p.hour}:${p.minute} ${(p.dayPeriod ?? "").toUpperCase()}`;
}

/** "3:00 PM" for an hour of the day (0 to 23), as a chart's tick: "12 AM" is midnight, "12 PM" noon. */
export function hourWords(hour: number): string {
  const h = hour % 12 === 0 ? 12 : hour % 12;
  return `${h} ${hour < 12 ? "AM" : "PM"}`;
}

/** "3 min ago", "2 h ago", "4 d ago"; "just now" under a minute; a future time "in the future". */
export function ago(date: Date, now: Date = new Date()): string {
  const seconds = Math.round((now.getTime() - date.getTime()) / 1000);
  if (seconds < -60) return "in the future";
  if (seconds < 60) return "just now";
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 48) return `${hours} h ago`;
  return `${Math.floor(hours / 24)} d ago`;
}

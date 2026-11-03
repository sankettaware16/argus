/**
 * Wall clocks and offsets of an IANA time zone (D-284): a time typed into a date-and-time box
 * is the site's clock whatever the browser's own zone is, so the instant it means is worked out
 * with the zone's rules, not the browser's.
 */
const WALL = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})$/;

/** Minutes east of UTC that `timeZone` is at the instant `at` (330 for Asia/Kolkata, always). */
export function offsetMinutes(timeZone: string, at: Date): number {
  const p: Record<string, string> = {};
  const format = new Intl.DateTimeFormat("en-US", {
    timeZone,
    hourCycle: "h23",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
  for (const part of format.formatToParts(at)) p[part.type] = part.value;
  // setUTCFullYear, not Date.UTC: Date.UTC reads the years 0 to 99 as 1900 to 1999
  const wallDate = new Date(0);
  wallDate.setUTCFullYear(Number(p.year), Number(p.month) - 1, Number(p.day));
  wallDate.setUTCHours(Number(p.hour), Number(p.minute), Number(p.second), 0);
  return Math.round((wallDate.getTime() - Math.floor(at.getTime() / 1000) * 1000) / 60_000);
}

/** "+05:30" for 330 minutes, "-03:00" for -180. */
export function offsetText(minutes: number): string {
  const sign = minutes < 0 ? "-" : "+";
  const total = Math.abs(minutes);
  return `${sign}${String(Math.floor(total / 60)).padStart(2, "0")}:${String(total % 60).padStart(2, "0")}`;
}

/**
 * The instant a wall clock ("2026-10-26T09:30", no seconds) is in `timeZone`, or undefined when
 * the text is no time, names a day or an hour that does not exist (31 February, 25:00), or falls
 * in the hour a clock change skips. In the hour a clock change repeats it is the first of the two
 * instants, as the server reads it (`fold=0`).
 */
export function wallInstant(timeZone: string, wall: string): Date | undefined {
  if (!WALL.test(wall)) return undefined;
  const asUtc = new Date(`${wall}:00Z`).getTime();
  // 31 February and 25:00 parse (or roll over) as another time: the text must read back as itself
  if (Number.isNaN(asUtc) || new Date(asUtc).toISOString().slice(0, 16) !== wall) return undefined;
  // the offsets in force a day before and a day after: a wall clock is one of them
  const offsets = new Set([-1, 1].map((day) => offsetMinutes(timeZone, new Date(asUtc + day * 86_400_000))));
  const found: number[] = [];
  for (const offset of offsets) {
    const at = asUtc - offset * 60_000;
    if (offsetMinutes(timeZone, new Date(at)) === offset) found.push(at);
  }
  return found.length === 0 ? undefined : new Date(Math.min(...found));
}

import { ago, ist, parse, utc } from "../lib/time";

/** A time in IST, UTC on hover; "relative" shows "3 min ago" with both on hover. */
export function Time({ value, relative = false }: { value: string | Date | null | undefined; relative?: boolean }) {
  const date = parse(value);
  if (date === null) return <span className="text-muted">unknown time</span>;
  return (
    <time dateTime={date.toISOString()} title={relative ? `${ist(date)} · ${utc(date)}` : utc(date)}>
      {relative ? ago(date) : ist(date)}
    </time>
  );
}

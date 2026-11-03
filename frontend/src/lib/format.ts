/** Numbers and spans as the pages write them (the classic dashboard's words). Pure. */
const COUNT = new Intl.NumberFormat("en-IN");

export function count(n: number): string {
  return COUNT.format(n);
}

/** "45 min", "3 h 20 min", "2 days 4 h"; "—" for none (src/argus/web/dashboard.py `duration`). */
export function duration(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined) return "—";
  const minutes = Math.trunc(seconds) / 60;
  const whole = Math.floor(minutes);
  if (whole < 60) return `${whole} min`;
  const hours = Math.floor(whole / 60);
  const rest = whole % 60;
  if (hours < 48) return rest > 0 ? `${hours} h ${rest} min` : `${hours} h`;
  const days = Math.floor(hours / 24);
  const left = hours % 24;
  return left > 0 ? `${days} days ${left} h` : `${days} days`;
}

/** "+12% vs the span before (340)", or "none in the span before". */
export function versusBefore(now: number, before: number): string {
  if (before <= 0) return "none in the span before";
  const delta = now - before;
  return `${delta >= 0 ? "+" : "−"}${Math.round((100 * Math.abs(delta)) / before)}% vs the span before (${count(before)})`;
}

export function percent(part: number, whole: number, digits = 0): string | null {
  if (whole <= 0) return null;
  const value = (100 * part) / whole;
  return digits === 0 ? `${Math.round(value)}%` : `${value.toFixed(digits)}%`;
}

export function plural(n: number, one: string, many: string = `${one}s`): string {
  return n === 1 ? one : many;
}

/** A capped count: "10,000 or more" when the server stopped counting there. */
export function capped(n: number, cap: number): string {
  return n >= cap ? `${count(cap)} or more` : count(n);
}

/** 2100 ms as "2.1 s", 850 ms as "850 ms". */
export function serverTime(ms: number): string {
  return ms >= 1000 ? `${(ms / 1000).toFixed(1)} s` : `${Math.round(ms)} ms`;
}

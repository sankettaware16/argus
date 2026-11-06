/**
 * The quiet "System" indicator and the one banner (P4-F U8): what the shell says about ARGUS's
 * own health, in the queue's terms. Nothing is said while all is well but "System: OK"; a banner
 * appears only when the queue itself may be wrong (ARGUS is not reading the SIEM, or it stopped
 * reading new alerts). Everything else (the SIEM reading less, the Kibana read-back, gaps, AI
 * cost) is in the indicator's details. Pure (tests/system.test.ts).
 */
import type { HealthOut } from "../client/types.gen";
import { parse } from "./time";

export const STALE_HOURS = 2; // new alerts not read for this long: the queue may be missing some

export interface SystemWord {
  tone: "ok" | "warn" | "danger";
  word: string;
  /** what the banner says, in the queue's terms; null: no banner */
  banner: string | null;
  /** each thing that is not as it should be, for the details */
  notes: string[];
}

function hours(ms: number): string {
  const h = Math.floor(ms / 3_600_000);
  return h >= 48 ? `${Math.floor(h / 24)} days` : `${h} hours`;
}

/** The indicator and the banner from the health ARGUS last measured; `now` for the age of what it read. */
export function systemWord(h: HealthOut | undefined, now: Date): SystemWord {
  if (h === undefined) return { tone: "ok", word: "System", banner: null, notes: [] };
  const notes: string[] = [];
  let banner: string | null = null;
  if (h.siem_state === "stop") banner = "ARGUS is not reading the SIEM now, to protect it: new incidents may arrive late.";
  else if (h.siem_state === "degraded") banner = "ARGUS reads very little from the SIEM now, to protect it: new incidents may arrive late.";
  const cursor = parse(h.live_cursor);
  if (cursor === null) notes.push("ARGUS has not read any alert yet.");
  else if (now.getTime() - cursor.getTime() > STALE_HOURS * 3_600_000) {
    banner = `ARGUS has not read new alerts from the SIEM for ${hours(now.getTime() - cursor.getTime())}: new incidents may be missing.`;
  }
  if (h.siem_state === "caution") notes.push("The SIEM is busy, so ARGUS reads less for now.");
  if (h.open_gaps.length > 0) notes.push(`${h.open_gaps.length === 1 ? "One stretch of time has" : `${h.open_gaps.length} stretches of time have`} alerts ARGUS could not read: what happened then is unknown.`);
  if (h.jobs_failed > 0) notes.push(`${h.jobs_failed} ${h.jobs_failed === 1 ? "piece of work" : "pieces of work"} failed and wait for an admin.`);
  const sync = h.kibana_sync.state;
  if (sync === "failed" || sync === "late" || sync === "partial") notes.push("ARGUS's read-back of Kibana's cases is not up to date.");
  if (banner !== null) return { tone: "danger", word: "System: needs a look", banner, notes };
  if (notes.length > 0 && !(notes.length === 1 && cursor === null)) return { tone: "warn", word: "System: check", banner: null, notes };
  return { tone: "ok", word: "System: OK", banner: null, notes };
}

export const PROBE_STALE_MIN = 60; // the SIEM's health not measured for this long: a Problem

export interface SystemDot {
  state: "ok" | "caution" | "problem";
  word: "OK" | "Caution" | "Problem";
  /** one line per part (the popover): SIEM, ARGUS's reading, Kibana read-back */
  parts: { name: string; words: string }[];
  /** Today's banner, in queue terms; only in the Problem state */
  banner: string | null;
}

function span(ms: number): string {
  const minutes = Math.round(ms / 60_000);
  if (minutes < 60) return `${minutes} min`;
  const hours = Math.round(minutes / 60);
  return hours < 48 ? `${hours} h` : `${Math.round(hours / 24)} days`;
}

/**
 * The header's system dot (docs/p4f-ui-spec.md §4.2, F25): Problem when ARGUS stopped reading the
 * SIEM, or measured its health over an hour ago (Kibana posting joins once `/health` reports it:
 * A5); Caution when the SIEM is busy, the Kibana read-back is behind, work failed or alerts went
 * unread; OK otherwise. `clock` writes the time of the banner's sentence.
 */
export function systemDot(h: HealthOut | undefined, now: Date, clock: (d: Date) => string = (d) => d.toISOString()): SystemDot {
  if (h === undefined) return { state: "ok", word: "OK", parts: [], banner: null };
  const probed = parse(h.siem_probed_at);
  const old = probed === null || now.getTime() - probed.getTime() > PROBE_STALE_MIN * 60_000;
  const parts: SystemDot["parts"] = [];
  const siem: Record<string, string> = { normal: "normal", caution: "busy: ARGUS reads less", degraded: "very busy: ARGUS reads very little", stop: "stopped: ARGUS reads nothing, to protect it" };
  parts.push({ name: "SIEM", words: siem[h.siem_state] ?? "not known" });
  parts.push({ name: "ARGUS's reading", words: probed === null ? "not measured yet" : old ? `last measured ${span(now.getTime() - probed.getTime())} ago` : h.open_gaps.length > 0 ? `${h.open_gaps.length} stretch${h.open_gaps.length === 1 ? "" : "es"} of time could not be read` : h.jobs_failed > 0 ? `${h.jobs_failed} piece${h.jobs_failed === 1 ? "" : "s"} of work failed` : "up to date" });
  const sync: Record<string, string> = { none: "not running yet", ok: "in sync", partial: "partly read", failed: "failing", late: "late" };
  parts.push({ name: "Kibana read-back", words: sync[h.kibana_sync.state] ?? "not known" });
  let banner: string | null = null;
  if (h.siem_state === "stop" || old) {
    banner = probed === null ? "ARGUS has not read the SIEM yet. New incidents may be missing or late." : `ARGUS has not read the SIEM since ${clock(probed)} (${span(now.getTime() - probed.getTime())}). New incidents may be missing or late.`;
  }
  if (banner !== null) return { state: "problem", word: "Problem", parts, banner };
  const caution = h.siem_state === "caution" || h.siem_state === "degraded" || ["failed", "late", "partial"].includes(h.kibana_sync.state) || h.jobs_failed > 0 || h.open_gaps.length > 0;
  return caution ? { state: "caution", word: "Caution", parts, banner: null } : { state: "ok", word: "OK", parts, banner: null };
}

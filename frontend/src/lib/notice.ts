/**
 * The notice, the block and the withdrawal of AR4b as the case page asks for them (D-176 to D-181):
 * what a form checks before it shows the request, and the words for how a person was told. The server
 * checks the same and answers 422; here the person is told before anything is sent. Pure
 * (tests/notice.test.ts).
 */
import type { KnownOut, NoticeIn } from "../client/types.gen";
import { kind, teamName, zone, zoneLabel } from "./site";
import { ist } from "./time";
import { offsetMinutes, offsetText, wallInstant } from "./zone";

export const HOW: Readonly<Record<NoticeIn["how"], string>> = {
  email: "By e-mail",
  phone: "By phone",
  in_person: "In person",
  through_it: "Through IT",
  other: "Another way",
};
export const HOW_KEYS = Object.keys(HOW) as NoticeIn["how"][];

export const TOLD_MAX = 200;
export const WHERE_MAX = 100;
export const TEXT_MAX = 4000;
const SLACK_MS = 5 * 60_000; // the server's clock slack for a date "now"
const YEAR_MS = 365 * 86_400_000;
// the machine's one-line rule: no control character (C0, DEL and C1)
// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u001f\u007f-\u009f]/;

/** A one-line answer to "who", "where": words, one line, not too long. */
export function lineProblem(label: string, value: string, max: number): string | null {
  const said = value.trim();
  if (said === "") return `${label} is needed.`;
  if (said.length > max) return `${label} has at most ${max} characters.`;
  if (CONTROL.test(said)) return `${label} must be one line, without control characters.`;
  return null;
}

/** Free text: at most 4,000 characters and no NUL. */
export function textProblem(label: string, value: string, required: boolean): string | null {
  const said = value.trim();
  if (required && said === "") return `${label} is needed.`;
  if (said.length > TEXT_MAX) return `${label} has at most ${TEXT_MAX} characters.`;
  if (said.includes("\u0000")) return `${label} holds a character ARGUS cannot keep.`;
  return null;
}

/**
 * The time a person typed into a date-and-time box, as an instant. The box holds a time of the
 * site's clock (IST, say), whatever the browser's own time zone: "2026-10-26T09:30" is 9:30 AM IST.
 * Empty means "now" (null); a value that is not a time, or names a day or an hour that does not
 * exist (31 February, 25:00), is `undefined`: the date parser would carry such a value into the
 * next month or day and record another time than the one typed (AR4 review).
 */
export function istInstant(local: string): Date | null | undefined {
  const said = local.trim();
  if (said === "") return null;
  return wallInstant(zone(), said);
}

/**
 * The same time as the request writes it: the person's own wall clock with its offset
 * ("2026-10-26T09:30:00+05:30"), so the exact request the dialog shows reads as typed, not as a
 * UTC instant; the server reads the offset. Null: empty or not a time.
 */
export function istStamp(local: string): string | null {
  const at = istInstant(local);
  return at instanceof Date ? `${local.trim()}:00${offsetText(offsetMinutes(zone(), at))}` : null;
}

/** The time the request will record, in words (the site's zone, 12-hour), for the confirm dialog; "now" when empty. */
export function whenWords(local: string): string {
  const at = istInstant(local);
  return at instanceof Date ? `It is dated ${ist(at)}.` : "It is dated when you send it.";
}

/** Why a date cannot be recorded: not a time, in the future, or more than a year back. */
export function whenProblem(local: string, now: Date): string | null {
  const at = istInstant(local);
  if (at === undefined) return `Write the time as a date and a time (${zoneLabel()}).`;
  if (at === null) return null;
  if (at.getTime() > now.getTime() + SLACK_MS) return "That time is in the future. Leave it empty for now.";
  if (at.getTime() < now.getTime() - YEAR_MS) return "That time is more than a year ago.";
  return null;
}

export interface NoticeDraft {
  told: string;
  how: string;
  at: string;
  note: string;
}

export function noticeProblem(d: NoticeDraft, now: Date): string | null {
  if (!(HOW_KEYS as string[]).includes(d.how)) return "Choose how the owner was told.";
  return lineProblem("Who was told", d.told, TOLD_MAX) ?? whenProblem(d.at, now) ?? textProblem("The note", d.note, false);
}

export interface BlockDraft {
  by: string;
  where: string;
  at: string;
  note: string;
}

export function blockProblem(d: BlockDraft, now: Date): string | null {
  return lineProblem("Who blocked it", d.by, TOLD_MAX) ?? lineProblem("Where it was blocked", d.where, WHERE_MAX) ?? whenProblem(d.at, now) ?? textProblem("The note", d.note, false);
}

export interface WithdrawDraft {
  who: string;
  reason: string;
}

export function withdrawProblem(d: WithdrawDraft): string | null {
  const who = d.who.trim() === "" ? null : lineProblem("Who withdraws it", d.who, TOLD_MAX);
  return who ?? textProblem("The reason", d.reason, true);
}

/** The request body for a notice: only what the person filled in. */
export function noticeBody(version: number, d: NoticeDraft): NoticeIn {
  const at = istStamp(d.at);
  return {
    expected_version: version,
    told: d.told.trim(),
    how: d.how as NoticeIn["how"],
    ...(at !== null ? { at } : {}),
    ...(d.note.trim() !== "" ? { note: d.note.trim() } : {}),
  };
}

export function blockBody(version: number, d: BlockDraft) {
  const at = istStamp(d.at);
  return {
    expected_version: version,
    by: d.by.trim(),
    where: d.where.trim(),
    ...(at !== null ? { at } : {}),
    ...(d.note.trim() !== "" ? { note: d.note.trim() } : {}),
  };
}

export function withdrawBody(version: number, d: WithdrawDraft) {
  return { expected_version: version, ...(d.who.trim() !== "" ? { who: d.who.trim() } : {}), reason: d.reason.trim() };
}

/** Whether the machines of a notified case are the organisation's own or people's own (D-176, D-180). */
export function managedWords(managed: KnownOut["managed"]): string {
  if (managed === true) return `These are ${kind()}-managed machines (labs and shared computer rooms): ${teamName()} can act on them, and the watch and a verified containment still apply.`;
  if (managed === false) return `These are personal devices: ${teamName()} can find the device and tell its owner, but cannot wipe or isolate it, so the case stays open while the device stays infected. ARGUS tracks it quietly and speaks only when something changes.`;
  return `Once the owner is told, ARGUS says here whether these are ${kind()}-managed machines or personal devices (an address it cannot place counts as personal).`;
}

export const REMINDER_WORDS: Readonly<Record<string, string>> = {
  notify_again: "Tell the owner again: the device is still active",
  network_action: "Ask for a block at the network: the device is still active",
};

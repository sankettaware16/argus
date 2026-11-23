/**
 * The Alerts page's address (the menu's third entry): every alert group ARGUS took in, newest
 * first, with the incident each one belongs to. Pure (tests/alerts.test.tsx).
 */
import { first } from "./search";

export const MEMBERSHIPS = ["all", "incident", "none"] as const;
export type Membership = (typeof MEMBERSHIPS)[number];
export const MEMBERSHIP_WORDS: Readonly<Record<Membership, string>> = { all: "All", incident: "In an incident", none: "Not in an incident" };

export const ALERT_STATES = ["all", "attention", "open", "reviewed"] as const;
export type AlertState = (typeof ALERT_STATES)[number];
export const ALERT_STATE_WORDS: Readonly<Record<AlertState, string>> = { all: "Any state", attention: "Needs attention", open: "Not reviewed yet", reviewed: "Reviewed" };

export interface AlertsSearch {
  /** only alert groups in an incident, or in none; left out: all */
  in?: Exclude<Membership, "all">;
  /** only one review state; left out: any */
  state?: Exclude<AlertState, "all">;
  /** only one rule's alert groups (the rule's id); left out: every rule */
  rule?: string;
}

/** The address's three choices; anything else is left out (the page then shows everything). */
export function parseAlerts(raw: Record<string, unknown>): AlertsSearch {
  const out: AlertsSearch = {};
  const membership = first(raw.in);
  if (membership === "incident" || membership === "none") out.in = membership;
  const state = first(raw.state);
  if (state === "attention" || state === "open" || state === "reviewed") out.state = state;
  const rule = first(raw.rule);
  if (rule !== undefined && rule !== "" && rule.length <= 200 && !rule.includes("\u0000")) out.rule = rule;
  return out;
}

/** What the list API is asked for. */
export function alertsQuery(search: AlertsSearch): { view: "all" | "attention" | "open" | "reviewed"; incident?: "in" | "none"; rule?: string } {
  return {
    view: search.state ?? "all",
    ...(search.in ? { incident: search.in === "incident" ? ("in" as const) : ("none" as const) } : {}),
    ...(search.rule !== undefined ? { rule: search.rule } : {}),
  };
}

/** The sentence under the heading: what the list holds, in words. */
export function alertsLead(search: AlertsSearch): string {
  const which = search.in === "incident" ? " that belong to an incident" : search.in === "none" ? " that belong to no incident" : "";
  const state = search.state === "attention" ? " and need attention" : search.state === "open" ? " and are not reviewed yet" : search.state === "reviewed" ? " and were reviewed" : "";
  const rule = search.rule !== undefined ? " of one rule" : "";
  return `The alert groups${rule}${which}${state}, newest alert first. An alert group is the alerts of one rule for one device, account or address on one day.`;
}

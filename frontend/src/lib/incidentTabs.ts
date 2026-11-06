/** The incident page's tabs (docs/p4f-ui-spec.md §4.3, §7), and the old case page's anchors as tabs. */
export const INCIDENT_TABS = ["overview", "story", "evidence", "entities", "alert-groups", "report", "activity"] as const;
export type IncidentTab = (typeof INCIDENT_TABS)[number] | "all";

/** `#report` → report, `#notes`/`#history` → activity, `#members` → alert groups, anything else → overview. */
export function tabForAnchor(hash: string): IncidentTab {
  const h = hash.replace(/^#/, "");
  if (h === "report" || h === "kibana" || h === "kibana-case") return "report";
  if (h === "notes" || h === "history" || h === "approvals" || h === "notified" || h === "actions") return "activity";
  if (h === "members") return "alert-groups";
  return "overview";
}

/** A tab the address may name: one of the tabs, or "all" (everything on one page, to print or read through). */
export function isIncidentTab(tab: string | undefined): tab is IncidentTab {
  return tab !== undefined && (tab === "all" || (INCIDENT_TABS as readonly string[]).includes(tab));
}

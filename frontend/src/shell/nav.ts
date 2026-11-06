/** The shell's menu (docs/p4f-ui-spec.md §4.1): four pages for the daily job, the rest under More,
 * and the person's own entries under their name. Every page is in /app; the entries with an
 * `href` open a server-rendered page ("Your access" and the read-only classic pages). */
export interface NavItem {
  label: string;
  /** a path inside /app (to), with the search that picks the entry, or a classic page (href) */
  to?: string;
  search?: Record<string, string>;
  href?: string;
  hint: string;
  /** shown only to admins (and in a development build) */
  admin?: boolean;
  /** the group heading it sits under in More */
  group?: string;
}

export const PRIMARY: NavItem[] = [
  { label: "Today", to: "/", hint: "What needs you today, and what ARGUS handled on its own" },
  { label: "Incidents", to: "/incidents", search: { view: "needs-you" }, hint: "Every incident and possible incident, by priority" },
  { label: "Search", to: "/search", hint: "One box for an address, a host, an account, a domain, a rule or an incident" },
  { label: "Reports", to: "/reports", hint: "Incident reports first, then the daily and weekly summaries" },
];

export const MORE: NavItem[] = [
  { label: "Overview", to: "/overview", hint: "Alerts, alert groups and incidents at a glance" },
  { label: "Approvals", to: "/approvals", hint: "Closures and merges waiting for a person to decide" },
  { label: "Rule tuning", to: "/tuning", hint: "Weekly suggestions to make noisy rules quieter" },
  { label: "ARGUS quality", to: "/quality", search: { tab: "metrics" }, hint: "How often ARGUS is right: its results and the gold set" },
  { label: "System health", to: "/health", hint: "Is data arriving; any gaps" },
  { label: "Help & glossary", to: "/glossary", hint: "What every word means" },
  { label: "Patterns", to: "/patterns", hint: "Groups of alike alert groups to review at once", group: "Classic queues" },
  { label: "Proposals", to: "/proposals", hint: "Outcomes ARGUS proposes, to confirm", group: "Classic queues" },
  { label: "Design system", to: "/design", hint: "The app's colours, components and safety checks", admin: true },
];

export const ACCOUNT: NavItem[] = [
  { label: "Your access", href: "/access", hint: "What you may do in ARGUS, why, and how fresh that is" },
  { label: "Classic pages", href: "/classic", hint: "The pages ARGUS had before this app, kept for now as a read-only fallback" },
];

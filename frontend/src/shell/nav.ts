/** The shell's menu (docs/p4f-ui-spec.md §4.1): the daily pages first, then the pages a person
 * works with and the ones that say how ARGUS is doing, the administration for those who may,
 * and what is opened rarely under More. The person's own entries are under their name. Every
 * page is in /app; the entries with an `href` open a server-rendered page ("Your access"). */
export interface NavItem {
  label: string;
  /** a path inside /app (to), with the search that picks the entry, or a server-rendered page (href) */
  to?: string;
  search?: Record<string, string>;
  href?: string;
  hint: string;
  /** shown only to admins (and in a development build) */
  admin?: boolean;
  /** shown only where the site has an account directory and the person may ask it (D-337) */
  directory?: boolean;
}

export interface NavSection {
  title: string;
  items: NavItem[];
  /** folded until asked for: the pages opened rarely */
  folded?: boolean;
}

export const PRIMARY: NavItem[] = [
  { label: "Today", to: "/", hint: "What needs you today, and what ARGUS handled on its own" },
  { label: "Incidents", to: "/incidents", search: { view: "needs-you" }, hint: "Every incident and possible incident, by priority" },
  { label: "Alerts", to: "/alerts", hint: "Every alert group ARGUS took in, and the incident each one belongs to" },
  { label: "Dashboards", to: "/dashboards", hint: "Security overview, detections and how ARGUS is running, with live charts" },
  { label: "Search", to: "/search", hint: "One box for an address, a host, an account, a domain, a rule or an incident" },
  { label: "Reports", to: "/reports", hint: "Incident reports first, then the daily and weekly summaries" },
];

/** The phone's tab bar: the four pages opened most; the rest are in its More sheet. */
export const BOTTOM: NavItem[] = PRIMARY.slice(0, 4);

export const SECTIONS: NavSection[] = [
  {
    title: "Work",
    items: [
      { label: "Approvals", to: "/approvals", hint: "Closures and merges waiting for a person to decide" },
      { label: "Rule tuning", to: "/tuning", hint: "Weekly suggestions to make noisy rules quieter" },
      { label: "Account look-up", to: "/account-lookup", hint: "Who an account belongs to: the name, the kind of account and the department", directory: true },
    ],
  },
  {
    title: "ARGUS",
    items: [
      { label: "ARGUS quality", to: "/quality", search: { tab: "metrics" }, hint: "How often ARGUS is right: its results and the gold set" },
      { label: "System health", to: "/health", hint: "Is data arriving; any gaps" },
    ],
  },
  {
    title: "Administration",
    items: [
      { label: "Settings", to: "/settings", hint: "Change how ARGUS works: the SIEM, Kibana, outside lookups, notices and more", admin: true },
      { label: "Users and roles", to: "/users", hint: "Who may sign in to ARGUS and what they may do", admin: true },
      { label: "AI and agents", to: "/ai", hint: "The AI providers, their keys and spending limits, and the agents that use them", admin: true },
      { label: "Threat intel", to: "/threat-intel", hint: "VirusTotal, Shodan and Censys: their keys, limits and lookups", admin: true },
    ],
  },
  {
    title: "More",
    folded: true,
    items: [
      { label: "Patterns", to: "/patterns", hint: "Groups of alike alert groups to review at once" },
      { label: "Proposals", to: "/proposals", hint: "Outcomes ARGUS proposes, to confirm" },
      { label: "Costs and usage", to: "/costs", hint: "What the AI costs and the threat-intel lookups, against their limits: the Costs board of the dashboards", admin: true },
      { label: "Design system", to: "/design", hint: "The app's colours, components and safety checks", admin: true },
      { label: "Help & glossary", to: "/glossary", hint: "What every word means" },
    ],
  },
];

/** Every page outside the daily ones, whatever its section. */
export const MORE: NavItem[] = SECTIONS.flatMap((s) => s.items);

export const ACCOUNT: NavItem[] = [
  { label: "Your access", href: "/access", hint: "What you may do in ARGUS, why, and how fresh that is" },
];

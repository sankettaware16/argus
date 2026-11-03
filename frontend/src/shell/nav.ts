/** The shell's sections (plan §5 Q-B1): Home · Review · Cases · Browse · AI & reports · System.
 * Every page is in /app (Q-B4); the two entries with an `href` open a server-rendered page
 * ("Your access" and the read-only classic pages). */
export interface NavItem {
  label: string;
  /** a path inside /app (to), with the search that picks the entry, or a classic page (href) */
  to?: string;
  search?: Record<string, string>;
  href?: string;
  /** the small word after an `href` entry (default "classic"); null for none */
  tag?: string | null;
  hint: string;
}

export interface NavGroup {
  label: string;
  items: NavItem[];
}

export const NAV: NavGroup[] = [
  {
    label: "Home",
    items: [
      { label: "Home", to: "/", hint: "What needs a person today, in order: ARGUS's cases, the patterns to close, single investigations" },
      { label: "Dashboard", to: "/dashboard", hint: "Alerts, investigations and incidents at a glance" },
    ],
  },
  {
    label: "Review",
    items: [
      { label: "Needs attention", to: "/inbox", search: { view: "attention" }, hint: "Follow-ups, changed and severe investigations" },
      { label: "Not reviewed", to: "/inbox", search: { view: "open" }, hint: "Everything nobody has reviewed yet" },
      { label: "Reviewed", to: "/inbox", search: { view: "reviewed" }, hint: "Investigations already decided" },
      { label: "All", to: "/inbox", search: { view: "all" }, hint: "Every investigation" },
      { label: "Notified, still active", to: "/inbox", search: { view: "known" }, hint: "Investigations of devices whose owner was told: counted, not raised" },
    ],
  },
  {
    label: "Cases",
    items: [
      { label: "Open cases", to: "/cases", search: { view: "active" }, hint: "Confirmed cases that are open, assigned or contained" },
      { label: "Notified cases", to: "/cases", search: { view: "notified" }, hint: "Cases whose owner was told: tracked quietly, back in the queue only when something changes" },
      { label: "My cases", to: "/cases", search: { view: "mine" }, hint: "Cases you own" },
      { label: "Approvals", to: "/approvals", hint: "Closures and merges waiting for a person to decide" },
    ],
  },
  {
    label: "Browse",
    items: [
      { label: "By rule", to: "/rules", hint: "Investigations per detection rule" },
      { label: "By host or IP", to: "/hosts", hint: "Investigations per host, IP, domain or user" },
      { label: "Patterns", to: "/patterns", hint: "Groups of alike investigations to review at once" },
    ],
  },
  {
    label: "AI & reports",
    items: [
      { label: "Proposals", to: "/proposals", hint: "Outcomes ARGUS proposes, to confirm" },
      { label: "Reports", to: "/reports", hint: "The daily and weekly reports: what waits, what happened, what went wrong" },
      { label: "Tuning", to: "/tuning", hint: "Weekly suggestions to make noisy rules quieter" },
      { label: "Metrics", to: "/metrics", hint: "How the AI is doing: results, waiting work, cost" },
      { label: "Gold set", to: "/gold", hint: "The answer key that measures how often ARGUS is right" },
    ],
  },
  {
    label: "System",
    items: [
      { label: "Health", to: "/health", hint: "Is data arriving; any gaps" },
      { label: "Glossary", to: "/glossary", hint: "What every word and page means" },
      { label: "Design system", to: "/design", hint: "The app's colours, components and safety checks" },
    ],
  },
  {
    label: "Account",
    items: [
      { label: "Your access", href: "/access", tag: "server page", hint: "What you may do in ARGUS, why, and how fresh that is" },
      { label: "Classic pages (read-only)", href: "/classic", tag: null, hint: "The pages ARGUS had before this app, kept for now as a read-only fallback" },
    ],
  },
];

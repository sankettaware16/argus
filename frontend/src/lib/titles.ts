/** The page title for an app path (without the /app base): "Dashboard · ARGUS" and the rest. Pure. */
const TITLES: Record<string, string> = {
  "/": "Today",
  "/incidents": "Incidents",
  "/search": "Search",
  "/overview": "Overview",
  "/quality": "ARGUS quality",
  "/design": "Design system",
  "/settings": "Settings",
  "/ai": "AI and agents",
  "/threat-intel": "Threat intel",
  "/costs": "Costs and usage",
  "/users": "Users and roles",
  "/setup": "First-time setup",
  "/confirmed": "Password confirmed",
  "/dashboard": "Dashboard",
  "/inbox": "Inbox",
  "/proposals": "Proposals",
  "/cases": "Cases",
  "/approvals": "Approvals",
  "/reports": "Reports",
  "/rules": "By rule",
  "/hosts": "By host or IP",
  "/patterns": "Patterns",
  "/health": "Health",
  "/glossary": "Glossary",
  "/metrics": "Metrics",
  "/tuning": "Rule tuning",
  "/gold": "Gold set",
};

export function titleFor(path: string): string {
  const clean = path.replace(/\/+$/, "") || "/";
  if (/^\/investigations\/[^/]+$/.test(clean)) return "Alert group";
  if (/^\/alert-groups\/[^/]+$/.test(clean)) return "Alert group";
  if (/^\/incidents\/(n\/)?[^/]+$/.test(clean)) return "Incident";
  if (/^\/entities\/[^/]+\/[^/]+$/.test(clean)) return "Entity";
  if (/^\/cases\/[^/]+$/.test(clean)) return "Case";
  if (/^\/reports\/[^/]+$/.test(clean)) return "Report";
  return TITLES[clean] ?? "Not found";
}

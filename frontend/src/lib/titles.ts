/** The page title for an app path (without the /app base): "Dashboard · ARGUS" and the rest. Pure. */
const TITLES: Record<string, string> = {
  "/": "Home",
  "/design": "Design system",
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
  if (/^\/investigations\/[^/]+$/.test(clean)) return "Investigation";
  if (/^\/cases\/[^/]+$/.test(clean)) return "Case";
  if (/^\/reports\/[^/]+$/.test(clean)) return "Report";
  return TITLES[clean] ?? "Not found";
}

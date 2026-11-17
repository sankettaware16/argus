import { createRootRoute, createRoute, createRouter, redirect, type RouterHistory } from "@tanstack/react-router";
import { lazy, Suspense, type ComponentType } from "react";
import { Loading } from "./components/Problem";
import { isStale, reloadOnce } from "./lib/build";
import { parseCases } from "./lib/cases";
import { parseFilters, toSearch } from "./lib/dashboardFilters";
import { parseInbox, TABS, type InboxSearch, type Tab } from "./lib/inboxQuery";
import { parseSearchPage, type SearchSearch } from "./lib/searchPage";
import { QualityPage } from "./pages/Quality";
import { parseIncidents, viewForOldCases } from "./lib/incidents";
import { isIncidentTab, tabForAnchor, type IncidentTab } from "./lib/incidentTabs";
import { first, parseSearch, stringifySearch } from "./lib/search";
import { titleFor } from "./lib/titles";
import { Failed } from "./pages/Failed";
import { TodayOrHome } from "./pages/Today";
import { NotFound } from "./pages/NotFound";
import { AppShell } from "./shell/AppShell";

const BASE = "/app";

// Lazy pages through React.lazy (not the router's lazyRouteComponent, which reloads by itself on
// a missing chunk): the stale-build check (lib/build.ts) is the one place that reloads.
const DesignPage = lazy(() => import("./pages/Design").then((m) => ({ default: m.Design })));
const DashboardPage = lazy(() => import("./pages/Dashboard").then((m) => ({ default: m.Dashboard })));
const InboxPage = lazy(() => import("./pages/Inbox").then((m) => ({ default: m.Inbox })));
const ProposalsPage = lazy(() => import("./pages/Proposals").then((m) => ({ default: m.Proposals })));
const IncidentsPage = lazy(() => import("./pages/Incidents").then((m) => ({ default: m.Incidents })));
const IncidentRoutePage = lazy(() => import("./pages/IncidentPage").then((m) => ({ default: m.IncidentRoute })));
const ApprovalsPage = lazy(() => import("./pages/Approvals").then((m) => ({ default: m.Approvals })));
const ReportsPage = lazy(() => import("./pages/Reports").then((m) => ({ default: m.Reports })));
const ReportDetailPage = lazy(() => import("./pages/Reports").then((m) => ({ default: m.ReportPage })));
const EntityPageLazy = lazy(() => import("./pages/Entity").then((m) => ({ default: m.EntityPage })));
const SearchPageLazy = lazy(() => import("./pages/Search").then((m) => ({ default: m.SearchPage })));
const PatternsPage = lazy(() => import("./pages/Patterns").then((m) => ({ default: m.Patterns })));
const HealthPage = lazy(() => import("./pages/System").then((m) => ({ default: m.Health })));
const GlossaryPage = lazy(() => import("./pages/System").then((m) => ({ default: m.Glossary })));
const MetricsPage = lazy(() => import("./pages/System").then((m) => ({ default: m.Metrics })));
const TuningPage = lazy(() => import("./pages/Tuning").then((m) => ({ default: m.Tuning })));
const GoldPage = lazy(() => import("./pages/Gold").then((m) => ({ default: m.Gold })));
const SettingsPage = lazy(() => import("./pages/Settings").then((m) => ({ default: m.Settings })));
const AiAgentsPage = lazy(() => import("./pages/AiAgents").then((m) => ({ default: m.AiAgents })));
const ThreatIntelPage = lazy(() => import("./pages/ThreatIntel").then((m) => ({ default: m.ThreatIntel })));
const CostsPage = lazy(() => import("./pages/Costs").then((m) => ({ default: m.Costs })));
const UsersPage = lazy(() => import("./pages/Users").then((m) => ({ default: m.Users })));
const ConfirmedPage = lazy(() => import("./pages/Confirmed").then((m) => ({ default: m.Confirmed })));
const SetupPage = lazy(() => import("./pages/Setup").then((m) => ({ default: m.Setup })));
const InvestigationPageLazy = lazy(() => import("./pages/InvestigationPage").then((m) => ({ default: m.InvestigationPage })));

const root = createRootRoute({ component: AppShell, notFoundComponent: NotFound, errorComponent: Failed });
const home = createRoute({ getParentRoute: () => root, path: "/", component: TodayOrHome });
const design = createRoute({
  getParentRoute: () => root,
  path: "/design",
  component: () => (
    <Suspense fallback={<Loading what="the page" />}>
      <DesignPage />
    </Suspense>
  ),
  errorComponent: Failed,
});
function admin<P extends string>(path: P, what: string, Page: ComponentType) {
  return createRoute({
    getParentRoute: () => root,
    path,
    component: () => (
      <Suspense fallback={<Loading what={what} />}>
        <Page />
      </Suspense>
    ),
    errorComponent: Failed,
  });
}
const settings = createRoute({
  getParentRoute: () => root,
  path: "/settings",
  validateSearch: (raw: Record<string, unknown>): { section?: string } => {
    const section = first(raw.section);
    return section !== undefined && /^[a-z_]{1,40}$/.test(section) ? { section } : {};
  },
  component: function SettingsRoute() {
    const { section } = settings.useSearch();
    return (
      <Suspense fallback={<Loading what="the settings" />}>
        <SettingsPage section={section} />
      </Suspense>
    );
  },
  errorComponent: Failed,
});
const aiAgents = admin("/ai", "the AI settings", AiAgentsPage);
const threatIntel = admin("/threat-intel", "the threat-intel sources", ThreatIntelPage);
const costs = admin("/costs", "the costs", CostsPage);
const users = admin("/users", "the people", UsersPage);
const setup = admin("/setup", "the setup", SetupPage);
const confirmed = admin("/confirmed", "the page", ConfirmedPage);
// the old addresses (docs/p4f-ui-spec.md §4.3): redirected, so saved links keep working
const dashboard = createRoute({
  getParentRoute: () => root,
  path: "/dashboard",
  validateSearch: (raw: Record<string, unknown>) => toSearch(parseFilters(raw)),
  beforeLoad: ({ search }) => {
    throw redirect({ to: "/overview", search, replace: true });
  },
});
const overview = createRoute({
  getParentRoute: () => root,
  path: "/overview",
  validateSearch: (raw: Record<string, unknown>) => toSearch(parseFilters(raw)),
  component: function OverviewRoute() {
    const search = overview.useSearch();
    return (
      <Suspense fallback={<Loading what="the dashboard" />}>
        <DashboardPage search={search} />
      </Suspense>
    );
  },
  errorComponent: Failed,
});
const inbox = createRoute({
  getParentRoute: () => root,
  path: "/inbox",
  validateSearch: parseInbox,
  beforeLoad: ({ search }) => {
    throw redirect({ to: "/search", search: { advanced: "1", ...search }, replace: true });
  },
});
const search = createRoute({
  getParentRoute: () => root,
  path: "/search",
  validateSearch: (raw: Record<string, unknown>): SearchSearch => (first(raw.advanced) === "1" ? { ...parseInbox(raw), advanced: "1" } : parseSearchPage(raw)),
  component: function SearchRoute() {
    const s = search.useSearch();
    return (
      <Suspense fallback={<Loading what="the search" />}>
        {s.advanced === "1" ? <InboxPage search={s as InboxSearch} /> : <SearchPageLazy search={s} />}
      </Suspense>
    );
  },
  errorComponent: Failed,
});
const investigation = createRoute({
  getParentRoute: () => root,
  path: "/investigations/$id",
  validateSearch: (raw: Record<string, unknown>): { tab?: Tab } => {
    const tab = first(raw.tab);
    return tab !== undefined && (TABS as readonly string[]).includes(tab) ? { tab: tab as Tab } : {};
  },
  beforeLoad: ({ params, search }) => {
    throw redirect({ to: "/alert-groups/$id", params: { id: params.id }, search, replace: true });
  },
});
const alertGroup = createRoute({
  getParentRoute: () => root,
  path: "/alert-groups/$id",
  validateSearch: (raw: Record<string, unknown>): { tab?: Tab } => {
    const tab = first(raw.tab);
    return tab !== undefined && (TABS as readonly string[]).includes(tab) ? { tab: tab as Tab } : {};
  },
  component: function AlertGroupRoute() {
    const { id } = alertGroup.useParams();
    const { tab } = alertGroup.useSearch();
    return (
      <Suspense fallback={<Loading what="the alert group" />}>
        <InvestigationPageLazy id={id} tab={tab ?? "overview"} />
      </Suspense>
    );
  },
  errorComponent: Failed,
});
const cases = createRoute({
  getParentRoute: () => root,
  path: "/cases",
  validateSearch: parseCases,
  beforeLoad: ({ search }) => {
    throw redirect({ to: "/incidents", search: { view: viewForOldCases(search.view), ...(search.q ? { q: search.q } : {}) }, replace: true });
  },
});
// the old case page's address: the incident page, its #section anchor mapped to a tab (§4.3)
const caseDetail = createRoute({
  getParentRoute: () => root,
  path: "/cases/$id",
  beforeLoad: ({ params, location }) => {
    const tab = tabForAnchor(location.hash);
    throw redirect({ to: "/incidents/$id", params: { id: params.id }, search: tab === "overview" ? {} : { tab }, replace: true });
  },
});
const incidentDetail = createRoute({
  getParentRoute: () => root,
  path: "/incidents/$id",
  validateSearch: (raw: Record<string, unknown>): { tab?: IncidentTab } => {
    const tab = first(raw.tab);
    return isIncidentTab(tab) && tab !== "overview" ? { tab } : {};
  },
  component: function IncidentDetailRoute() {
    const { id } = incidentDetail.useParams();
    const { tab } = incidentDetail.useSearch();
    return (
      <Suspense fallback={<Loading what="the incident" />}>
        <IncidentRoutePage id={id} tab={tab} />
      </Suspense>
    );
  },
  errorComponent: Failed,
});
const incidents = createRoute({
  getParentRoute: () => root,
  path: "/incidents",
  validateSearch: parseIncidents,
  component: function IncidentsRoute() {
    const search = incidents.useSearch();
    return (
      <Suspense fallback={<Loading what="the incidents" />}>
        <IncidentsPage search={search} />
      </Suspense>
    );
  },
  errorComponent: Failed,
});
const approvals = createRoute({
  getParentRoute: () => root,
  path: "/approvals",
  component: () => (
    <Suspense fallback={<Loading what="the approvals" />}>
      <ApprovalsPage />
    </Suspense>
  ),
  errorComponent: Failed,
});
const reports = createRoute({
  getParentRoute: () => root,
  path: "/reports",
  component: () => (
    <Suspense fallback={<Loading what="the reports" />}>
      <ReportsPage />
    </Suspense>
  ),
  errorComponent: Failed,
});
const reportDetail = createRoute({
  getParentRoute: () => root,
  path: "/reports/$id",
  component: function ReportRoute() {
    const { id } = reportDetail.useParams();
    return (
      <Suspense fallback={<Loading what="the report" />}>
        <ReportDetailPage id={id} />
      </Suspense>
    );
  },
  errorComponent: Failed,
});
const proposals = createRoute({
  getParentRoute: () => root,
  path: "/proposals",
  component: () => (
    <Suspense fallback={<Loading what="the proposals" />}>
      <ProposalsPage />
    </Suspense>
  ),
  errorComponent: Failed,
});

/** A page with nothing in its address (the browse and system pages): lazy, with its loading words. */
function plain<P extends string>(path: P, what: string, Page: ComponentType) {
  return createRoute({
    getParentRoute: () => root,
    path,
    component: () => (
      <Suspense fallback={<Loading what={what} />}>
        <Page />
      </Suspense>
    ),
    errorComponent: Failed,
  });
}
function toAdvanced<P extends string>(path: P) {
  return createRoute({
    getParentRoute: () => root,
    path,
    beforeLoad: () => {
      throw redirect({ to: "/search", search: { advanced: "1", view: "attention" }, replace: true });
    },
  });
}
const rules = toAdvanced("/rules");
const hosts = toAdvanced("/hosts");
const patterns = plain("/patterns", "the patterns", PatternsPage);
const health = plain("/health", "the health", HealthPage);
const glossary = plain("/glossary", "the glossary", GlossaryPage);
const metrics = createRoute({
  getParentRoute: () => root,
  path: "/metrics",
  beforeLoad: () => {
    throw redirect({ to: "/quality", search: { tab: "metrics" }, replace: true });
  },
});
const tuning = plain("/tuning", "the tuning reports", TuningPage);
const gold = createRoute({
  getParentRoute: () => root,
  path: "/gold",
  beforeLoad: () => {
    throw redirect({ to: "/quality", search: { tab: "gold" }, replace: true });
  },
});
const ENTITY_KINDS = ["device", "account", "site", "outside"] as const;
const entity = createRoute({
  getParentRoute: () => root,
  path: "/entities/$kind/$value",
  component: function EntityRoute() {
    const { kind, value } = entity.useParams();
    const known = ENTITY_KINDS.find((k) => k === kind);
    if (known === undefined) return <NotFound />;
    return (
      <Suspense fallback={<Loading what="the page" />}>
        <EntityPageLazy kind={known} value={value} />
      </Suspense>
    );
  },
  errorComponent: Failed,
});
const quality = createRoute({
  getParentRoute: () => root,
  path: "/quality",
  validateSearch: (raw: Record<string, unknown>): { tab: "metrics" | "gold" } => ({ tab: first(raw.tab) === "gold" ? "gold" : "metrics" }),
  component: function QualityRoute() {
    const { tab } = quality.useSearch();
    return (
      <Suspense fallback={<Loading what="ARGUS quality" />}>
        <QualityPage tab={tab} Metrics={MetricsPage} Gold={GoldPage} />
      </Suspense>
    );
  },
  errorComponent: Failed,
});

/** The app's router; tests give it a memory history. */
export function createAppRouter(history?: RouterHistory) {
  const made = createRouter({
    routeTree: root.addChildren([home, design, confirmed, settings, aiAgents, threatIntel, costs, users, setup, dashboard, overview, inbox, search, investigation, alertGroup, proposals, cases, caseDetail, incidents, incidentDetail, approvals, reports, reportDetail, rules, hosts, patterns, health, glossary, metrics, tuning, gold, quality, entity]),
    basepath: BASE,
    defaultPreload: false,
    scrollRestoration: false,
    parseSearch,
    stringifySearch,
    history,
  });
  // The stale-build check: a navigation inside a stale page loads its target afresh, once.
  made.subscribe("onBeforeNavigate", ({ toLocation, pathChanged }) => {
    if (pathChanged && isStale()) {
      reloadOnce(appHref(toLocation.href));
    }
  });
  // Each page has its title; after a navigation to another page of the app the focus moves to
  // the page's content, so a screen reader starts reading the new page (the first load keeps the
  // browser's). Choosing an investigation in the Inbox keeps the focus where the person put it.
  let firstLoad = true;
  let lastPath = "";
  made.subscribe("onResolved", ({ toLocation }) => {
    const path = toLocation.pathname.replace(/^\/app(?=\/|$)/, "") || "/";
    document.title = `${titleFor(path)} · ARGUS`;
    if (!firstLoad && path !== lastPath) document.getElementById("main")?.focus();
    firstLoad = false;
    lastPath = path;
  });
  return made;
}

export const router = createAppRouter();

/** The address of an app location (the router's href is without its basepath). */
export function appHref(href: string): string {
  return BASE + (href.startsWith("/") ? href : `/${href}`);
}

declare module "@tanstack/react-router" {
  interface Register {
    router: ReturnType<typeof createAppRouter>;
  }
}

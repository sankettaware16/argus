import { createRootRoute, createRoute, createRouter, type RouterHistory } from "@tanstack/react-router";
import { lazy, Suspense, type ComponentType } from "react";
import { Loading } from "./components/Problem";
import { isStale, reloadOnce } from "./lib/build";
import { parseCases } from "./lib/cases";
import { parseFilters, toSearch } from "./lib/dashboardFilters";
import { parseInbox, TABS, type Tab } from "./lib/inboxQuery";
import { first, parseSearch, stringifySearch } from "./lib/search";
import { titleFor } from "./lib/titles";
import { Failed } from "./pages/Failed";
import { Home } from "./pages/Home";
import { NotFound } from "./pages/NotFound";
import { AppShell } from "./shell/AppShell";

const BASE = "/app";

// Lazy pages through React.lazy (not the router's lazyRouteComponent, which reloads by itself on
// a missing chunk): the stale-build check (lib/build.ts) is the one place that reloads.
const DesignPage = lazy(() => import("./pages/Design").then((m) => ({ default: m.Design })));
const DashboardPage = lazy(() => import("./pages/Dashboard").then((m) => ({ default: m.Dashboard })));
const InboxPage = lazy(() => import("./pages/Inbox").then((m) => ({ default: m.Inbox })));
const ProposalsPage = lazy(() => import("./pages/Proposals").then((m) => ({ default: m.Proposals })));
const CasesPage = lazy(() => import("./pages/Cases").then((m) => ({ default: m.Cases })));
const CaseDetailPage = lazy(() => import("./pages/CasePage").then((m) => ({ default: m.CasePage })));
const ApprovalsPage = lazy(() => import("./pages/Approvals").then((m) => ({ default: m.Approvals })));
const ReportsPage = lazy(() => import("./pages/Reports").then((m) => ({ default: m.Reports })));
const ReportDetailPage = lazy(() => import("./pages/Reports").then((m) => ({ default: m.ReportPage })));
const RulesPage = lazy(() => import("./pages/Browse").then((m) => ({ default: m.Rules })));
const HostsPage = lazy(() => import("./pages/Browse").then((m) => ({ default: m.Hosts })));
const PatternsPage = lazy(() => import("./pages/Patterns").then((m) => ({ default: m.Patterns })));
const HealthPage = lazy(() => import("./pages/System").then((m) => ({ default: m.Health })));
const GlossaryPage = lazy(() => import("./pages/System").then((m) => ({ default: m.Glossary })));
const MetricsPage = lazy(() => import("./pages/System").then((m) => ({ default: m.Metrics })));
const TuningPage = lazy(() => import("./pages/Tuning").then((m) => ({ default: m.Tuning })));
const GoldPage = lazy(() => import("./pages/Gold").then((m) => ({ default: m.Gold })));
const InvestigationPageLazy = lazy(() => import("./pages/InvestigationPage").then((m) => ({ default: m.InvestigationPage })));

const root = createRootRoute({ component: AppShell, notFoundComponent: NotFound, errorComponent: Failed });
const home = createRoute({ getParentRoute: () => root, path: "/", component: Home });
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
const dashboard = createRoute({
  getParentRoute: () => root,
  path: "/dashboard",
  validateSearch: (raw: Record<string, unknown>) => toSearch(parseFilters(raw)),
  component: function DashboardRoute() {
    const search = dashboard.useSearch();
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
  component: function InboxRoute() {
    const search = inbox.useSearch();
    return (
      <Suspense fallback={<Loading what="the Inbox" />}>
        <InboxPage search={search} />
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
  component: function InvestigationRoute() {
    const { id } = investigation.useParams();
    const { tab } = investigation.useSearch();
    return (
      <Suspense fallback={<Loading what="the investigation" />}>
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
  component: function CasesRoute() {
    const search = cases.useSearch();
    return (
      <Suspense fallback={<Loading what="the cases" />}>
        <CasesPage search={search} />
      </Suspense>
    );
  },
  errorComponent: Failed,
});
const caseDetail = createRoute({
  getParentRoute: () => root,
  path: "/cases/$id",
  component: function CaseRoute() {
    const { id } = caseDetail.useParams();
    return (
      <Suspense fallback={<Loading what="the case" />}>
        <CaseDetailPage id={id} />
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
const rules = plain("/rules", "the rules", RulesPage);
const hosts = plain("/hosts", "the hosts and addresses", HostsPage);
const patterns = plain("/patterns", "the patterns", PatternsPage);
const health = plain("/health", "the health", HealthPage);
const glossary = plain("/glossary", "the glossary", GlossaryPage);
const metrics = plain("/metrics", "the metrics", MetricsPage);
const tuning = plain("/tuning", "the tuning reports", TuningPage);
const gold = plain("/gold", "the gold set", GoldPage);

/** The app's router; tests give it a memory history. */
export function createAppRouter(history?: RouterHistory) {
  const made = createRouter({
    routeTree: root.addChildren([home, design, dashboard, inbox, investigation, proposals, cases, caseDetail, approvals, reports, reportDetail, rules, hosts, patterns, health, glossary, metrics, tuning, gold]),
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

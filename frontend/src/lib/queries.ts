/**
 * What the pages read (TanStack Query over the generated client). Every read goes through
 * `unwrap`, so a failure is an ApiError in plain words; nothing is retried (lib/session.ts sets
 * the client's defaults). A change invalidates what it touched (`changed`).
 */
import { infiniteQueryOptions, queryOptions, type QueryClient } from "@tanstack/react-query";
import {
  getCase,
  getCaseReport,
  getCaseTeam,
  getCounts,
  getDashboard,
  getGlossary,
  getGoldSet,
  getHealth,
  getInvestigation,
  getMetrics,
  getPatternSummary,
  getQueue,
  getReport,
  getReports,
  getSince,
  getThreatLists,
  listAlerts,
  listApprovals,
  listCases,
  listChecks,
  listEntities,
  listEntityNotes,
  listInvestigations,
  listPatterns,
  listProposals,
  listReports,
  listRules,
  listTuning,
  previewClosure,
  previewMerge,
} from "../client/sdk.gen";
import type { PreviewClosureData } from "../client/types.gen";
import { BACKGROUND } from "./api";
import { casesQuery, type CasesSearch } from "./cases";
import { toQuery, type Filters } from "./dashboardFilters";
import { listQuery, type InboxSearch } from "./inboxQuery";
import { unwrap } from "./call";

export const PAGE = 100; // the API's page size
export const DEEPEST = 10_000; // the deepest offset the API serves

export const countsQuery = queryOptions({
  queryKey: ["counts"],
  queryFn: () => unwrap(getCounts()),
  staleTime: 15_000,
});

/** What needs a person, in order (AR4): ARGUS's cases, then the single investigations, and the order Next walks. */
export const queueOptions = queryOptions({
  queryKey: ["queue"],
  queryFn: () => unwrap(getQueue()),
  staleTime: 15_000,
});

export function listOptions(search: InboxSearch) {
  const q = listQuery(search);
  return infiniteQueryOptions({
    queryKey: ["investigations", q],
    queryFn: ({ pageParam }) => unwrap(listInvestigations({ query: { ...q, offset: pageParam, limit: PAGE } })),
    initialPageParam: 0,
    getNextPageParam: (last, _all, offset) => (last.has_more && offset + PAGE <= DEEPEST ? offset + PAGE : undefined),
    staleTime: 15_000,
  });
}

export function investigationOptions(id: string) {
  return queryOptions({
    queryKey: ["investigation", id],
    queryFn: () => unwrap(getInvestigation({ path: { investigation_id: id } })),
    staleTime: 15_000,
  });
}

/** The same read as a background poll (it never keeps the session alive): while a request to the AI investigator waits. */
export function pollInvestigation(id: string) {
  return unwrap(getInvestigation({ path: { investigation_id: id }, headers: BACKGROUND }));
}

export function reportsOptions(id: string) {
  return queryOptions({
    queryKey: ["reports", id],
    queryFn: () => unwrap(getReports({ path: { investigation_id: id } })),
    staleTime: 60_000,
  });
}

export function alertsOptions(id: string, columns: string[] | null) {
  return queryOptions({
    queryKey: ["alerts", id, columns],
    queryFn: () => unwrap(listAlerts({ path: { investigation_id: id }, query: columns === null ? {} : { columns: columns.join(",") } })),
    staleTime: 60_000,
  });
}

export function dashboardOptions(f: Filters) {
  return queryOptions({
    queryKey: ["dashboard", toQuery(f)],
    queryFn: () => unwrap(getDashboard({ query: toQuery(f) })),
    staleTime: 30_000,
  });
}

export function threatOptions(f: Filters) {
  return queryOptions({
    queryKey: ["threat", toQuery(f)],
    queryFn: () => unwrap(getThreatLists({ query: toQuery(f) })),
    staleTime: 60_000,
  });
}

export const sinceOptions = queryOptions({
  queryKey: ["since"],
  queryFn: () => unwrap(getSince()),
  staleTime: 5 * 60_000,
});

export const proposalsOptions = queryOptions({
  queryKey: ["proposals"],
  queryFn: () => unwrap(listProposals()),
  staleTime: 15_000,
});

export const rulesOptions = queryOptions({
  queryKey: ["rules"],
  queryFn: () => unwrap(listRules()),
  staleTime: 5 * 60_000,
});

export const entitiesOptions = queryOptions({
  queryKey: ["entities"],
  queryFn: () => unwrap(listEntities()),
  staleTime: 5 * 60_000,
});

export const patternsOptions = queryOptions({
  queryKey: ["patterns"],
  queryFn: () => unwrap(listPatterns()),
  staleTime: 15_000,
});

/** The patterns ARGUS recommends closing, for Home: real totals counted on the server, the largest few (AR4 review). */
export const patternSummaryOptions = queryOptions({
  queryKey: ["patterns", "summary"],
  queryFn: () => unwrap(getPatternSummary()),
  staleTime: 15_000,
});

/** The Health page's own read (the shell's status bar polls the same route under its own key, in the background). */
export const healthPageOptions = queryOptions({
  queryKey: ["health-page"],
  queryFn: () => unwrap(getHealth()),
  staleTime: 15_000,
});

export const glossaryOptions = queryOptions({
  queryKey: ["glossary"],
  queryFn: () => unwrap(getGlossary()),
  staleTime: 30 * 60_000,
});

export const metricsOptions = queryOptions({
  queryKey: ["metrics"],
  queryFn: () => unwrap(getMetrics()),
  staleTime: 30_000,
});

export const tuningOptions = queryOptions({
  queryKey: ["tuning"],
  queryFn: () => unwrap(listTuning()),
  staleTime: 5 * 60_000,
});

export const goldOptions = queryOptions({
  queryKey: ["gold"],
  queryFn: () => unwrap(getGoldSet()),
  staleTime: 30_000,
});

export const CASES_PAGE = 100;

export function casesOptions(search: CasesSearch) {
  const q = casesQuery(search);
  return infiniteQueryOptions({
    queryKey: ["cases", q],
    queryFn: ({ pageParam }) => unwrap(listCases({ query: { ...q, offset: pageParam, limit: CASES_PAGE } })),
    initialPageParam: 0,
    getNextPageParam: (last, _all, offset) => (last.has_more ? offset + CASES_PAGE : undefined),
    staleTime: 15_000,
  });
}

export function caseOptions(id: string) {
  return queryOptions({
    queryKey: ["case", id],
    queryFn: () => unwrap(getCase({ path: { case_id: id } })),
    staleTime: 10_000,
  });
}

/** A case's incident report (AR7): the newest version, or one asked for. */
export function caseReportOptions(id: string, version: number | null = null) {
  return queryOptions({
    queryKey: ["case-report", id, version],
    queryFn: () => unwrap(getCaseReport({ path: { case_id: id }, query: version === null ? {} : { version } })),
    staleTime: 10_000,
  });
}

/** What ARGUS would write to the case in Kibana (AR8): the dry run, always fresh. */
export function caseTeamOptions(id: string) {
  return queryOptions({
    queryKey: ["case-team", id],
    queryFn: () => unwrap(getCaseTeam({ path: { case_id: id } })),
    staleTime: 5_000,
  });
}

/** After an approval of the case's post: read the preview again. */
export async function changedTeam(queries: QueryClient, id: string): Promise<void> {
  await queries.invalidateQueries({ queryKey: ["case-team", id] });
}

/** After a decision on the report: read it and the case again. */
export async function changedReport(queries: QueryClient, id: string): Promise<void> {
  await Promise.all([queries.invalidateQueries({ queryKey: ["case-report", id] }), changedCase(queries, id)]);
}

/** The exact writes asking for this closure binds (the builder the request itself uses), at a version. */
export function closurePreviewOptions(id: string, reason: string, version: number) {
  return queryOptions({
    queryKey: ["closure-preview", id, reason, version],
    queryFn: () => unwrap(previewClosure({ path: { case_id: id }, query: { reason: reason as PreviewClosureData["query"]["reason"], expected_version: version } })),
    staleTime: 0,
    gcTime: 0,
  });
}

export function mergePreviewOptions(id: string, target: string, version: number) {
  return queryOptions({
    queryKey: ["merge-preview", id, target, version],
    queryFn: () => unwrap(previewMerge({ path: { case_id: id }, query: { target, expected_version: version } })),
    staleTime: 0,
    gcTime: 0,
  });
}

export const approvalsOptions = queryOptions({
  queryKey: ["approvals"],
  queryFn: () => unwrap(listApprovals()),
  staleTime: 10_000,
});

/** The newest 60 reports of one kind (the server filters: older weeklies are not pushed out by dailies). */
export function reportListOptions(kind: "all" | "daily" | "weekly") {
  return queryOptions({
    queryKey: ["report-list", kind],
    queryFn: () => unwrap(listReports(kind === "all" ? {} : { query: { kind } })),
    staleTime: 60_000,
  });
}

/** `id` goes into the URL as written: as a number it would lose digits above 2^53 (the API takes up to 2^62). */
export function reportDetailOptions(id: string) {
  return queryOptions({
    queryKey: ["report", id],
    queryFn: () => unwrap(getReport({ path: { report_id: id as unknown as number } })),
    staleTime: 5 * 60_000, // a report is never rewritten
  });
}

export function checksOptions(id: string) {
  return queryOptions({
    queryKey: ["checks", id],
    queryFn: () => unwrap(listChecks({ path: { investigation_id: id } })),
    staleTime: 10_000,
  });
}

/** The same read as a background poll (it never keeps the session alive): while a check waits or runs. */
export function pollChecks(id: string) {
  return unwrap(listChecks({ path: { investigation_id: id }, headers: BACKGROUND }));
}

export function entityNotesOptions(kind: "ip" | "domain" | "host" | "user", value: string) {
  return queryOptions({
    queryKey: ["entity-notes", kind, value],
    queryFn: () => unwrap(listEntityNotes({ query: { kind, value } })),
    staleTime: 15_000,
  });
}

/** After a change to a case: read again the case, the lists, the approvals queue. */
export async function changedCase(queries: QueryClient, id?: string): Promise<void> {
  await Promise.all([
    id !== undefined ? queries.invalidateQueries({ queryKey: ["case", id] }) : Promise.resolve(),
    queries.invalidateQueries({ queryKey: ["cases"] }),
    queries.invalidateQueries({ queryKey: ["cases-counts"] }),
    queries.invalidateQueries({ queryKey: ["approvals"] }),
    queries.invalidateQueries({ queryKey: ["queue"] }),
    queries.invalidateQueries({ queryKey: ["dashboard"] }),
  ]);
}

/** After a change: read again what it touched (the open investigation, the lists, the counts, proposals and the dashboard). */
export async function changed(queries: QueryClient, id?: string): Promise<void> {
  await Promise.all([
    id !== undefined ? queries.invalidateQueries({ queryKey: ["investigation", id] }) : Promise.resolve(),
    queries.invalidateQueries({ queryKey: ["investigations"] }),
    queries.invalidateQueries({ queryKey: ["counts"] }),
    queries.invalidateQueries({ queryKey: ["queue"] }),
    queries.invalidateQueries({ queryKey: ["proposals"] }),
    queries.invalidateQueries({ queryKey: ["patterns"] }),
    queries.invalidateQueries({ queryKey: ["dashboard"] }),
    queries.invalidateQueries({ queryKey: ["threat"] }),
  ]);
}

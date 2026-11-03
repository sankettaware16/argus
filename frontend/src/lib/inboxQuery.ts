/**
 * What the Inbox's address says: a view, a sort, a rule or a host/IP/domain/user to find, the
 * investigation open in the right pane, and the tab shown there. Anything invalid is left out,
 * never an error. Pure (tests/inboxQuery.test.ts).
 */
import { first } from "./search";

export const VIEWS = ["attention", "open", "reviewed", "all", "known"] as const;
export const SORTS = ["newest", "oldest", "urgent", "reviewed", "queue"] as const;
export const TABS = ["overview", "report", "ai", "checked", "alerts", "history"] as const;
export const KINDS = ["ip", "host", "domain", "user"] as const;
export type View = (typeof VIEWS)[number];
export type Sort = (typeof SORTS)[number];
export type Tab = (typeof TABS)[number];
export type Kind = (typeof KINDS)[number];

export interface InboxSearch {
  view: View;
  sort?: Sort;
  rule?: string;
  kind?: Kind;
  value?: string;
  id?: string;
  tab?: Tab;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const KIND_LIST: readonly string[] = KINDS;
const SORT_LIST: readonly string[] = SORTS;
const VIEW_LIST: readonly string[] = VIEWS;
const TAB_LIST: readonly string[] = TABS;

export function parseInbox(raw: Record<string, unknown>): InboxSearch {
  const view = first(raw.view);
  const sort = first(raw.sort);
  const rule = first(raw.rule);
  const kind = first(raw.kind);
  const value = first(raw.value);
  const id = first(raw.id);
  const tab = first(raw.tab);
  const entity = kind !== undefined && KIND_LIST.includes(kind) && value !== undefined && value !== "" && value.length <= 300 && !value.includes("\u0000");
  const out: InboxSearch = { view: view !== undefined && VIEW_LIST.includes(view) ? (view as View) : "attention" };
  if (sort !== undefined && SORT_LIST.includes(sort)) out.sort = sort as Sort;
  if (rule !== undefined && rule !== "" && rule.length <= 200 && !rule.includes("\u0000")) out.rule = rule;
  if (entity) {
    out.kind = kind as Kind;
    out.value = value;
  }
  if (id !== undefined && UUID.test(id)) out.id = id;
  if (tab !== undefined && TAB_LIST.includes(tab)) out.tab = tab as Tab;
  return out;
}

/** The sort the list is really in: the reviewed view by decision, everything else newest first (D-095). */
export function effectiveSort(s: Pick<InboxSearch, "view" | "sort">): Sort {
  return s.sort ?? (s.view === "reviewed" ? "reviewed" : "newest");
}

/** The list's query for the API (the reviewed sort belongs to the reviewed view only). */
export function listQuery(s: InboxSearch): { view: View; sort: Sort; rule?: string; kind?: Kind; value?: string } {
  const sort = effectiveSort(s);
  return {
    view: s.view,
    sort: sort === "reviewed" && s.view !== "reviewed" ? "newest" : sort,
    ...(s.rule !== undefined ? { rule: s.rule } : {}),
    ...(s.kind !== undefined && s.value !== undefined ? { kind: s.kind, value: s.value } : {}),
  };
}

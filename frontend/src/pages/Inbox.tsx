import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { Link, useNavigate } from "@tanstack/react-router";
import { useCallback, useEffect, useId, useMemo, useRef, useState, type KeyboardEvent } from "react";
import type { InvestigationOut } from "../client/types.gen";
import { InboxList } from "../components/InboxList";
import { InvestigationView } from "../components/investigation/InvestigationView";
import { KeysHelp } from "../components/KeysHelp";
import { Loading, Problem } from "../components/Problem";
import { UntrustedText } from "../components/UntrustedText";
import { Button } from "../components/ui/button";
import { Check, Field, Select, TextInput } from "../components/ui/field";
import { count } from "../lib/format";
import { validateFind } from "../lib/inboxSearch";
import { effectiveSort, type InboxSearch, type Tab, VIEWS } from "../lib/inboxQuery";
import { KIND_TITLES, SORT_TITLES, VIEW_TITLES } from "../lib/labels";
import { optionText } from "../lib/optionText";
import { countsQuery, DEEPEST, listOptions, PAGE, rulesOptions } from "../lib/queries";
import { useSession } from "../lib/session";
import { browserStorage, loadShortcuts, saveShortcuts } from "../lib/shortcuts";
import { useWide } from "../lib/viewport";

const FOLLOW_MS = 120; // the right pane follows the cursor once it rests this long

/** The views with their counts (the old Inbox's summary strip), each a link. */
function Views({ search }: { search: InboxSearch }) {
  const counts = useQuery(countsQuery);
  const number = (view: (typeof VIEWS)[number]): string => {
    const c = counts.data;
    if (!c) return "";
    return count(view === "attention" ? c.attention : view === "known" ? c.known : view === "open" ? c.open : view === "reviewed" ? c.reviewed : c.all);
  };
  return (
    <div className="flex flex-col gap-1">
      <nav aria-label="Views" className="flex flex-wrap gap-1">
        {VIEWS.map((view) => (
          <Link
            key={view}
            to="/search"
            search={{ advanced: "1", view }}
            aria-current={search.view === view ? "page" : undefined}
            className="inline-flex min-h-8 items-center gap-1 rounded-control px-2 text-sm text-text no-underline hover:bg-surface-3 aria-[current=page]:bg-accent-soft aria-[current=page]:font-semibold"
          >
            {VIEW_TITLES[view]}
            <span className="text-xs text-muted tabular-nums">{number(view)}</span>
          </Link>
        ))}
      </nav>
      {search.view === "known" && (
        <p className="m-0 px-2 text-sm text-muted">
          Investigations of devices whose owner was told (a notified case). ARGUS counts their alerts and keeps them out of Needs attention; one comes back there, with its reason, only when something changed since the notice. Each shows its case.
        </p>
      )}
      {counts.data && (
        <p className="m-0 px-2 text-xs text-muted">
          {count(counts.data.follow_up)} follow-ups · {count(counts.data.changed)} changed since review · {count(counts.data.reviewed_today)} reviewed in 24 h
        </p>
      )}
    </div>
  );
}

function FindAndSort({ search }: { search: InboxSearch }) {
  const navigate = useNavigate({ from: "/search" });
  const id = useId();
  const rules = useQuery(rulesOptions);
  const [kind, setKind] = useState<string>(search.kind ?? "ip");
  const [value, setValue] = useState(search.value ?? "");
  const [problem, setProblem] = useState<string | null>(null);
  // the boxes follow the address when it changes under them (Clear, a link, Back), never while it does not (review B2-R7)
  const [shown, setShown] = useState({ kind: search.kind, value: search.value });
  if (shown.kind !== search.kind || shown.value !== search.value) {
    setShown({ kind: search.kind, value: search.value });
    setKind(search.kind ?? "ip");
    setValue(search.value ?? "");
    setProblem(null);
  }
  const active = search.rule !== undefined || search.kind !== undefined || search.sort !== undefined;
  const go = (patch: Partial<InboxSearch>) =>
    void navigate({ search: (prev) => ({ ...prev, ...patch, id: undefined }) });
  return (
    <details open={active} className="rounded-card border border-border bg-surface px-3 py-2">
      <summary className="cursor-pointer text-sm font-medium">Find, filter and sort</summary>
      <div className="mt-2 flex flex-col gap-3">
        <form
          className="flex flex-col gap-2"
          aria-label="Find a host, address, domain or user"
          onSubmit={(e) => {
            e.preventDefault();
            const found = validateFind(kind, value);
            if (!found.ok) {
              setProblem(found.why);
              return;
            }
            setProblem(null);
            setValue(found.value);
            go({ view: "all", kind: found.kind, value: found.value, rule: undefined });
          }}
        >
          <div className="flex flex-wrap items-end gap-2">
            <Field label="Find" htmlFor={`${id}-kind`}>
              <Select id={`${id}-kind`} value={kind} onChange={(e) => setKind(e.target.value)}>
                {Object.entries(KIND_TITLES).map(([k, title]) => (
                  <option key={k} value={k}>
                    {title}
                  </option>
                ))}
              </Select>
            </Field>
            <Field label="Value" htmlFor={`${id}-value`} className="min-w-40 flex-1">
              <TextInput id={`${id}-value`} value={value} maxLength={300} placeholder="e.g. 10.201.7.13" aria-invalid={problem !== null} aria-describedby={problem ? `${id}-problem` : undefined} onChange={(e) => setValue(e.target.value)} />
            </Field>
            <Button type="submit">Find</Button>
          </div>
          {problem && (
            <p id={`${id}-problem`} role="alert" className="m-0 text-sm text-danger">
              {problem}
            </p>
          )}
        </form>
        <Field label="Rule" htmlFor={`${id}-rule`}>
          <Select id={`${id}-rule`} value={search.rule ?? ""} onChange={(e) => go({ rule: e.target.value === "" ? undefined : e.target.value })}>
            <option value="">All rules</option>
            {search.rule !== undefined && !rules.data?.some((r) => r.rule_id === search.rule) && <option value={search.rule}>{optionText(search.rule)}</option>}
            {(rules.data ?? []).map((r) => (
              <option key={r.rule_id} value={r.rule_id}>
                {optionText(r.rule_name ?? r.rule_id)}
              </option>
            ))}
          </Select>
        </Field>
        <Field label="Sort" htmlFor={`${id}-sort`}>
          <Select id={`${id}-sort`} value={effectiveSort(search)} onChange={(e) => go({ sort: e.target.value as InboxSearch["sort"] })}>
            {Object.entries(SORT_TITLES)
              .filter(([k]) => k !== "reviewed" || search.view === "reviewed")
              .map(([k, title]) => (
                <option key={k} value={k}>
                  {title}
                </option>
              ))}
          </Select>
        </Field>
        {(search.kind !== undefined || search.rule !== undefined) && (
          <p className="m-0 text-sm">
            Showing{" "}
            {search.kind !== undefined && (
              <>
                {KIND_TITLES[search.kind]?.toLowerCase()} <span className="font-mono"><UntrustedText value={search.value} limits={{ maxChars: 120, maxLines: 1 }} /></span>
              </>
            )}
            {search.rule !== undefined && (
              <>
                {search.kind !== undefined ? " and " : ""}rule <span className="font-mono"><UntrustedText value={search.rule} limits={{ maxChars: 120, maxLines: 1 }} /></span>
              </>
            )}
            .{" "}
            <Link to="/search" search={{ advanced: "1", view: search.view }}>
              Clear
            </Link>
          </p>
        )}
      </div>
    </details>
  );
}

/**
 * The two-pane Inbox (plan §5 Q-B2): the list on the left, the selected investigation on the
 * right. Above ~1024 px the right pane follows the list's cursor; below it one pane shows at a
 * time (the list, or the investigation with a way back).
 */
export function Inbox({ search }: { search: InboxSearch }) {
  const navigate = useNavigate({ from: "/search" });
  const session = useSession();
  const wide = useWide();
  const list = useInfiniteQuery(listOptions(search));
  const fetchMore = list.fetchNextPage;
  const loadMore = useCallback(() => void fetchMore(), [fetchMore]);
  // a page that failed to read is not asked for again by itself: the person reads the message
  const more = list.hasNextPage && !list.isFetchNextPageError;
  const rows = useMemo<InvestigationOut[]>(() => list.data?.pages.flatMap((p) => p.items) ?? [], [list.data]);
  const [moved, setMoved] = useState<{ id: string | undefined; index: number } | null>(null);
  const [shortcuts, setShortcuts] = useState(() => loadShortcuts(browserStorage()));
  const [help, setHelp] = useState(false);
  const follow = useRef<number | undefined>(undefined);
  const grid = useRef<HTMLDivElement>(null);
  const openId = search.id;
  const tab: Tab = search.tab ?? "overview";
  // the cursor stands on the open investigation, until a key or a click moves it elsewhere
  const openAt = openId === undefined ? -1 : rows.findIndex((r) => r.id === openId);
  const cursor = moved !== null && moved.id === openId ? moved.index : openAt;

  const open = useCallback(
    (id: string, replace: boolean) => {
      void navigate({ search: (prev) => ({ ...prev, id }), replace });
    },
    [navigate],
  );

  // two panes: the right one is never empty once there is a list
  useEffect(() => {
    const first = rows[0];
    if (wide && openId === undefined && first) open(first.id, true);
  }, [wide, openId, rows, open]);

  useEffect(() => () => window.clearTimeout(follow.current), []);

  const moveCursor = (index: number) => {
    setMoved({ id: openId, index });
    const row = rows[index];
    if (row && wide) {
      window.clearTimeout(follow.current);
      follow.current = window.setTimeout(() => open(row.id, true), FOLLOW_MS);
    }
  };

  const choose = (row: InvestigationOut, focus: boolean) => {
    window.clearTimeout(follow.current);
    open(row.id, false);
    if (focus) window.setTimeout(() => document.getElementById("detail-pane")?.focus(), 0);
  };

  const backToList = () => {
    void navigate({ search: (prev) => ({ ...prev, id: undefined }) });
    window.setTimeout(() => grid.current?.querySelector<HTMLElement>("[role=grid]")?.focus(), 0);
  };

  const detailKeys = (e: KeyboardEvent<HTMLElement>) => {
    if (e.key !== "Escape" || !e.currentTarget.contains(e.target as Node)) return;
    const tag = (e.target as HTMLElement).tagName;
    if (tag === "SELECT" || tag === "INPUT" || tag === "TEXTAREA") return;
    if (wide) grid.current?.querySelector<HTMLElement>("[role=grid]")?.focus();
    else backToList();
  };

  const showList = wide || openId === undefined;
  const showDetail = wide || openId !== undefined;
  const capped = rows.length >= DEEPEST + PAGE;
  return (
    <>
      <h1 className="sr-only">Inbox</h1>
      <div className="flex flex-col gap-3 lg:grid lg:h-[calc(100dvh-7rem)] lg:grid-cols-[minmax(20rem,26rem)_minmax(0,1fr)] lg:items-stretch lg:gap-4">
        {showList && (
          <section aria-label="Investigations" className="flex min-h-0 flex-col gap-2 lg:h-full">
            <Views search={search} />
            <FindAndSort search={search} />
            <div className="flex flex-wrap items-center justify-between gap-2 text-sm">
              <span aria-live="polite" className="text-muted">
                {list.isPending ? "Loading…" : `${count(rows.length)}${more ? " or more" : ""} ${rows.length === 1 ? "investigation" : "investigations"}, ${SORT_TITLES[effectiveSort(search)]}`}
              </span>
              <span className="inline-flex items-center gap-2">
                <Check checked={shortcuts} onChange={(e) => { setShortcuts(e.target.checked); saveShortcuts(browserStorage(), e.target.checked); }}>
                  Single-key shortcuts (j, k, ?)
                </Check>
                <Button size="sm" variant="ghost" onClick={() => setHelp(true)} aria-label="Show keyboard shortcuts">
                  ?
                </Button>
              </span>
            </div>
            {list.isError && <Problem error={list.error} what={rows.length > 0 ? "The next part of the list" : "The list"} onRetry={() => void list.refetch()} />}
            {list.isPending && <Loading what="the investigations" />}
            {list.data && rows.length === 0 && <p className="m-0 text-sm text-muted">Nothing here.</p>}
            <div ref={grid} className="flex min-h-0 flex-col max-lg:h-[70dvh] lg:flex-1">
              {rows.length > 0 && (
                <InboxList
                  rows={rows}
                  hasMore={more}
                  loadingMore={list.isFetchingNextPage}
                  onLoadMore={loadMore}
                  cursor={cursor}
                  onCursor={moveCursor}
                  onOpen={choose}
                  shortcuts={shortcuts}
                  onHelp={() => setHelp(true)}
                  since={session.data?.since}
                />
              )}
            </div>
            {capped && <p className="m-0 text-xs text-muted">This is as far as the list goes. Narrow it with a view, a rule, or a host or address to see the rest.</p>}
          </section>
        )}
        {showDetail && (
          <section id="detail-pane" tabIndex={-1} aria-label="Investigation details" onKeyDown={detailKeys} className="min-w-0 overflow-y-auto rounded-card border border-border bg-surface p-4 focus:outline-none lg:h-full">
            {!wide && (
              <p className="m-0 mb-2">
                <Button size="sm" onClick={backToList}>
                  ← Back to the list
                </Button>
              </p>
            )}
            {openId !== undefined ? (
              <InvestigationView
                id={openId}
                tab={tab}
                onTab={(next) => void navigate({ search: (prev) => ({ ...prev, tab: next }), replace: true })}
              />
            ) : (
              <p className="m-0 text-sm text-muted">Choose an investigation from the list.</p>
            )}
          </section>
        )}
      </div>
      <KeysHelp open={help} onOpenChange={setHelp} />
    </>
  );
}

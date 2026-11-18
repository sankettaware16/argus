import { useInfiniteQuery } from "@tanstack/react-query";
import { Link, useNavigate } from "@tanstack/react-router";
import { useEffect, useId, useMemo, useRef, useState, type ReactNode } from "react";
import { BulkBar } from "../components/incidents/Bulk";
import { PreviewPane } from "../components/incidents/PreviewPane";
import { ReviewTogether } from "../components/incidents/ReviewTogether";
import { CertaintyWord, ChangedDot, PriorityBadge } from "../components/incident/Parts";
import { Problem } from "../components/Problem";
import { UntrustedText } from "../components/UntrustedText";
import { Button } from "../components/ui/button";
import { reasonLabel } from "../lib/cases";
import { cn } from "../lib/cn";
import { BANDS, priorityTip, shownCertainty, startsWithCertainty, stateWords, topWhy } from "../lib/engine";
import {
  CERTAINTY_FILTERS,
  filterCount,
  filterRows,
  INCIDENT_VIEWS,
  KIBANA_FILTERS,
  LANE_FILTERS,
  rowOf,
  SIDE_FILTERS,
  SIDE_WORDS,
  SORT_WORDS,
  SORTS,
  sortRows,
  VIEW_API,
  VIEW_TITLES,
  type IncidentsSearch,
  type IncidentView,
  type Row,
} from "../lib/incidents";
import { casesOptions } from "../lib/queries";
import { can, useSession } from "../lib/session";
import { parse } from "../lib/time";
import { usePaneWide, usePhone } from "../lib/viewport";
import { useShortcuts } from "../lib/useShortcuts";
import { shortDay, waited, weekdayDay } from "../lib/when";
import { LANE_WORDS } from "../lib/engine";

const MAX_ROWS = 500;

/** A row's title link: the keys move the focus there, so the cursor is always a real focus. */
function titleOf(id: string): HTMLElement | null {
  return document.getElementById(`incident-row-${id}`)?.querySelector<HTMLElement>("[data-testid=row-title]") ?? null;
}
const DAY = 86_400_000;
const LAST_VIEW = "argus.incidents.view";

function rememberView(view: IncidentView) {
  try {
    window.localStorage.setItem(LAST_VIEW, view);
  } catch {
    // a convenience: without browser storage nothing is remembered
  }
}

/** One filter chip: a small menu of check boxes, written to the address. */
function Chip({ label, values, words, chosen, onChange }: { label: string; values: readonly string[]; words?: Readonly<Record<string, string>>; chosen: string[] | undefined; onChange: (next: string[] | undefined) => void }) {
  const [open, setOpen] = useState(false);
  const id = useId();
  const box = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const away = (e: MouseEvent) => {
      if (box.current && !box.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", away);
    return () => document.removeEventListener("mousedown", away);
  }, [open]);
  const n = chosen?.length ?? 0;
  return (
    <div ref={box} className="relative" onKeyDown={(e) => e.key === "Escape" && setOpen(false)}>
      <Button size="sm" aria-expanded={open} aria-controls={open ? id : undefined} onClick={() => setOpen(!open)} className={cn(n > 0 && "border-accent bg-accent-soft")}>
        {label}
        {n > 0 ? ` (${n})` : ""} ▾
      </Button>
      {open && (
        <fieldset id={id} className="absolute left-0 z-30 m-0 mt-1 flex min-w-48 flex-col gap-1 rounded-card border border-border bg-raised p-2 text-sm shadow-card">
          <legend className="sr-only">{label}</legend>
          {values.map((v) => (
            <label key={v} className="flex items-center gap-2">
              <input
                type="checkbox"
                className="size-4 accent-accent"
                checked={chosen?.includes(v) ?? false}
                onChange={(e) => {
                  const next = e.target.checked ? [...(chosen ?? []), v] : (chosen ?? []).filter((x) => x !== v);
                  onChange(next.length > 0 ? next : undefined);
                }}
              />
              {words?.[v] ?? v}
            </label>
          ))}
        </fieldset>
      )}
    </div>
  );
}

function Filters({ search, set, me }: { search: IncidentsSearch; set: (patch: Partial<IncidentsSearch>) => void; me: string | null }) {
  const [q, setQ] = useState(search.q ?? "");
  const phone = usePhone();
  const [shown, setShown] = useState(false);
  const n = filterCount(search);
  const body = (
    <div className="flex flex-wrap items-center gap-2">
      <Chip label="Priority" values={BANDS} chosen={search.band} onChange={(band) => set({ band: band as IncidentsSearch["band"] })} />
      <Chip label="Certainty" values={CERTAINTY_FILTERS} chosen={search.certainty} onChange={(certainty) => set({ certainty })} />
      <Chip label="Campus side" values={SIDE_FILTERS} words={SIDE_WORDS} chosen={search.side} onChange={(side) => set({ side })} />
      <Chip label="Taken by" values={["me", "nobody"]} words={{ me: me ? "Me" : "Me", nobody: "Nobody" }} chosen={search.taken ? [search.taken] : undefined} onChange={(t) => set({ taken: t?.at(-1) })} />
      <label className="flex items-center gap-1.5 text-sm">
        <input type="checkbox" className="size-4 accent-accent" checked={search.active === "1"} onChange={(e) => set({ active: e.target.checked ? "1" : undefined })} />
        Still active
      </label>
      <Chip label="More" values={["ai", ...LANE_FILTERS.map((l) => `lane:${l}`), ...KIBANA_FILTERS.map((k) => `kibana:${k}`)]} words={{ ai: "Raised by ARGUS's AI", ...Object.fromEntries(LANE_FILTERS.map((l) => [`lane:${l}`, `Kind of signal: ${LANE_WORDS[l]}`])), "kibana:in": "In Kibana", "kibana:waiting": "Not in Kibana yet", "kibana:failing": "Kibana posting failing" }} chosen={[...(search.ai ? ["ai"] : []), ...(search.lane ? [`lane:${search.lane}`] : []), ...(search.kibana ? [`kibana:${search.kibana}`] : [])]} onChange={(v) => set({ ai: v?.includes("ai") ? "1" : undefined, lane: v?.filter((x) => x.startsWith("lane:")).at(-1)?.slice(5), kibana: v?.filter((x) => x.startsWith("kibana:")).at(-1)?.slice(7) as IncidentsSearch["kibana"] })} />
      {n > 0 && (
        <Button size="sm" variant="ghost" onClick={() => set({ band: undefined, certainty: undefined, side: undefined, taken: undefined, active: undefined, ai: undefined, lane: undefined, kibana: undefined })}>
          Clear
        </Button>
      )}
    </div>
  );
  return (
    <div className="flex flex-col gap-2">
      <form
        role="search"
        aria-label="Filter the incidents"
        onSubmit={(e) => {
          e.preventDefault();
          set({ q: q.trim() || undefined });
        }}
        className="flex flex-wrap items-center gap-2"
      >
        <input type="search" value={q} maxLength={120} onChange={(e) => setQ(e.target.value)} aria-label="Filter by title, number, IR, address" placeholder="Filter by title, number, IR, address…" className="min-h-8 w-full max-w-sm rounded-control border border-border-strong bg-bg px-3 text-sm text-text" />
        {phone && (
          <Button size="sm" aria-expanded={shown} onClick={() => setShown(!shown)}>
            Filters{n > 0 ? ` (${n})` : ""}
          </Button>
        )}
      </form>
      {(!phone || shown) && body}
    </div>
  );
}

function Cell({ children, className }: { children: ReactNode; className?: string }) {
  return <span className={cn("min-w-0 text-sm", className)}>{children}</span>;
}

function RowView({ r, view, active, selected, selectable, onSelect, onOpen, onFocus, now, phone }: { r: Row; view: IncidentView; active: boolean; selected: boolean; selectable: boolean; onSelect: (on: boolean) => void; onOpen: () => void; onFocus: () => void; now: Date; phone: boolean }) {
  const { row, engine } = r;
  const certainty = shownCertainty(row.state, row.closure_reason, engine);
  const top = engine ? topWhy(engine, 1).shown[0] : undefined;
  const campus = engine?.objects.filter((o) => o.role === "affected") ?? [];
  const last = parse(engine?.last_seen ?? row.last_alert_at);
  const first = parse(engine?.first_seen ?? row.first_alert_at);
  const waiting = parse((row as typeof row & { waiting_since?: string | null }).waiting_since ?? null);
  const hold = (row as typeof row & { hold?: { by?: { name?: string }; until?: string } | null }).hold;
  const kibana = row.in_kibana ? "In Kibana" : row.state === "suspected" ? "—" : "Not yet";
  const title = (
    <Link to="/incidents/$id" params={{ id: row.id }} className="inline-block min-h-6 text-text no-underline hover:underline" onClick={(e) => e.stopPropagation()} onFocus={onFocus} data-testid="row-title">
      {certainty !== null && !startsWithCertainty(row.title) && (
        <>
          <CertaintyWord value={certainty} /> ·{" "}
        </>
      )}
      <UntrustedText value={row.title} limits={{ maxChars: 200, maxLines: 2 }} />
    </Link>
  );
  const second = (
    <span className="text-[0.8125rem] text-muted">
      #{row.number}
      {(view === "all" || view === "closed") && ` · ${stateWords({ state: row.state, number: null, taken_by: row.owner ? { username: row.owner.username, name: row.owner.display_name } : null })}`}
      {top && (
        <>
          {" "}
          · <UntrustedText value={top} limits={{ maxChars: 120, maxLines: 1 }} />
        </>
      )}
    </span>
  );
  const check = selectable ? (
    <input type="checkbox" className="size-6 accent-accent" aria-label={`Select incident #${row.number}`} checked={selected} onChange={(e) => onSelect(e.target.checked)} onClick={(e) => e.stopPropagation()} />
  ) : null;
  if (phone) {
    return (
      <li id={`incident-row-${row.id}`} data-active={active || undefined} data-testid="incident-row" data-id={row.id} className={cn("flex flex-col gap-1 rounded-card bg-surface p-3", active && "ring-2 ring-focus")} onClick={onOpen}>
        <span className="flex items-center gap-2 text-sm">
          {check}
          <PriorityBadge engine={engine} />
          <CertaintyWord value={certainty} />
          {waiting && <span className="text-muted">· waiting {waited(waiting, now)}</span>}
        </span>
        <span className="line-clamp-2 font-semibold">{title}</span>
        {top && <span className="truncate text-sm">{top}</span>}
        <span className="text-sm text-muted">
          {campus[0]?.label ?? ""}
          {campus.length > 1 ? ` +${campus.length - 1}` : ""} · {engine?.active ? "active" : last ? `quiet ${waited(last, now)}` : ""}
        </span>
      </li>
    );
  }
  return (
    <li
      id={`incident-row-${row.id}`}
      data-active={active || undefined}
      data-testid="incident-row"
      data-id={row.id}
      onClick={onOpen}
      className={cn("grid min-h-16 cursor-pointer grid-cols-[1.5rem_3rem_0.75rem_minmax(0,1fr)_9rem_6rem_9rem] items-center gap-x-3 border-b border-border px-2 py-1.5 hover:bg-surface-2", active && "bg-accent-soft")}
    >
      <Cell>{check}</Cell>
      <Cell>
        <span title={priorityTip(engine)}>
          <PriorityBadge engine={engine} />
        </span>
      </Cell>
      <Cell>
        <ChangedDot on={(engine?.changed.length ?? 0) > 0} />
      </Cell>
      <Cell className="flex flex-col">
        <span className="font-medium">{title}</span>
        {second}
      </Cell>
      <Cell className="truncate">
        {campus[0] ? <UntrustedText value={campus[0].label} limits={{ maxChars: 60, maxLines: 1 }} /> : "—"}
        {campus.length > 1 && <span className="text-muted"> +{campus.length - 1}</span>}
      </Cell>
      <Cell>
        <span title={first ? `first seen ${shortDay(first)}` : undefined}>{engine?.active ? "active" : last ? `quiet ${waited(last, now).replace(" days", " d").replace(" day", " d")}` : "—"}</span>
      </Cell>
      <Cell className="truncate">
        {view === "needs-you" && (hold?.by?.name ? `${hold.by.name} is checking${hold.until ? ` · ${weekdayDay(new Date(hold.until))}` : ""}` : waiting ? waited(waiting, now) : "—")}
        {view === "owner-told" && row.notified_at && <span className="block">Owner told {shortDay(parse(row.notified_at) ?? now)}{row.blocked_at ? ", blocked at the network" : ""}</span>}
        {(view === "mine" || view === "open" || view === "owner-told" || view === "all") && (row.owner ? <UntrustedText value={row.owner.display_name} limits={{ maxChars: 40, maxLines: 1 }} /> : "—")}
        {(view === "open" || view === "mine") && <span className="block text-muted">{kibana}</span>}
        {view === "closed" && `Closed${row.closed_at ? ` ${shortDay(parse(row.closed_at) ?? now)}` : ""}: ${reasonLabel(row.closure_reason)}`}
      </Cell>
    </li>
  );
}

function Header({ view }: { view: IncidentView }) {
  const third = view === "needs-you" ? "Waiting" : view === "closed" ? "Closed" : view === "open" || view === "mine" ? "Taken by · Kibana" : "Taken by";
  return (
    <div className="grid grid-cols-[1.5rem_3rem_0.75rem_minmax(0,1fr)_9rem_6rem_9rem] gap-x-3 border-b border-border px-2 py-1 text-xs font-semibold text-muted" aria-hidden="true">
      <span />
      <span>Pri</span>
      <span />
      <span>Incident</span>
      <span>Campus side</span>
      <span>Activity</span>
      <span>{third}</span>
    </div>
  );
}

/**
 * Incidents (docs/p4f-ui-spec.md §6): every incident, sorted by what matters; decide or find one.
 * The view tab, the filters and the sort are in the address; at 1280 px a row opens the preview
 * pane, below it the incident's page. Bulk is "Not an incident", merge and Review together; there
 * is no bulk confirm.
 */
export function Incidents({ search }: { search: IncidentsSearch }) {
  const navigate = useNavigate({ from: "/incidents" });
  const session = useSession();
  const me = session.data?.user.username ?? null;
  const selectable = can(session.data, "review");
  const wide = usePaneWide();
  const phone = usePhone();
  const [shortcuts] = useShortcuts();
  const filtered = filterCount(search) > 0 || (search.sort !== undefined && search.sort !== "priority");
  const list = useInfiniteQuery(casesOptions({ view: VIEW_API[search.view], ...(search.q ? { q: search.q } : {}) }));
  const { hasNextPage, isFetchingNextPage, fetchNextPage } = list;
  const loaded = useMemo(() => (list.data?.pages ?? []).flatMap((p) => p.items).map(rowOf), [list.data]);
  useEffect(() => {
    if (filtered && hasNextPage && !isFetchingNextPage && loaded.length < MAX_ROWS) void fetchNextPage();
  }, [filtered, hasNextPage, isFetchingNextPage, fetchNextPage, loaded.length]);
  const now = useMemo(() => new Date(), [list.dataUpdatedAt]); // eslint-disable-line react-hooks/exhaustive-deps
  const counts = list.data?.pages[0]?.counts;
  const recent = search.view === "closed" && search.all_time !== "1" ? loaded.filter((r) => r.row.closed_at === null || (parse(r.row.closed_at)?.getTime() ?? 0) > now.getTime() - 30 * DAY) : loaded;
  const rows = sortRows(filterRows(recent, search, me), search.sort);
  const [cursor, setCursor] = useState<string | null>(null);
  const [pane, setPane] = useState<string | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const listRef = useRef<HTMLUListElement>(null);
  const confirmRef = useRef<(() => void) | null>(null);
  const dismissRef = useRef<(() => void) | null>(null);
  const set = (patch: Partial<IncidentsSearch>) => void navigate({ search: (prev: IncidentsSearch) => ({ ...prev, ...patch }) as IncidentsSearch, replace: true });
  const at = rows.findIndex((r) => r.row.id === cursor);
  const open = (id: string) => {
    setCursor(id);
    if (wide) setPane(id);
    else void navigate({ to: "/incidents/$id", params: { id } });
  };
  const move = (step: 1 | -1) => {
    const next = rows[Math.max(0, Math.min(rows.length - 1, (at < 0 ? -1 : at) + step))];
    if (next === undefined) return;
    setCursor(next.row.id);
    if (pane !== null) setPane(next.row.id);
    titleOf(next.row.id)?.focus();
  };
  useEffect(() => {
    if (!shortcuts) return;
    const press = (e: KeyboardEvent) => {
      if (e.ctrlKey || e.metaKey || e.altKey || e.defaultPrevented) return;
      const t = e.target as HTMLElement | null;
      if (t && (t.isContentEditable || ["INPUT", "TEXTAREA", "SELECT"].includes(t.tagName) || t.closest("[role=dialog],[role=alertdialog],[role=menu],form,fieldset"))) return;
      if (e.key === "j" || e.key === "ArrowDown") {
        e.preventDefault();
        move(1);
      } else if (e.key === "k" || e.key === "ArrowUp") {
        e.preventDefault();
        move(-1);
      } else if ((e.key === "Enter" || e.key === "o") && cursor) {
        e.preventDefault();
        void navigate({ to: "/incidents/$id", params: { id: cursor } });
      } else if (e.key === "Escape" && pane !== null) {
        e.preventDefault();
        setPane(null);
        if (cursor) titleOf(cursor)?.focus();
      } else if (e.key === "x" && cursor && selectable) {
        e.preventDefault();
        setSelected((old) => {
          const next = new Set(old);
          if (next.has(cursor)) next.delete(cursor);
          else next.add(cursor);
          return next;
        });
      } else if (e.key === "c" && pane !== null && confirmRef.current) {
        e.preventDefault();
        confirmRef.current();
      } else if (e.key === "d" && pane !== null && dismissRef.current) {
        e.preventDefault();
        dismissRef.current();
      }
    };
    document.addEventListener("keydown", press);
    return () => document.removeEventListener("keydown", press);
  });
  useEffect(() => rememberView(search.view), [search.view]);

  const chosen = rows.filter((r) => selected.has(r.row.id));
  if (search.together && search.together.length > 0) {
    const ids = search.together;
    const together = loaded.filter((r) => ids.includes(r.row.id));
    return (
      <div className="flex flex-col gap-3">
        <h1 className="page-h">Incidents</h1>
        {list.isPending ? <p className="m-0 text-sm text-muted">Loading…</p> : <ReviewTogether rows={together} onClose={() => set({ together: undefined })} />}
      </div>
    );
  }
  const empty =
    search.view === "needs-you" && filterCount(search) === 0 ? (
      <>
        Nothing needs you right now.{" "}
        <Link to="/incidents" search={{ view: "open" }}>
          See open incidents
        </Link>
      </>
    ) : filterCount(search) > 0 ? (
      <>
        No incident matches these filters. <Button size="sm" variant="ghost" onClick={() => set({ band: undefined, certainty: undefined, side: undefined, taken: undefined, active: undefined, ai: undefined, lane: undefined, kibana: undefined })}>Clear filters</Button>
      </>
    ) : search.view === "closed" ? (
      <>
        No incident was closed in the last 30 days. <Button size="sm" variant="ghost" onClick={() => set({ all_time: "1" })}>Show all time</Button>
      </>
    ) : (
      "No incident here."
    );
  const countOf: Record<IncidentView, number | undefined> = counts ? { "needs-you": counts.queue, mine: counts.mine, open: counts.active, "owner-told": counts.notified, closed: undefined, all: undefined } : ({} as Record<IncidentView, number | undefined>);
  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h1 className="page-h">Incidents</h1>
        <Button size="sm" variant="ghost" onClick={() => void navigator.clipboard?.writeText(window.location.href)}>
          Copy link to this view
        </Button>
      </div>
      <nav aria-label="Views" className="-mx-1 flex gap-1 overflow-x-auto px-1" data-testid="view-tabs">
        {INCIDENT_VIEWS.map((v) => (
          <Link key={v} to="/incidents" search={{ view: v }} aria-current={search.view === v ? "page" : undefined} activeOptions={{ includeSearch: true }} className="inline-flex min-h-9 shrink-0 items-center gap-1.5 rounded-full px-3.5 text-sm whitespace-nowrap text-text no-underline hover:bg-surface aria-[current=page]:bg-text aria-[current=page]:font-medium aria-[current=page]:text-bg">
            {VIEW_TITLES[v]}
            {countOf[v] !== undefined && <span className="text-xs text-muted tabular-nums" data-testid={`count-${v}`}>{countOf[v]}</span>}
          </Link>
        ))}
      </nav>
      <Filters search={search} set={set} me={me} />
      <div className="flex flex-wrap items-center justify-between gap-2 text-sm">
        <label className="flex items-center gap-2">
          Sorted by:
          <select value={search.sort ?? "priority"} onChange={(e) => set({ sort: e.target.value === "priority" ? undefined : (e.target.value as IncidentsSearch["sort"]) })} className="min-h-8 rounded-control border border-border-strong bg-bg px-2 text-sm text-text">
            {SORTS.map((s) => (
              <option key={s} value={s}>
                {SORT_WORDS[s]}
              </option>
            ))}
          </select>
        </label>
        <span className="text-muted" data-testid="row-count">
          {rows.length} {rows.length === 1 ? "incident" : "incidents"}
        </span>
      </div>
      {filtered && hasNextPage && loaded.length >= MAX_ROWS && <p className="m-0 text-sm text-muted">Filtering the {MAX_ROWS} newest incidents of this view.</p>}
      {chosen.length > 0 && <BulkBar rows={chosen} togetherIds={chosen.map((r) => r.row.id)} onClear={() => setSelected(new Set())} />}
      {list.isError && <Problem error={list.error} what="The incidents" onRetry={() => void list.refetch()} />}
      <div className={cn("grid gap-4", pane !== null && wide && "grid-cols-[minmax(0,58fr)_minmax(0,42fr)]")}>
        <div className="min-w-0">
          {!phone && <Header view={search.view} />}
          {list.isPending ? (
            <ul className="m-0 flex list-none flex-col p-0" aria-busy="true" aria-label="Loading the incidents">
              {Array.from({ length: 8 }, (_, i) => (
                <li key={i} className="h-16 border-b border-border bg-surface-2" />
              ))}
            </ul>
          ) : rows.length === 0 ? (
            <p className="m-0 py-4 text-sm text-muted" data-testid="incidents-empty">
              {empty}
            </p>
          ) : (
            <ul ref={listRef} aria-label={`${VIEW_TITLES[search.view]}: incidents`} className={cn("m-0 flex list-none flex-col p-0", phone && "gap-2")}>
              {rows.map((r) => (
                <RowView
                  key={r.row.id}
                  r={r}
                  view={search.view}
                  active={r.row.id === cursor}
                  selectable={selectable}
                  selected={selected.has(r.row.id)}
                  onSelect={(on) =>
                    setSelected((old) => {
                      const next = new Set(old);
                      if (on) next.add(r.row.id);
                      else next.delete(r.row.id);
                      return next;
                    })
                  }
                  onOpen={() => open(r.row.id)}
                  onFocus={() => setCursor(r.row.id)}
                  now={now}
                  phone={phone}
                />
              ))}
            </ul>
          )}
          {!filtered && hasNextPage && (
            <Button className="mt-2" aria-disabled={isFetchingNextPage} onClick={() => void fetchNextPage()}>
              {isFetchingNextPage ? "Loading…" : "Show more"}
            </Button>
          )}
        </div>
        {pane !== null && wide && (
          <PreviewPane
            id={pane}
            nextId={rows[at + 1]?.row.id ?? null}
            confirmRef={confirmRef}
            dismissRef={dismissRef}
            onMove={move}
            onClose={() => {
              setPane(null);
              if (cursor) titleOf(cursor)?.focus();
            }}
          />
        )}
      </div>
    </div>
  );
}

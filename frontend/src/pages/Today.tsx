import { useQuery } from "@tanstack/react-query";
import { teamName } from "../lib/site";
import { Link, useNavigate } from "@tanstack/react-router";
import { useEffect, useMemo, useRef, useState } from "react";
import type { DecideKeys } from "../components/decide/Decide";
import { inSentence, useOutcome } from "../components/decide/useOutcome";
import { IncidentCard } from "../components/today/IncidentCard";
import { UntrustedText } from "../components/UntrustedText";
import { Button } from "../components/ui/button";
import { Home } from "./Home";
import { SystemBanner } from "../shell/Status";
import { BACKGROUND } from "../lib/api";
import { unwrap } from "../lib/call";
import { listCases } from "../client/sdk.gen";
import type { CaseRowOut } from "../client/types.gen";
import { useDecided, type Decided } from "../lib/decided";
import { layoutNeedsYou, needsYouCount, stateWords, summaryParts, type Card, type Slot, type Today as TodayData } from "../lib/engine";
import { approvalsOptions } from "../lib/queries";
import { can, useSession } from "../lib/session";
import { parse } from "../lib/time";
import { todayOptions } from "../lib/today";
import { usePhone } from "../lib/viewport";
import { useShortcuts } from "../lib/useShortcuts";
import { longDay, roundWords, shortDay } from "../lib/when";
import { useNow } from "../lib/now";

const HOUR = 3_600_000;

/** The Kibana words of a decided or confirmed case (§3.3). */
export function kibanaWords(row: Pick<CaseRowOut, "in_kibana" | "kibana_wait" | "state">, ir?: string | null): string | null {
  if (row.in_kibana) return ir ? `In Kibana (${ir})` : "In Kibana";
  if (row.kibana_wait) return `Not in Kibana yet: ${row.kibana_wait}`;
  return null;
}

function Skeleton() {
  return (
    <div className="flex flex-col gap-3" aria-busy="true" aria-label="Loading Today">
      <div className="h-5 w-2/3 rounded bg-surface-3" />
      {[0, 1, 2].map((i) => (
        <div key={i} className="h-40 rounded-card border border-border bg-surface-2" />
      ))}
      <div className="h-4 w-1/2 rounded bg-surface-3" />
      <div className="h-4 w-1/3 rounded bg-surface-3" />
    </div>
  );
}

/** Region 2 (§5.2): confirmed incidents not in Kibana for over an hour, from the open list. */
function KibanaLine({ data }: { data: TodayData }) {
  const open = useQuery({
    queryKey: ["cases", "kibana-waiting"],
    queryFn: () => unwrap(listCases({ query: { view: "active", limit: 100 }, headers: BACKGROUND })),
    enabled: data.kibana_waiting === null,
    staleTime: 60_000,
  });
  const now = useNow(60_000);
  const waiting = data.kibana_waiting !== null ? [] : (open.data?.items ?? []).filter((c) => c.state !== "suspected" && !c.in_kibana && (parse(c.opened_at)?.getTime() ?? now) < now - HOUR);
  const n = data.kibana_waiting !== null ? data.kibana_waiting.count : waiting.length;
  const oldest = waiting.reduce<CaseRowOut | null>((o, c) => (o === null || (c.opened_at ?? "") < (o.opened_at ?? "") ? c : o), null);
  if (n === 0) return null;
  const since = parse(oldest?.opened_at ?? data.kibana_waiting?.oldest_since);
  return (
    <p data-testid="today-kibana" className="m-0 rounded-control border border-warn/40 bg-warn-soft px-3 py-2 text-sm text-warn">
      {n} confirmed {n === 1 ? "incident is" : "incidents are"} not in Kibana yet, so {teamName()} cannot see {n === 1 ? "it" : "them"} there.
      {oldest && since && ` Oldest #${oldest.number}, since ${shortDay(since)}.`}{" "}
      <Link to="/incidents" search={{ view: "open", kibana: "waiting" }}>
        See them
      </Link>
    </p>
  );
}

function SimilarRow({ slot }: { slot: Extract<Slot, { kind: "similar" }> }) {
  return (
    <div data-testid="similar-row" className="flex flex-wrap items-center justify-between gap-2 rounded-card border border-dashed border-border-strong bg-surface-2 px-4 py-2 text-sm">
      <span>
        <strong>{slot.cards.length} similar:</strong> {slot.band} · <UntrustedText value={slot.words} limits={{ maxChars: 120, maxLines: 1 }} /> · <UntrustedText value={slot.outcome} limits={{ maxChars: 120, maxLines: 1 }} />
      </span>
      <Link to="/incidents" search={{ view: "needs-you", together: slot.cards.map((c) => c.id ?? "").filter((x) => x !== "") }} className="inline-flex min-h-8 items-center rounded-control border border-border-strong bg-surface px-3 font-medium text-text no-underline hover:bg-surface-3">
        Review together
      </Link>
    </div>
  );
}

function DecidedRows() {
  const { items } = useDecided();
  const outcome = useOutcome();
  if (items.length === 0) return null;
  return (
    <section data-testid="today-decided" aria-labelledby="today-decided-h" className="flex flex-col gap-1">
      <h2 id="today-decided-h" className="m-0 text-sm font-semibold tracking-wide text-muted uppercase">
        Just decided
      </h2>
      <ul className="m-0 flex list-none flex-col p-0">
        {items.map((d) => (
          <DecidedRow key={d.id} d={d} canUndo={outcome.canReopen} undo={() => void outcome.undo(d.id, d.number, d.row)} />
        ))}
      </ul>
    </section>
  );
}

function DecidedRow({ d, canUndo, undo }: { d: Decided; canUndo: boolean; undo: () => void }) {
  // a confirmed one's Kibana state, read again every minute in the background (§5.2 region 4)
  const fresh = useQuery({
    queryKey: ["cases", "decided", d.number],
    queryFn: () => unwrap(listCases({ query: { view: "all", number: d.number, limit: 1 }, headers: BACKGROUND })),
    enabled: d.kind === "confirmed",
    refetchInterval: 60_000,
    staleTime: 55_000,
  });
  const row = fresh.data?.items[0] ?? d.row;
  return (
    <li data-testid="decided-row" className="flex min-h-12 flex-wrap items-center gap-x-3 gap-y-1 border-b border-border py-1 text-sm">
      <span className="font-semibold tabular-nums">#{d.number}</span>
      {d.undone ? (
        <span>Reopened by you: a possible incident again</span>
      ) : d.kind === "confirmed" ? (
        <span>
          Confirmed by you{kibanaWords(row) ? ` · ${kibanaWords(row)}` : ""}
        </span>
      ) : (
        <span>Closed by you: {inSentence(d.label ?? "")}</span>
      )}
      <span className="ml-auto flex gap-2">
        {d.kind === "closed" && !d.undone && canUndo && (
          <Button size="sm" onClick={undo}>
            Undo
          </Button>
        )}
        <Link to="/incidents/$id" params={{ id: d.id }}>
          Open
        </Link>
      </span>
    </li>
  );
}

function NewActivity({ cards }: { cards: Card[] }) {
  return (
    <section data-testid="today-new-activity" aria-labelledby="today-new-h" className="flex flex-col gap-1">
      <h2 id="today-new-h" className="m-0 text-sm font-semibold tracking-wide text-muted uppercase">
        New activity · {cards.length}
      </h2>
      {cards.length === 0 ? (
        <p className="m-0 text-sm text-muted">No new activity on incidents you know.</p>
      ) : (
        <ul className="m-0 flex list-none flex-col p-0">
          {cards.map((c) => (
            <li key={c.id ?? c.title} className="flex min-h-12 flex-wrap items-center gap-x-2 gap-y-1 border-b border-border py-1 text-sm">
              <span className="font-semibold tabular-nums">#{c.number}</span>
              <span className="text-muted">· {c.notified_at && c.state !== "closed" ? `Owner told ${shortDay(parse(c.notified_at) ?? new Date())}` : stateWords({ state: c.state, number: null, taken_by: c.taken_by })} ·</span>
              <span className="min-w-0 flex-1 truncate">
                <UntrustedText value={c.title} limits={{ maxChars: 120, maxLines: 1 }} />
              </span>
              {c.engine.changed[0] && (
                <span>
                  New: <UntrustedText value={c.engine.changed[0]} limits={{ maxChars: 100, maxLines: 1 }} />
                  {c.engine.changed.length > 1 && <span className="text-muted"> +{c.engine.changed.length - 1}</span>}
                </span>
              )}
              {c.id && (
                <Link to="/incidents/$id" params={{ id: c.id }}>
                  Open
                </Link>
              )}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function Handled({ data }: { data: TodayData }) {
  const h = data.handled;
  const since = parse(h.since);
  return (
    <section data-testid="today-handled" aria-labelledby="today-handled-h" className="flex flex-col gap-2">
      <h2 id="today-handled-h" className="m-0 text-sm font-semibold tracking-wide text-muted uppercase">
        Handled by ARGUS{since ? ` since ${roundWords(since)}` : ""} · {h.count.toLocaleString("en-US")}
      </h2>
      {h.count === 0 ? (
        <p className="m-0 text-sm text-muted">ARGUS closed nothing on its own since your last round.</p>
      ) : (
        <p className="m-0 text-sm" data-testid="handled-categories">
          {h.categories.map((c, i) => (
            <span key={c.key}>
              {i > 0 && " · "}
              <UntrustedText value={c.label} limits={{ maxChars: 80, maxLines: 1 }} /> <span className="tabular-nums">{c.count.toLocaleString("en-US")}</span>
            </span>
          ))}
        </p>
      )}
      {h.audits.length > 0 && (
        <div className="flex flex-wrap items-baseline justify-between gap-2">
          <h3 className="m-0 text-sm font-semibold">Spot-check (about 10 seconds each)</h3>
          {data.audit_score && (
            <span className="text-sm text-muted" data-testid="audit-score">
              Your team&apos;s spot-checks, {data.audit_score.days} days: {data.audit_score.checked} checked, {data.audit_score.wrong} wrong
            </span>
          )}
        </div>
      )}
      {h.audits.map((a) => (
        <article key={a.id} data-testid="today-audit" className="flex flex-col gap-1 rounded-card border border-border bg-surface p-3 text-sm">
          <p className="m-0" data-testid="audit-facts">
            <UntrustedText value={a.facts.length > 0 ? a.facts.join(" · ") : a.title} limits={{ maxChars: 400, maxLines: 3 }} />
          </p>
          <p className="m-0 self-end text-[0.8125rem] text-muted" data-testid="audit-closed-as">
            ARGUS closed it as: <UntrustedText value={a.closed_as} limits={{ maxChars: 80, maxLines: 1 }} />
          </p>
          <p className="m-0">
            {a.kind === "incident" ? (
              <Link to="/incidents/$id" params={{ id: a.id }}>
                Open it
              </Link>
            ) : (
              <Link to="/alert-groups/$id" params={{ id: a.id }}>
                Open it
              </Link>
            )}
          </p>
        </article>
      ))}
    </section>
  );
}

function Approvals() {
  const session = useSession();
  const approver = can(session.data, "approve");
  const q = useQuery({ ...approvalsOptions, enabled: approver });
  const pending = q.data?.pending ?? [];
  if (!approver || pending.length === 0) return null;
  return (
    <section data-testid="today-approvals" aria-labelledby="today-approvals-h" className="flex flex-col gap-1">
      <h2 id="today-approvals-h" className="m-0 text-sm font-semibold tracking-wide text-muted uppercase">
        Waiting for your approval · {q.data?.pending_total ?? pending.length}
      </h2>
      <ul className="m-0 flex list-none flex-col p-0">
        {pending.slice(0, 5).map((a) => (
          <li key={a.id} className="flex min-h-12 flex-wrap items-center gap-x-2 border-b border-border py-1 text-sm">
            <span className="min-w-0 flex-1">
              <UntrustedText value={a.words} limits={{ maxChars: 200, maxLines: 1 }} />, requested by <UntrustedText value={a.requested_by?.display_name ?? "someone"} limits={{ maxChars: 60, maxLines: 1 }} />
              {a.note && (
                <>
                  : “<UntrustedText value={a.note} limits={{ maxChars: 120, maxLines: 1 }} />”
                </>
              )}
            </span>
            <Link to="/approvals">Review</Link>
          </li>
        ))}
      </ul>
    </section>
  );
}

/** The cards in Needs you, pinned: a refetch that adds cards says "N new · Show" and never reorders the list under the cursor (§5, §14). */
function usePinned(cards: Card[]): { shown: Card[]; added: number; show: () => void } {
  const ids = cards.map((c) => c.id ?? c.title);
  const [order, setPinned] = useState<string[]>(() => ids);
  const byId = new Map(cards.map((c) => [c.id ?? c.title, c]));
  const shown = order.map((id) => byId.get(id)).filter((c): c is Card => c !== undefined);
  const added = ids.filter((id) => !order.includes(id)).length;
  return { shown, added, show: () => setPinned(ids) };
}

/** j/k between the cards' titles, c and d on the card that holds the focus (§13); nothing sends on one key. */
function useCardKeys(on: boolean, titles: React.MutableRefObject<(HTMLAnchorElement | null)[]>, keys: DecideKeys[]) {
  const navigate = useNavigate();
  useEffect(() => {
    if (!on) return;
    const press = (e: KeyboardEvent) => {
      if (e.ctrlKey || e.metaKey || e.altKey || e.defaultPrevented) return;
      const t = e.target as HTMLElement | null;
      if (t && (t.isContentEditable || ["INPUT", "TEXTAREA", "SELECT"].includes(t.tagName) || t.closest("[role=dialog],[role=alertdialog],[role=menu],form"))) return;
      const list = titles.current.filter((x): x is HTMLAnchorElement => x !== null);
      const at = list.findIndex((x) => x.closest("article")?.contains(document.activeElement) ?? false);
      if (e.key === "j" || e.key === "k") {
        e.preventDefault();
        const next = at < 0 ? 0 : Math.max(0, Math.min(list.length - 1, at + (e.key === "j" ? 1 : -1)));
        list[next]?.focus();
      } else if ((e.key === "c" || e.key === "d") && at >= 0) {
        const k = keys[titles.current.indexOf(list[at] ?? null)];
        const fn = e.key === "c" ? k?.confirm.current : k?.dismiss.current;
        if (fn) {
          e.preventDefault();
          fn();
        }
      } else if (e.key === "o" && at >= 0) {
        const href = list[at]?.getAttribute("href");
        if (href) {
          e.preventDefault();
          void navigate({ href: href.replace(/^\/app/, "") });
        }
      }
    };
    document.addEventListener("keydown", press);
    return () => document.removeEventListener("keydown", press);
  }, [on, titles, keys, navigate]);
}

function useCardKeyRefs(n: number): DecideKeys[] {
  return useMemo(() => Array.from({ length: n }, () => ({ confirm: { current: null }, dismiss: { current: null } })), [n]);
}

/**
 * Today (docs/p4f-ui-spec.md §5): in 20 minutes, decide what needs a person and trust what ARGUS
 * did alone. One call (`GET /today`); the summary line, the Kibana line, Needs you (every P1 and P2
 * on its own card), what was just decided, new activity, the gray band, what ARGUS handled with its
 * spot-checks, approvals.
 */
export function Today({ data }: { data: TodayData }) {
  const phone = usePhone();
  const [shortcuts] = useShortcuts();
  const { items } = useDecided();
  const [conflicts, setConflicts] = useState<Set<string>>(new Set());
  const decidedIds = useMemo(() => new Set(items.filter((d) => !d.undone).map((d) => d.id)), [items]);
  const live = data.needs_you.filter((c) => c.id === null || !decidedIds.has(c.id));
  const pinned = usePinned(live);
  const { slots, hidden } = layoutNeedsYou(pinned.shown);
  const now = new Date();
  const since = parse(data.handled.since);
  const parts = summaryParts(data, since ? roundWords(since, now) : null);
  const firstP1 = data.needs_you.find((c) => c.engine.band === "P1");
  const titles = useRef<(HTMLAnchorElement | null)[]>([]);
  const cardCount = slots.filter((s) => s.kind === "card").length + data.gray.length;
  const keyRefs = useCardKeyRefs(cardCount);
  useCardKeys(shortcuts && !phone, titles, keyRefs);
  const gray = data.gray.filter((c) => c.id === null || !decidedIds.has(c.id));
  let k = 0;
  const focusNext = (index: number) => {
    window.setTimeout(() => titles.current.filter((t) => t !== null && t.isConnected)[index]?.focus(), 0);
  };
  return (
    <div className="flex flex-col gap-3 sm:gap-5">
      <header className="flex flex-col gap-1">
        <div className="flex flex-wrap items-baseline justify-between gap-2">
          <h1 className="m-0 text-2xl font-semibold">Today</h1>
          <span className="text-sm text-muted">{longDay(now)}</span>
        </div>
        <p className="m-0 text-sm" data-testid="today-summary">
          {parts.map((p, i) => (
            <span key={i}>
              {i > 0 && " · "}
              {p.strong ? <strong>{p.text}</strong> : p.text}
            </span>
          ))}
        </p>
        {phone && firstP1?.id && (
          <p className="m-0 text-sm">
            <Link to="/incidents/$id" params={{ id: firstP1.id }}>
              Urgent: <UntrustedText value={firstP1.title} limits={{ maxChars: 120, maxLines: 1 }} />
            </Link>
          </p>
        )}
      </header>
      <KibanaLine data={data} />
      <section data-testid="today-needs-you" aria-labelledby="today-needs-h" className="flex flex-col gap-2 sm:gap-3">
        <div className="flex flex-wrap items-baseline justify-between gap-2">
          <h2 id="today-needs-h" className="m-0 text-sm font-semibold tracking-wide text-muted uppercase">
            Needs you · {needsYouCount(data)}
          </h2>
          <span className="hidden text-sm text-muted sm:inline">Sorted by priority</span>
        </div>
        {pinned.added > 0 && (
          <p className="m-0 text-sm" role="status">
            {pinned.added} new ·{" "}
            <Button size="sm" variant="ghost" onClick={pinned.show}>
              Show
            </Button>
          </p>
        )}
        {slots.length === 0 && <p className="m-0 text-sm text-muted">Nothing needs you right now. ARGUS puts new incidents here.</p>}
        {slots.map((s, i) => {
          if (s.kind === "similar") return <SimilarRow key={`similar-${i}`} slot={s} />;
          const index = k++;
          const id = s.card.id ?? s.card.title;
          return (
            <IncidentCard
              key={id}
              card={s.card}
              form={phone ? "phone" : "full"}
              now={now}
              keys={keyRefs[index]}
              titleRef={(el) => {
                titles.current[index] = el;
              }}
              conflict={conflicts.has(id)}
              onConflict={() => setConflicts((old) => new Set(old).add(id))}
              onDone={() => focusNext(index)}
            />
          );
        })}
        {hidden + data.more_waiting > 0 && (
          <p className="m-0 text-sm" data-testid="today-more-waiting">
            + {hidden + data.more_waiting} more waiting · lower priority →{" "}
            <Link to="/incidents" search={{ view: "needs-you" }}>
              Open Needs you in Incidents
            </Link>
          </p>
        )}
      </section>
      <DecidedRows />
      <NewActivity cards={data.new_activity} />
      {data.away && since && now.getTime() - since.getTime() > 24 * HOUR && (
        <section data-testid="today-away" className="flex flex-col gap-1 text-sm">
          <h2 className="m-0 text-sm font-semibold tracking-wide text-muted uppercase">While you were away</h2>
          {data.away.decided_by_others.length > 0 && <p className="m-0">Decided by others: {data.away.decided_by_others.map((d) => `${d.who} ${d.text}`).join(" · ")}</p>}
          {data.away.went_quiet.length > 0 && <p className="m-0">Went quiet: {data.away.went_quiet.map((c) => `#${c.number}`).join(", ")}</p>}
          {data.away.gaps.map((g, i) => (
            <p key={i} className="m-0">
              Gaps: <UntrustedText value={g.words} limits={{ maxChars: 300, maxLines: 2 }} />
            </p>
          ))}
        </section>
      )}
      {gray.length > 0 && (
        <section data-testid="today-gray" aria-labelledby="today-gray-h" className="flex flex-col gap-2">
          <h2 id="today-gray-h" className="m-0 text-sm font-semibold tracking-wide text-muted uppercase">
            ARGUS is unsure about these · {gray.length}
          </h2>
          {gray.map((c) => {
            const index = k++;
            return (
              <IncidentCard
                key={c.id ?? c.title}
                card={c}
                form={phone ? "phone" : "compact"}
                now={now}
                keys={keyRefs[index]}
                titleRef={(el) => {
                  titles.current[index] = el;
                }}
              />
            );
          })}
        </section>
      )}
      <Handled data={data} />
      <Approvals />
    </div>
  );
}

/** `/`: Today when the server serves it, else today's Home unchanged (§2.4, T-16). */
export function TodayOrHome() {
  const today = useQuery(todayOptions());
  if (today.isPending) return <Skeleton />;
  if (today.isError) {
    return (
      <>
        <h1 className="m-0 text-2xl font-semibold">Today</h1>
        <div role="alert" className="flex flex-col items-start gap-2 rounded-control border border-danger/40 bg-danger-soft px-3 py-2 text-sm text-danger" data-testid="today-error">
          <p className="m-0">Today could not load. Nothing was changed.</p>
          <Button size="sm" onClick={() => void today.refetch()}>
            Try again
          </Button>
        </div>
      </>
    );
  }
  return (
    <>
      <SystemBanner />
      {!today.data.served || today.data.today.mode === "shadow" ? <Home /> : <Today data={today.data.today} />}
    </>
  );
}

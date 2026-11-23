import { Dialog } from "@base-ui/react/dialog";
import { teamName } from "../lib/site";
import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useCallback, useRef, useState, type ReactNode } from "react";
import { listCases, listInvestigations } from "../client/sdk.gen";
import type { CaseRowOut } from "../client/types.gen";
import { DIRECTORY_ACCOUNT, DirectoryCard, useDirectory } from "./DirectoryCard";
import { EntityOpener, PriorityBadge } from "./incident/Parts";
import { UntrustedText } from "./UntrustedText";
import { Button } from "./ui/button";
import { unwrap } from "../lib/call";
import { engineOf, entityKind, isIp, nounFor, stateWords, type EngineObject } from "../lib/engine";
import { count, plural } from "../lib/format";
import { entityNotesOptions } from "../lib/queries";
import { parse } from "../lib/time";
import { dayAndTime } from "../lib/when";

export type EntityKind = "device" | "account" | "site" | "outside";

/** What the incidents count is (§9.6, without A11): `GET /cases?q=` matches titles only, so it never says "in 0 incidents". */
export const TITLE_NAMES = "Incidents whose title names it";

export const coverage = (): string => `ARGUS keeps alert detail for the last 5 days, and every incident and decision. It sees alerts, not all traffic: for raw logs use Kibana Discover (ask the ${teamName()} lead).`;


/** The API's kind for an entity (§9.6): an address is `ip`, a device's name `host`, an account `user`, a site `domain`. */
export function apiKind(kind: EntityKind, value: string): "ip" | "host" | "user" | "domain" {
  if (kind === "account") return "user";
  if (kind === "site") return "domain";
  if (kind === "outside") return isIp(value) ? "ip" : "domain";
  return isIp(value) ? "ip" : "host";
}

export function useEntity(kind: EntityKind, value: string) {
  const k = apiKind(kind, value);
  const incidents = useQuery({ queryKey: ["entity", "cases", value], queryFn: () => unwrap(listCases({ query: { view: "all", q: value, limit: 25 } })), staleTime: 30_000 });
  const groups = useQuery({ queryKey: ["entity", "groups", k, value], queryFn: () => unwrap(listInvestigations({ query: { view: "all", kind: k, value, limit: 50 } })), staleTime: 30_000 });
  const notes = useQuery(entityNotesOptions(k, value));
  return { k, incidents, groups, notes };
}

export function IncidentLine({ c }: { c: CaseRowOut }) {
  return (
    <li className="flex min-h-9 items-center gap-2 border-b border-border text-sm">
      <PriorityBadge engine={engineOf((c as unknown as { engine?: unknown }).engine)} />
      <Link to="/incidents/$id" params={{ id: c.id }} className="min-w-0 flex-1 truncate">
        #{c.number} · {stateWords({ state: c.state, number: null })} · <UntrustedText value={c.title} limits={{ maxChars: 160, maxLines: 1 }} />
      </Link>
    </li>
  );
}

function DrawerBody({ o, onClose }: { o: EngineObject; onClose: () => void }) {
  const kind = entityKind(o);
  const { incidents, groups, notes } = useEntity(kind, o.label);
  const inc = incidents.data?.items ?? [];
  const g = groups.data?.items ?? [];
  const last = g.map((x) => parse(x.last_event_at)).filter((d): d is Date => d !== null).sort((a, b) => b.getTime() - a.getTime())[0];
  const directory = useDirectory();
  return (
    <>
      <div className="flex items-start justify-between gap-2">
        <Dialog.Title className="m-0 text-lg font-semibold break-all">
          <span className="text-muted">{nounFor(o)}</span> <UntrustedText value={o.label} limits={{ maxChars: 120, maxLines: 1 }} />
        </Dialog.Title>
        <Dialog.Close render={<Button size="sm" variant="ghost" aria-label="Close" />}>✕</Dialog.Close>
      </div>
      <p className="m-0 text-sm text-muted">{coverage()}</p>
      {kind === "account" && directory !== null && DIRECTORY_ACCOUNT.test(o.label) && (
        <section aria-label="Who this is" className="flex flex-col gap-1 text-sm" data-testid="drawer-directory">
          <h3 className="m-0 text-sm font-semibold">Who this is (from {directory})</h3>
          <DirectoryCard account={o.label} />
        </section>
      )}
      <section aria-label="What ARGUS knows" className="flex flex-col gap-1 text-sm">
        <h3 className="m-0 text-sm font-semibold">What ARGUS knows (from alert groups)</h3>
        <ul className="m-0 flex list-none flex-col gap-0.5 p-0">
          <li>
            {count(g.length)} {plural(g.length, "alert group")} in the last 5 days
          </li>
          <li>{count(g.reduce((n, x) => n + x.alert_count, 0))} alerts</li>
          <li>{last ? `Last seen ${dayAndTime(last)}` : "Not seen in the last 5 days"}</li>
          <li>
            {TITLE_NAMES}: {count(inc.length)}
            {incidents.data?.has_more ? "+" : ""}
          </li>
          <li>Notes: {notes.data?.items.length ?? 0}</li>
        </ul>
      </section>
      {inc.length > 0 && (
        <section aria-label="Newest incidents" className="flex flex-col gap-1">
          <h3 className="m-0 text-sm font-semibold">Newest incidents</h3>
          <ul className="m-0 list-none p-0">
            {inc.slice(0, 3).map((c) => (
              <IncidentLine key={c.id} c={c} />
            ))}
          </ul>
        </section>
      )}
      <Link to="/entities/$kind/$value" params={{ kind, value: o.label }} onClick={onClose} className="inline-flex min-h-8 items-center self-start rounded-control border border-border-strong px-3 text-sm text-text no-underline hover:bg-surface-2">
        Open full page
      </Link>
    </>
  );
}

/**
 * The entity drawer (§9.5): a 420 px side sheet (full screen on a phone) with what ARGUS knows and
 * the three newest incidents, and a way to the full page. Esc closes it; the focus goes back to
 * the chip that opened it.
 */
export function EntityDrawerProvider({ children }: { children: ReactNode }) {
  const [open, setOpen] = useState<EngineObject | null>(null);
  const from = useRef<HTMLElement | null>(null);
  const opener = useCallback((o: EngineObject, el: HTMLElement) => {
    from.current = el;
    setOpen(o);
  }, []);
  return (
    <EntityOpener.Provider value={opener}>
      {children}
      <Dialog.Root open={open !== null} onOpenChange={(next) => !next && setOpen(null)}>
        <Dialog.Portal>
          <Dialog.Backdrop className="fixed inset-0 z-40 bg-black/30" />
          <Dialog.Popup finalFocus={() => from.current ?? true} data-testid="entity-drawer" className="fixed inset-0 z-50 flex flex-col gap-3 overflow-auto border-l border-border bg-raised p-4 text-text shadow-card sm:inset-y-0 sm:right-0 sm:left-auto sm:w-[420px]">
            {open && <DrawerBody o={open} onClose={() => setOpen(null)} />}
          </Dialog.Popup>
        </Dialog.Portal>
      </Dialog.Root>
    </EntityOpener.Provider>
  );
}

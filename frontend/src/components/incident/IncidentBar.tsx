import { Link } from "@tanstack/react-router";
import { useEffect, useId, useRef, useState, type ReactNode } from "react";
import type { CaseActionStateOut, CaseDetail, ReportVerdict } from "../../client/types.gen";
import { reasonLabel } from "../../lib/cases";
import { cn } from "../../lib/cn";
import type { Alternative, Engine } from "../../lib/engine";
import { callText } from "../../lib/incident";
import { can, useSession } from "../../lib/session";
import { parse } from "../../lib/time";
import { shortDay } from "../../lib/when";
import { ActionForm, MergeForm } from "../cases/CaseActions";
import { NoticeForm, WithdrawForm } from "../cases/KnownSections";
import { PossibleButtons, type DecideKeys } from "../decide/Decide";
import { targetOfDetail } from "../decide/target";
import { UntrustedText } from "../UntrustedText";
import { Button } from "../ui/button";
import { CisoDraftDialog, cisoSent, SendToKibanaDialog } from "./Ciso";
import { PriorityBadge } from "./Parts";

type Panel = string | null; // an action's form under the bar
type Dialog = "kibana" | "ciso" | null;

export type BarState = "possible" | "readonly" | "open" | "mine" | "other" | "told" | "contained" | "closed";

/** Which row of §7.1's table the bar is in. */
export function barState(d: CaseDetail, me: string | null, mayReview: boolean): BarState {
  const c = d.case;
  if (!mayReview) return "readonly";
  if (c.state === "suspected") return "possible";
  if (c.state === "closed") return "closed";
  if (c.notified_at !== null) return "told";
  if (c.state === "contained") return "contained";
  if (c.owner === null) return "open";
  return c.owner.username === me ? "mine" : "other";
}

const WORDS: Record<string, string> = {
  take: "Take it",
  assign: "Assign ▾",
  release: "Release",
  contain: "Mark contained",
  request_closure: "Request closure",
  merge: "Merge into…",
  reopen: "Reopen",
  notify: "Record that the owner was told…",
  withdraw_notice: "Withdraw notice",
};

interface Item {
  key: string;
  label: string;
  enabled: boolean;
  why: string | null;
  run: () => void;
}

/** "More ▾": a small menu of the remaining actions; a disabled one says why. */
function More({ items, touch }: { items: Item[]; touch: boolean }) {
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
  if (items.length === 0) return null;
  return (
    <div ref={box} className="relative inline-block">
      <Button className={cn(touch && "min-h-11")} aria-haspopup="menu" aria-expanded={open} aria-controls={open ? id : undefined} onClick={() => setOpen(!open)}>
        More ▾
      </Button>
      {open && (
        <div
          id={id}
          role="menu"
          aria-label="More actions"
          className="absolute right-0 z-30 mt-1 flex w-[min(22rem,calc(100vw-2rem))] flex-col rounded-card border border-border bg-surface p-1 text-text shadow-card sm:left-0 sm:right-auto"
          onKeyDown={(e) => {
            if (e.key === "Escape") {
              e.stopPropagation();
              setOpen(false);
            }
          }}
        >
          {items.map((it) => (
            <button
              key={it.key}
              type="button"
              role="menuitem"
              aria-disabled={!it.enabled || undefined}
              className={cn("flex flex-col items-start rounded-control px-3 py-2 text-left text-sm hover:bg-surface-2", !it.enabled && "cursor-not-allowed opacity-70")}
              onClick={() => {
                if (!it.enabled) return;
                setOpen(false);
                it.run();
              }}
            >
              <span className="font-medium">{it.label}</span>
              {!it.enabled && it.why && (
                <span className="text-muted">
                  <UntrustedText value={it.why} limits={{ maxChars: 240, maxLines: 3 }} />
                </span>
              )}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

/**
 * The incident page's sticky decision bar (docs/p4f-ui-spec.md §7.1): ARGUS's call in words and the
 * band, then the buttons of the incident's state, the primary first; each button's state and its
 * reason come from the server (`decision` on a possible incident, `actions` otherwise). Sticky
 * under the header on a desktop, shrinking to one line once the header scrolls out; docked at the
 * bottom on a phone.
 */
export function IncidentBar({ detail, engine, keys, reportConfirmable, verdict = null, alternatives = [], headerId, onConflict }: { detail: CaseDetail; engine: Engine | null; keys: DecideKeys; reportConfirmable: boolean; verdict?: Pick<ReportVerdict, "outcome"> | null; alternatives?: readonly Alternative[]; headerId: string; onConflict?: () => void }) {
  const session = useSession();
  const me = session.data?.user.username ?? null;
  const state = barState(detail, me, can(session.data, "review"));
  const [panel, setPanel] = useState<Panel>(null);
  const [dialog, setDialog] = useState<Dialog>(null);
  const [compact, setCompact] = useState(false);
  const whyId = useId();
  const c = detail.case;
  const target = { ...targetOfDetail(detail), alternatives };
  const sent = cisoSent(detail);

  useEffect(() => {
    const head = document.getElementById(headerId);
    if (head === null || typeof IntersectionObserver === "undefined") return;
    const seen = new IntersectionObserver(([entry]) => setCompact(entry !== undefined && !entry.isIntersecting));
    seen.observe(head);
    return () => seen.disconnect();
  }, [headerId]);

  const act = (name: CaseActionStateOut["action"]): CaseActionStateOut | undefined => detail.actions.find((a) => a.action === name) ?? (name === "notify" ? detail.known?.notify : name === "withdraw_notice" ? detail.known?.withdraw_notice : undefined);
  const item = (name: CaseActionStateOut["action"], label = WORDS[name] ?? name): Item | null => {
    const a = act(name);
    return a ? { key: name, label, enabled: a.enabled, why: a.why_not, run: () => setPanel(name) } : null;
  };
  const kibana: Item = { key: "kibana", label: "Send to Kibana…", enabled: reportConfirmable && !c.in_kibana, why: c.in_kibana ? "It is in Kibana already." : "The incident report is not ready to confirm yet: see the Report tab.", run: () => setDialog("kibana") };
  const ciso: Item = { key: "ciso", label: "Report to the CISO…", enabled: true, why: null, run: () => setDialog("ciso") };
  const touch = false;
  const button = (it: Item | null, primary = false): ReactNode =>
    it === null ? null : (
      <Button key={it.key} variant={primary ? "primary" : "secondary"} aria-disabled={!it.enabled} aria-describedby={it.enabled ? undefined : whyId} onClick={() => it.enabled && it.run()}>
        {it.label}
      </Button>
    );
  const list = (...xs: (Item | null)[]) => xs.filter((x): x is Item => x !== null);

  let lead: ReactNode = null;
  let buttons: ReactNode = null;
  let disabledWhy: string[] = [];
  const shown = (main: Item | null, side: (Item | null)[], more: (Item | null)[]) => {
    const all = list(main, ...side);
    disabledWhy = all.filter((x) => !x.enabled && x.why).map((x) => x.why as string);
    buttons = (
      <>
        {button(main, true)}
        {side.map((s) => button(s))}
        <More items={list(...more)} touch={touch} />
      </>
    );
  };

  switch (state) {
    case "readonly":
      lead = <span>A person with review access decides this.</span>;
      break;
    case "possible": {
      const d = detail.decision;
      const confirmOff = d && !d.confirm.enabled ? { why: d.confirm.why_not ?? "", id: whyId } : null;
      const dismissOff = d && !d.dismiss.enabled ? { why: d.dismiss.why_not ?? "", id: whyId } : null;
      disabledWhy = [confirmOff?.why, dismissOff?.why !== confirmOff?.why ? dismissOff?.why : null].filter((x): x is string => typeof x === "string" && x !== "");
      const mergeOn = d?.merge.enabled ?? false;
      buttons = (
        <PossibleButtons
          target={target}
          confirmRef={keys.confirm}
          dismissRef={keys.dismiss}
          confirmDisabled={confirmOff}
          dismissDisabled={dismissOff}
          onDuplicate={mergeOn ? () => setPanel("duplicate") : undefined}
          onConflict={onConflict}
          checkLink={
            <Link to="/incidents/$id" params={{ id: c.id }} search={{ tab: "evidence" }} className="text-accent">
              Ask ARGUS to check
            </Link>
          }
        >
          <Button aria-disabled={!mergeOn} aria-describedby={mergeOn ? undefined : whyId} onClick={() => mergeOn && setPanel("merge")}>
            Merge into…
          </Button>
        </PossibleButtons>
      );
      break;
    }
    case "open":
      shown(item("take"), [item("assign")], [kibana, ciso, item("contain"), item("request_closure"), item("merge")]);
      break;
    case "mine": {
      const notify = item("notify");
      const next = kibana.enabled ? kibana : sent === null ? ciso : notify;
      const rest = [kibana, ciso, notify].filter((x) => x !== next);
      shown(next, [], [...rest, item("contain"), item("request_closure"), item("release"), item("merge")]);
      break;
    }
    case "other":
      lead = (
        <span>
          Taken by <UntrustedText value={c.owner?.display_name ?? ""} limits={{ maxChars: 60, maxLines: 1 }} />
        </span>
      );
      shown(null, can(session.data, "manage_cases") ? [item("assign")] : [], [kibana, ciso, item("contain"), item("request_closure"), item("merge")]);
      break;
    case "told": {
      const at = parse(c.notified_at);
      lead = <span>Owner told {at ? shortDay(at) : ""} · ARGUS watches quietly</span>;
      shown(item("request_closure"), [], [item("notify", "Re-notify"), item("withdraw_notice"), kibana, ciso]);
      break;
    }
    case "contained":
      shown(item("request_closure"), [], [kibana, ciso, item("merge")]);
      break;
    case "closed": {
      const at = parse(c.closed_at);
      lead = (
        <span>
          Closed {at ? shortDay(at) : ""}: {reasonLabel(c.closure_reason)}
        </span>
      );
      shown(can(session.data, "reopen") ? item("reopen") : null, [], []);
      break;
    }
  }

  const form = panel === null ? null : panel === "duplicate" ? <MergeForm detail={detail} onDone={() => setPanel(null)} label="It duplicates incident number" hint="This possible incident is merged into it: its alert groups move there." /> : panel === "merge" && state === "possible" ? <MergeForm detail={detail} onDone={() => setPanel(null)} /> : panel === "notify" ? <NoticeForm detail={detail} onDone={() => setPanel(null)} /> : panel === "withdraw_notice" ? <WithdrawForm detail={detail} onDone={() => setPanel(null)} /> : <ActionForm detail={detail} action={panel} onDone={() => setPanel(null)} />;

  return (
    <section
      aria-label="Decision"
      data-testid="decision-bar"
      data-state={state}
      data-compact={compact || undefined}
      className="fixed inset-x-0 bottom-14 z-20 flex max-h-[70vh] flex-col gap-2 overflow-auto border-t border-border-strong bg-surface-2 px-4 py-2 shadow-card sm:sticky sm:top-0 sm:bottom-auto sm:max-h-none sm:overflow-visible sm:rounded-card sm:border"
    >
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
        {compact && (
          <span className="hidden min-w-0 max-w-[40%] items-center gap-2 truncate text-sm font-semibold sm:inline-flex">
            <PriorityBadge engine={engine} />
            <span className="truncate">
              <UntrustedText value={c.title} limits={{ maxChars: 90, maxLines: 1 }} />
            </span>
          </span>
        )}
        <p className="m-0 text-sm font-medium" data-testid="bar-call">
          {callText(detail, engine, verdict)}
        </p>
        {lead && <p className="m-0 text-sm text-muted">{lead}</p>}
        <div className="flex flex-wrap items-center gap-2">{buttons}</div>
      </div>
      {disabledWhy.length > 0 && (
        <p id={whyId} className="m-0 max-w-prose text-sm text-muted">
          {[...new Set(disabledWhy)].map((w, i) => (
            <span key={i} className="block">
              <UntrustedText value={w} limits={{ maxChars: 400, maxLines: 4 }} />
            </span>
          ))}
        </p>
      )}
      {form && <div className="rounded-card border border-border bg-surface p-3">{form}</div>}
      <SendToKibanaDialog detail={detail} open={dialog === "kibana"} onOpenChange={(o) => setDialog(o ? "kibana" : null)} />
      <CisoDraftDialog detail={detail} engine={engine} open={dialog === "ciso"} onOpenChange={(o) => setDialog(o ? "ciso" : null)} />
    </section>
  );
}

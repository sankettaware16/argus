import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { getCost, getHealth } from "../client/sdk.gen";
import { Badge, type Tone } from "../components/ui/badge";
import { BACKGROUND } from "../lib/api";
import { useCan } from "../components/investigation/actions";
import { useSession } from "../lib/session";
import { systemDot, type SystemDot as Dot } from "../lib/system";
import { clock, sinceWords } from "../lib/when";
import { useEffect, useId, useRef, useState } from "react";
import { ago } from "../lib/time";

const MONEY = new Intl.NumberFormat("en-US", { style: "currency", currency: "USD" });

/** The AI spend this month against the cap (D-094), polled every 30 s in the background. */
export function CostStatus() {
  const cost = useQuery({
    queryKey: ["cost"],
    queryFn: async () => (await getCost({ headers: BACKGROUND, throwOnError: true })).data,
    refetchInterval: 30_000,
  });
  if (!cost.data) {
    return <span className="text-sm text-muted">AI cost: {cost.isError ? "not available" : "loading"}</span>;
  }
  const c = cost.data;
  const near = c.month_usd >= c.paid_until_usd;
  return (
    <Link to="/metrics" className="flex flex-wrap items-center gap-x-2 gap-y-1 text-sm text-text no-underline hover:underline" title={`Paid AI until ${MONEY.format(c.paid_until_usd)} this month, then the free providers; read ${ago(new Date(c.at))}`}>
      <span className="font-medium">AI cost</span>
      <meter
        className="h-2 w-16"
        min={0}
        max={c.cap_usd}
        low={c.cap_usd * 0.5}
        high={c.paid_until_usd}
        optimum={0}
        value={Math.min(c.month_usd, c.cap_usd)}
        aria-label="AI cost this month against the monthly cap"
      />
      <span>
        {MONEY.format(c.month_usd)} of {MONEY.format(c.cap_usd)} this month · today {MONEY.format(c.today_usd)}
        {c.daily_cap_usd != null && <> of {MONEY.format(c.daily_cap_usd)}</>} ({c.calls_today} {c.calls_today === 1 ? "call" : "calls"})
      </span>
      {c.stopped && <Badge tone="danger">AI stopped</Badge>}
      {!c.stopped && near && <Badge tone="warn">free providers now</Badge>}
    </Link>
  );
}

/** The SIEM's state in words (the status bar and the Health page). */
export const SIEM: Record<string, [Tone, string]> = {
  normal: ["ok", "normal"],
  caution: ["warn", "caution: ARGUS reads less"],
  degraded: ["warn", "degraded: ARGUS reads very little"],
  stop: ["danger", "stopped: ARGUS reads nothing"],
};

/** The Kibana read-back in words, from its newest cycle. */
export const SYNC: Record<string, [Tone, string]> = {
  none: ["neutral", "not running yet"],
  ok: ["ok", "in sync"],
  partial: ["warn", "partly read"],
  failed: ["danger", "failing"],
  late: ["warn", "late"],
};

function useHealth() {
  return useQuery({
    queryKey: ["health"],
    queryFn: async () => (await getHealth({ headers: BACKGROUND, throwOnError: true })).data,
    refetchInterval: 60_000,
  });
}

const DOT_TONE: Record<Dot["state"], string> = { ok: "bg-ok", caution: "bg-warn", problem: "bg-danger", setup: "bg-border-strong" };

/** "today 4:10 PM": the banner's time words. */
function at(d: Date): string {
  const words = sinceWords(d);
  return words.startsWith("today") ? clock(d) : `${words} ${clock(d)}`;
}

/**
 * The header's system dot (docs/p4f-ui-spec.md §4.2): always a word with the dot ("● OK", "●
 * Caution", "● Problem"), opening to one line per part. The AI cost is an admin's, in it only for
 * them; it left the header.
 */
export function SystemDot() {
  const health = useHealth();
  const pending = useSession().data?.setup_pending === true;
  const admin = useCan("admin");
  const [open, setOpen] = useState(false);
  const id = useId();
  const box = useRef<HTMLDivElement>(null);
  const dot = systemDot(health.data, new Date(), at, pending);
  useEffect(() => {
    if (!open) return;
    const away = (e: MouseEvent) => {
      if (box.current && !box.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", away);
    return () => document.removeEventListener("mousedown", away);
  }, [open]);
  return (
    <div ref={box} className="relative text-sm" data-testid="system-dot" data-state={dot.state}>
      <button
        type="button"
        aria-expanded={open}
        aria-controls={open ? id : undefined}
        onClick={() => setOpen(!open)}
        onKeyDown={(e) => e.key === "Escape" && setOpen(false)}
        className="inline-flex min-h-8 cursor-pointer items-center gap-1.5 rounded-control border-0 bg-transparent px-2 text-sm text-text hover:bg-surface-2"
      >
        <span aria-hidden="true" className={`inline-block size-2 rounded-full ${DOT_TONE[dot.state]}`} />
        <span>{health.isError && !pending ? "Not known" : dot.word}</span>
        <span className="sr-only"> — the system's state</span>
      </button>
      {open && (
        <div id={id} className="absolute right-0 z-30 mt-1 flex w-[min(24rem,calc(100vw-2rem))] flex-col gap-2 rounded-card border border-border bg-surface p-3 shadow-card" onKeyDown={(e) => e.key === "Escape" && setOpen(false)}>
          <ul className="m-0 flex list-none flex-col gap-1 p-0" data-testid="system-parts">
            {dot.parts.map((p) => (
              <li key={p.name}>
                <span className="font-medium">{p.name}:</span> {p.words}
              </li>
            ))}
          </ul>
          {admin && <CostStatus />}
          <Link to="/health" className="text-sm">
            System health
          </Link>
        </div>
      )}
    </div>
  );
}

/** Today's banner (§4.2): only in the Problem state, in the queue's terms. */
export function SystemBanner() {
  const health = useHealth();
  const pending = useSession().data?.setup_pending === true;
  const dot = systemDot(health.data, new Date(), at, pending);
  if (dot.banner === null) return null;
  return (
    <p role="status" data-testid="system-banner" className="m-0 rounded-control border border-danger/40 bg-danger-soft px-3 py-2 text-sm text-danger">
      <span aria-hidden="true">⚠ </span>
      {dot.banner} <Link to="/health">What ARGUS knows</Link>
    </p>
  );
}

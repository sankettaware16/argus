import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { getCost, getHealth } from "../client/sdk.gen";
import { Badge, type Tone } from "../components/ui/badge";
import { BACKGROUND } from "../lib/api";
import { ago, ist, parse, utc } from "../lib/time";

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

/** The SIEM's health as ARGUS last measured it (D-021), polled every minute in the background. */
export function SiemStatus() {
  const health = useQuery({
    queryKey: ["health"],
    queryFn: async () => (await getHealth({ headers: BACKGROUND, throwOnError: true })).data,
    refetchInterval: 60_000,
  });
  if (!health.data) {
    return <span className="text-sm text-muted">SIEM: {health.isError ? "not available" : "loading"}</span>;
  }
  const h = health.data;
  const probed = parse(h.siem_probed_at);
  const [tone, word] = SIEM[h.siem_state] ?? (["neutral", "unknown"] as [Tone, string]);
  const when = probed ? `checked ${ago(probed)} (${ist(probed)}; ${utc(probed)})` : "never checked";
  return (
    <Link to="/health" className="flex flex-wrap items-center gap-x-2 gap-y-1 text-sm text-text no-underline hover:underline" title={when}>
      <span className="font-medium">SIEM</span>
      <Badge tone={tone}>{word}</Badge>
      <span className="text-muted">{probed ? `checked ${ago(probed)}` : "not checked yet"}</span>
    </Link>
  );
}

/** The Kibana read-back in words, from its newest cycle. */
export const SYNC: Record<string, [Tone, string]> = {
  none: ["neutral", "not running yet"],
  ok: ["ok", "in sync"],
  partial: ["warn", "partly read"],
  failed: ["danger", "failing"],
  late: ["warn", "late"],
};

/** Whether ARGUS reads Kibana's cases back (argus-kibana-sync), from the health poll. */
export function SyncStatus() {
  const health = useQuery({
    queryKey: ["health"],
    queryFn: async () => (await getHealth({ headers: BACKGROUND, throwOnError: true })).data,
    refetchInterval: 60_000,
  });
  const sync = health.data?.kibana_sync;
  if (!sync) {
    return <span className="text-sm text-muted">Kibana sync: {health.isError ? "not available" : "loading"}</span>;
  }
  const [tone, word] = SYNC[sync.state] ?? (["neutral", "unknown"] as [Tone, string]);
  const last = parse(sync.last_cycle_at);
  const complete = parse(sync.last_complete_at);
  const title = last
    ? `Last read-back ${ago(last)} (${ist(last)}; ${utc(last)}): ${sync.last_outcome}` +
      (sync.last_reason ? ` (${sync.last_reason})` : "") +
      (complete ? `; last complete ${ago(complete)}` : "; none complete yet")
    : "No read-back of Kibana's cases recorded yet: it runs as argus-kibana-sync once Kibana is set up";
  return (
    <Link to="/health" className="flex flex-wrap items-center gap-x-2 gap-y-1 text-sm text-text no-underline hover:underline" title={title}>
      <span className="font-medium">Kibana sync</span>
      <Badge tone={tone}>{word}</Badge>
      {last && <span className="text-muted">read {ago(last)}</span>}
    </Link>
  );
}

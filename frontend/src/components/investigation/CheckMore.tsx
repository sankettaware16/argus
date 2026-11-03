import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useEffect, useId, useMemo, useState } from "react";
import type { InvestigationCheckOut } from "../../client/types.gen";
import { useAnnounce } from "../../lib/announce";
import { entityProblem, entityShape } from "../../lib/checkEntity";
import { count, plural, serverTime } from "../../lib/format";
import { useGuard } from "../../lib/guard";
import { checksOptions, pollChecks } from "../../lib/queries";
import { ConfirmDialog } from "../ConfirmDialog";
import { Loading, Problem } from "../Problem";
import { Time } from "../Time";
import { UntrustedText } from "../UntrustedText";
import { Badge, type Tone } from "../ui/badge";
import { Button } from "../ui/button";
import { Field, Select, TextInput } from "../ui/field";
import { NeedsCapability, useCan } from "./actions";

const STATUS_TONE: Record<string, Tone> = { queued: "info", running: "info", done: "ok", refused: "warn", failed: "danger" };

export const CHECK_POLL_MS = 15_000;

/** While a check waits or runs, read the list again every 15 s (a background request: it never keeps the session alive); a refusal stops the asking. */
function useChecksPoll(id: string, waiting: boolean): void {
  const queries = useQueryClient();
  useEffect(() => {
    if (!waiting) return;
    let stopped = false;
    const timer = setInterval(() => {
      if (stopped) return;
      pollChecks(id).then(
        (fresh) => queries.setQueryData(["checks", id], fresh),
        () => {
          stopped = true;
          clearInterval(timer);
        },
      );
    }, CHECK_POLL_MS);
    return () => {
      stopped = true;
      clearInterval(timer);
    };
  }, [id, waiting, queries]);
}

function Record({ c, investigationId }: { c: InvestigationCheckOut; investigationId: string }) {
  const eids = c.lines.map((l) => l.eid).filter((e): e is string => e !== null);
  return (
    <li className="flex flex-col gap-1 border-b border-border py-2 last:border-b-0" data-testid="check-record">
      <p className="m-0 text-sm">
        <strong>{c.words}</strong> for{" "}
        <span className="font-mono">
          <UntrustedText value={c.entity} limits={{ maxChars: 253, maxLines: 1 }} />
        </span>{" "}
        <Badge tone={STATUS_TONE[c.status] ?? "neutral"}>{c.status_words}</Badge>
      </p>
      <p className="m-0 text-xs text-muted">
        Asked by <UntrustedText value={c.requested_by ?? "ARGUS"} limits={{ maxChars: 60, maxLines: 1 }} /> at <Time value={c.requested_at} />, about version {c.version}.
        {c.finished_at && (
          <>
            {" "}
            Finished <Time value={c.finished_at} />.
          </>
        )}
      </p>
      {c.status === "done" && (
        <p className="m-0 text-sm">
          {c.requests === null
            ? "It left no record of its cost."
            : `It sent ${count(c.requests)} ${plural(c.requests, "request")} to the SIEM (${count(c.heavy_requests ?? 0)} heavy), ${serverTime(c.server_ms ?? 0)} of SIEM time.`}{" "}
          {eids.length > 0 && (
            <>
              Its answer is {eids.join(", ")} in{" "}
              <Link to="/investigations/$id" params={{ id: investigationId }} search={{ tab: "report" }}>
                the report
              </Link>
              .
            </>
          )}{" "}
          {c.assessed ? "An assessment has read it." : "Not yet assessed: ARGUS reads this answer in its next assessment."}
        </p>
      )}
      {c.lines.length > 0 && (
        <ul className="m-0 pl-5 text-xs text-muted">
          {c.lines.map((l, i) => (
            <li key={i}>
              {l.eid ?? "not asked"} · {l.template}
              {l.status ? ` · ${l.status}` : ""}
              {l.server_ms !== null ? ` · ${serverTime(l.server_ms)}` : ""}
              {l.sent === false ? " · answered from what ARGUS already held" : ""}
              {l.why_not ? ` · ${l.why_not}` : ""}
            </li>
          ))}
        </ul>
      )}
      {c.why_not && (c.status === "refused" || c.status === "failed") && (
        <p className="m-0 text-sm">
          Why: <UntrustedText value={c.why_not} limits={{ maxChars: 300, maxLines: 3 }} />
        </p>
      )}
    </li>
  );
}

/**
 * "Check more" (plan §5 Q-B3): one approved check on one address or domain, asked for by name,
 * queued for ARGUS's service, with its cost said before and its record shown after. The request
 * names the version of the investigation the person looked at, and is shown whole before it is sent.
 */
export function CheckMore({ investigationId, version, suggestions = [] }: { investigationId: string; version: number; suggestions?: readonly string[] }) {
  const can = useCan("review");
  const checks = useQuery(checksOptions(investigationId));
  useChecksPoll(investigationId, checks.data?.items.some((c) => c.status === "queued" || c.status === "running") ?? false);
  const queries = useQueryClient();
  const { announce } = useAnnounce();
  const id = useId();
  const [template, setTemplate] = useState("");
  const [entity, setEntity] = useState("");
  const [open, setOpen] = useState(false);
  const chosen = checks.data?.templates.find((t) => t.template === template);
  const problem = chosen === undefined ? "Choose a check first." : entityProblem(entity, chosen.takes);
  const request = useMemo(
    () => ({ method: "POST" as const, path: `/api/v1/investigations/${investigationId}/checks`, body: { template, entity: entity.trim(), seen_version: version } }),
    [investigationId, template, entity, version],
  );
  const offered = useMemo(() => [...new Set(suggestions.filter((v) => entityShape(v) !== null))], [suggestions]);
  const limits = checks.data?.limits;
  const used = limits !== undefined && limits.open_now >= limits.open_per_person;
  const guard = useGuard(used ? `You have ${limits.open_per_person} checks waiting already: wait for one to finish.` : problem);
  return (
    <section aria-label="Check more" id="check-more" className="flex flex-col gap-2">
      <h3 className="m-0 text-base font-semibold">Check more</h3>
      <p className="m-0 max-w-prose text-sm text-muted">
        Ask ARGUS to look at one more thing in the SIEM: one approved check on one address or domain. It is queued and run by ARGUS&apos;s service when the SIEM is healthy;
        the answer joins this investigation&apos;s report under its E-number.
      </p>
      {checks.isPending && <Loading what="the checks" />}
      {checks.isError && <Problem error={checks.error} what="The checks" onRetry={() => void checks.refetch()} />}
      {checks.data &&
        (can ? (
          <form
            className="grid gap-3 sm:grid-cols-[minmax(0,22rem)_minmax(0,16rem)]"
            aria-label="Ask for a check"
            onSubmit={(e) => {
              e.preventDefault();
              guard.press(() => setOpen(true))();
            }}
          >
            <Field label="Check" htmlFor={`${id}-template`}>
              <Select id={`${id}-template`} value={template} onChange={(e) => setTemplate(e.target.value)}>
                <option value="">Choose a check…</option>
                {checks.data.templates.map((t) => (
                  <option key={t.template} value={t.template}>
                    {t.words} ({t.heavy ? "heavy" : "light"}; takes {t.takes_words})
                  </option>
                ))}
              </Select>
            </Field>
            <Field label="Address or domain" htmlFor={`${id}-entity`}>
              <TextInput id={`${id}-entity`} value={entity} maxLength={253} list={offered.length > 0 ? `${id}-list` : undefined} onChange={(e) => setEntity(e.target.value)} autoComplete="off" />
              {offered.length > 0 && (
                <datalist id={`${id}-list`}>
                  {offered.map((s) => (
                    <option key={s} value={s} />
                  ))}
                </datalist>
              )}
            </Field>
            {chosen && (
              <p className="m-0 text-sm sm:col-span-2" data-testid="check-cost">
                <strong>What it costs.</strong> {chosen.cost_words}
              </p>
            )}
            {limits && (
              <p className="m-0 text-xs text-muted sm:col-span-2">
                You have {count(limits.open_now)} of {count(limits.open_per_person)} checks waiting, and have asked for {count(limits.today)} of {count(limits.per_day)} today.
              </p>
            )}
            <div className="flex flex-wrap items-center gap-x-3 gap-y-1 sm:col-span-2">
              <Button type="submit" variant="primary" {...guard.props}>
                Review the request
              </Button>
              {guard.hint}
            </div>
          </form>
        ) : (
          <NeedsCapability what="asking for a check" capability="review" />
        ))}
      {chosen !== undefined && problem === null && (
        <ConfirmDialog
          open={open}
          onOpenChange={(next) => {
            setOpen(next);
            if (!next) void queries.invalidateQueries({ queryKey: ["checks", investigationId] });
          }}
          title={`Ask for: ${chosen.words}`}
          description={`It is asked about version ${version} of the investigation, under your name. ${chosen.cost_words}`}
          request={request}
          confirmLabel="Ask for this check"
          onSent={(sent) => {
            const result = (sent.data as { result?: string } | undefined)?.result;
            announce(result === "open" ? "The same check is waiting already." : "Queued. ARGUS runs it when the SIEM allows; this page checks for the answer by itself.", "ok");
            setEntity("");
          }}
        />
      )}
      {checks.data && (
        <>
          <h4 className="m-0 text-sm font-semibold">Checks people asked for</h4>
          {checks.data.items.length === 0 ? (
            <p className="m-0 text-sm text-muted">None yet.</p>
          ) : (
            <ul className="m-0 list-none p-0" aria-label="Checks people asked for">
              {checks.data.items.map((c) => (
                <Record key={c.id} c={c} investigationId={investigationId} />
              ))}
            </ul>
          )}
        </>
      )}
    </section>
  );
}

import { useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import type { CaseDetail, CaseSuggestionOut, WatchDayOut } from "../../client/types.gen";
import { useAnnounce } from "../../lib/announce";
import { count, plural } from "../../lib/format";
import { changedCase } from "../../lib/queries";
import { ConfirmDialog } from "../ConfirmDialog";
import { Time } from "../Time";
import { UntrustedText } from "../UntrustedText";
import { Badge, type Tone } from "../ui/badge";
import { Button } from "../ui/button";
import { useCan } from "../investigation/actions";

function Text({ value, max = 300, lines = 3 }: { value: string; max?: number; lines?: number }) {
  return <UntrustedText value={value} limits={{ maxChars: max, maxLines: lines }} />;
}

const KIND_WORDS: Record<CaseSuggestionOut["kind"], string> = {
  shared: "It shares an address or name with the case, but that one is used by many (a shared service), so ARGUS did not join it.",
  tie: "It matches this case and another equally, so ARGUS did not choose.",
  also: "It matches the case through one value only, so ARGUS left the decision to a person.",
};
const LINK_WORDS: Record<CaseSuggestionOut["link"], string> = { actor: "the case's host or account", c2: "the case's command-and-control address", indicator: "an indicator of the case" };

function Suggestion({ s, caseId }: { s: CaseSuggestionOut; caseId: string }) {
  const can = useCan("manage_cases");
  const [open, setOpen] = useState(false);
  const queries = useQueryClient();
  const { announce } = useAnnounce();
  const request = useMemo(() => ({ method: "POST" as const, path: `/api/v1/cases/${caseId}/suggestions/${s.id}/dismiss` }), [caseId, s.id]);
  return (
    <li className="flex flex-col gap-1 border-b border-border py-2 last:border-b-0" data-testid="suggestion">
      <p className="m-0 text-sm">
        <Link to="/alert-groups/$id" params={{ id: s.investigation_id }}>
          <Text value={s.rule_name ?? "(no rule name)"} max={120} lines={1} />
        </Link>{" "}
        <span className="text-muted">
          ({count(s.alert_count)} {plural(s.alert_count, "alert")}
          {s.severity ? `, ${s.severity}` : ""})
        </span>
      </p>
      <p className="m-0 text-sm text-muted">
        {KIND_WORDS[s.kind]} It matched through {LINK_WORDS[s.link]}
        {s.link_value && (
          <>
            {" "}
            <span className="font-mono">
              <Text value={s.link_value} max={200} lines={1} />
            </span>
          </>
        )}
        . Found <Time value={s.created_at} />.
      </p>
      <p className="m-0 text-xs text-muted">
        What ARGUS noted: <Text value={s.why} max={300} lines={3} />
      </p>
      {can && (
        <div>
          <Button size="sm" onClick={() => setOpen(true)}>
            Dismiss this suggestion
          </Button>
          <ConfirmDialog
            open={open}
            onOpenChange={(next) => {
              setOpen(next);
              if (!next) void changedCase(queries, caseId);
            }}
            title="Dismiss this suggestion"
            description="ARGUS stops suggesting this investigation for this case. Nothing about the case changes, and the investigation is not joined to it. The dismissal is kept in the audit trail under your name."
            request={request}
            confirmLabel="Dismiss"
            onSent={() => announce("Dismissed: ARGUS will not suggest it for this case again.", "ok")}
          />
        </div>
      )}
    </li>
  );
}

/** The investigations ARGUS found that may belong to the case and did not join (Q-C2). */
export function SuggestionsBlock({ detail }: { detail: CaseDetail }) {
  const shown = detail.suggestions;
  return (
    <section aria-label="Suggested members" className="flex flex-col gap-1">
      <h3 className="m-0 mt-2 text-base font-semibold">Suggested members</h3>
      {shown.length === 0 ? (
        <p className="m-0 text-sm text-muted">ARGUS has no investigation to suggest for this case.</p>
      ) : (
        <>
          <p className="m-0 max-w-prose text-sm text-muted">
            Investigations that may belong to this case. ARGUS did not join them by itself; a person decides. Open one to judge it, and dismiss a suggestion that does not belong. (Joining one to the case is done at the terminal for now.)
          </p>
          <ul className="m-0 list-none p-0" aria-label="Suggested members">
            {shown.map((s) => (
              <Suggestion key={s.id} s={s} caseId={detail.case.id} />
            ))}
          </ul>
          {detail.suggestions_total > shown.length && <p className="m-0 text-sm text-muted">{count(detail.suggestions_total - shown.length)} older suggestions are not shown.</p>}
        </>
      )}
    </section>
  );
}

const OUTCOME_WORDS = { active: "activity seen", quiet: "quiet", unverified: "could not be verified", not_checked: "not checked yet" } as const;
const OUTCOME_TONE: Record<string, Tone> = { active: "danger", quiet: "ok", unverified: "warn", not_checked: "neutral" };

function Day({ d }: { d: WatchDayOut }) {
  const proxy = Object.entries(d.proxy);
  return (
    <li className="flex flex-col gap-0.5 text-sm" data-testid="watch-day">
      <p className="m-0">
        <strong>{d.day}</strong>{" "}
        {d.alerts ? (
          <>
            ARGUS&apos;s own alerts: <Badge tone={OUTCOME_TONE[d.alerts] ?? "neutral"}>{OUTCOME_WORDS[d.alerts]}</Badge>
          </>
        ) : (
          <span className="text-muted">ARGUS&apos;s own alerts: no answer</span>
        )}
        {proxy.length > 0 && (
          <>
            {"; "}proxy logs:{" "}
            {proxy.map(([outcome, n], i) => (
              <span key={outcome}>
                {i > 0 && ", "}
                {count(n)} {plural(n, "address", "addresses")} <Badge tone={OUTCOME_TONE[outcome] ?? "neutral"}>{OUTCOME_WORDS[outcome as keyof typeof OUTCOME_WORDS] ?? outcome}</Badge>
              </span>
            ))}
          </>
        )}
      </p>
      {(d.alerts_reason || d.proxy_reasons.length > 0 || d.seen.length > 0) && (
        <ul className="m-0 list-none pl-4 text-xs text-muted">
          {d.alerts_reason && (
            <li>
              Alerts: <Text value={d.alerts_reason} max={300} lines={3} />
            </li>
          )}
          {d.seen.map((r, i) => (
            <li key={`seen-${i}`}>
              Seen: <Text value={r} max={300} lines={3} />
            </li>
          ))}
          {d.proxy_reasons.map((r, i) => (
            <li key={i}>
              Proxy logs: <Text value={r} max={300} lines={3} />
            </li>
          ))}
        </ul>
      )}
    </li>
  );
}

/** What the still-active watch can say about the case (Q-C2): when it last ran, the last days, quiet or not. */
export function WatchBlock({ detail }: { detail: CaseDetail }) {
  const w = detail.watch;
  if (w === null || w === undefined) return null;
  return (
    <section aria-label="The still-active watch" className="flex flex-col gap-1">
      <h3 className="m-0 mt-2 text-base font-semibold">The still-active watch</h3>
      <p className="m-0 max-w-prose text-sm text-muted">
        Once a day ARGUS asks whether a case is still active. A case can be called contained only when the last three whole UTC days were quiet. {w.mode_words}
      </p>
      <p className="m-0 text-sm">
        {w.last_run_at ? (
          <>
            The watch last ran <Time value={w.last_run_at} />
            {w.late && <strong className="text-warn"> (the daily run is late)</strong>}.
          </>
        ) : (
          "The watch has never run."
        )}
      </p>
      {w.quiet !== null && w.quiet !== undefined ? (
        <p className="m-0 text-sm">
          <Badge tone={w.quiet ? "ok" : "neutral"}>{w.quiet ? "Quiet for 72 hours" : "Not shown quiet"}</Badge> <Text value={w.quiet_words ?? ""} max={600} lines={5} />
        </p>
      ) : (
        <p className="m-0 text-sm text-muted">Whether the case is verifiably quiet is shown to people who manage cases.</p>
      )}
      {w.days.length === 0 ? (
        <p className="m-0 text-sm text-muted">
          No day has been answered yet.
          {w.proxy_checks_due > 0 && ` ${count(w.proxy_checks_due)} proxy ${plural(w.proxy_checks_due, "check is", "checks are")} due.`}
        </p>
      ) : (
        <ul className="m-0 flex list-none flex-col gap-1.5 p-0" aria-label="The watch's answers by day">
          {w.days.map((d) => (
            <Day key={d.day} d={d} />
          ))}
        </ul>
      )}
    </section>
  );
}

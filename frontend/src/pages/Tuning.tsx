// Rule tuning (the classic page /tuning): each rule's newest weekly report and the suggestions a
// model drafted from it, kept only with evidence. A person applies them in Kibana; ARGUS never
// edits a rule. Rule names, values and the suggestions' words come from SIEM and model data:
// untrusted text.
import { useQuery } from "@tanstack/react-query";
import type { SuggestionOut, TuningReportOut } from "../client/types.gen";
import { Loading, Problem } from "../components/Problem";
import { Time } from "../components/Time";
import { UntrustedText } from "../components/UntrustedText";
import { Card, CardTitle } from "../components/ui/card";
import { count } from "../lib/format";
import { OUTCOMES } from "../lib/labels";
import { optionText } from "../lib/optionText";
import { tuningOptions } from "../lib/queries";

function Suggestion({ s }: { s: SuggestionOut }) {
  const kind = s.kind.charAt(0).toUpperCase() + s.kind.slice(1);
  return (
    <li>
      <strong>
        {kind}
        {s.value != null && s.value !== "" && (
          <>
            : <UntrustedText value={s.path ?? ""} limits={{ maxChars: 80, maxLines: 1 }} /> = <UntrustedText value={s.value} limits={{ maxChars: 200, maxLines: 2 }} />
          </>
        )}
      </strong>
      {" — "}
      <UntrustedText value={s.change} limits={{ maxChars: 400, maxLines: 4 }} />
      <br />
      <span className="text-muted">
        Why: <UntrustedText value={s.why} limits={{ maxChars: 400, maxLines: 4 }} /> Risk: <UntrustedText value={s.risk} limits={{ maxChars: 400, maxLines: 4 }} />
      </span>
      {s.evidence.length > 0 && (
        <details>
          <summary className="cursor-pointer">Evidence</summary>
          <ul className="m-0 pl-5">
            {s.evidence.map((e, i) => (
              <li key={i}>
                <UntrustedText value={e} limits={{ maxChars: 300, maxLines: 3 }} />
              </li>
            ))}
          </ul>
        </details>
      )}
    </li>
  );
}

function Report({ r }: { r: TuningReportOut }) {
  const verdicts = Object.entries(r.labels).map(([o, n]) => `${OUTCOMES[o] ?? o.replaceAll("_", " ")} ${count(n)}`);
  return (
    <Card aria-label={`Tuning: ${optionText(r.rule, 60)}`}>
      <CardTitle>
        <UntrustedText value={r.rule} limits={{ maxChars: 200, maxLines: 1 }} />
      </CardTitle>
      <p className="m-0 mb-1 text-sm text-muted">
        Week to <Time value={r.week_end} />
        {r.model != null && r.model !== "" && (
          <>
            {" · "}
            <UntrustedText value={r.model} limits={{ maxChars: 80, maxLines: 1 }} />
          </>
        )}
      </p>
      <p className="m-0 mb-2 text-sm">
        {r.alerts != null ? count(r.alerts) : "?"} alerts, {r.investigations != null ? count(r.investigations) : "?"} investigations; {r.runs_at_limit != null ? count(r.runs_at_limit) : "?"} of {r.runs != null ? count(r.runs) : "?"} runs hit the alert limit
        {r.max_signals != null && <> ({count(r.max_signals)})</>}. Verdicts: {verdicts.length > 0 ? verdicts.join(", ") : "none"}.
      </p>
      {r.suggestions.length > 0 ? (
        <ul className="m-0 flex flex-col gap-2 pl-5 text-sm">
          {r.suggestions.map((s, i) => (
            <Suggestion key={i} s={s} />
          ))}
        </ul>
      ) : (
        <p className="m-0 text-sm text-muted">No suggestion this week.</p>
      )}
      {r.dropped.length > 0 && (
        <details className="mt-2 text-sm">
          <summary className="cursor-pointer">{count(r.dropped.length)} not kept</summary>
          <ul className="m-0 pl-5">
            {r.dropped.map((d, i) => (
              <li key={i}>
                <UntrustedText value={d} limits={{ maxChars: 200, maxLines: 2 }} />
              </li>
            ))}
          </ul>
        </details>
      )}
    </Card>
  );
}

export function Tuning() {
  const tuning = useQuery(tuningOptions);
  return (
    <>
      <h1 className="m-0 text-2xl font-semibold">Rule tuning</h1>
      <p className="m-0 max-w-prose text-sm text-muted">
        Each rule&apos;s weekly report: how much it fires, how often a run hit its alert limit, and your verdicts. Suggestions are drafted by a model and kept only with evidence from the report (an exception needs at least three benign or false-positive verdicts on that value and none true positive). Apply any of them in Kibana yourself; ARGUS never edits a rule.
      </p>
      {tuning.isPending && <Loading what="the tuning reports" />}
      {tuning.isError && <Problem error={tuning.error} what="The tuning reports" onRetry={() => void tuning.refetch()} />}
      {tuning.data && tuning.data.length === 0 && <p className="m-0 text-sm">No report yet (<code>argus tune run</code>, or weekly by the assessment service).</p>}
      {tuning.data?.map((r, i) => <Report key={`${r.rule}-${i}`} r={r} />)}
    </>
  );
}

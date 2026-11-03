import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import type { CaseTeamOut } from "../../client/types.gen";
import { useAnnounce } from "../../lib/announce";
import { count, plural } from "../../lib/format";
import { useGuard } from "../../lib/guard";
import { caseTeamOptions, changedTeam } from "../../lib/queries";
import { approveBody, AUTHOR_ROLE, decisionTitle, shortAuthor, STATE_TONE, STATE_WORDS, type TeamStep } from "../../lib/team";
import { ConfirmDialog } from "../ConfirmDialog";
import { Loading, Problem } from "../Problem";
import { Time } from "../Time";
import { UntrustedText } from "../UntrustedText";
import { Badge } from "../ui/badge";
import { Button } from "../ui/button";

function Text({ value, max = 700, lines = 6 }: { value: string; max?: number; lines?: number }) {
  return <UntrustedText value={value} limits={{ maxChars: max, maxLines: lines }} />;
}

// ------------------------------------------------------------------ one step

function Step({ step, hidden }: { step: TeamStep; hidden: boolean }) {
  return (
    <li className="rounded-control border border-border bg-surface p-2" data-testid="team-step">
      <details>
        <summary className="flex cursor-pointer flex-wrap items-center gap-x-2 gap-y-1 text-sm">
          <span className="text-muted">{step.n}.</span>
          <Badge tone="neutral" title={AUTHOR_ROLE[step.author]}>
            {step.author}
          </Badge>
          <span>{step.what.replace(`${step.author} `, "")}</span>
          {step.state && <Badge tone={STATE_TONE[step.state] ?? "neutral"}>{STATE_WORDS[step.state] ?? step.state}</Badge>}
        </summary>
        <div className="mt-2 flex flex-col gap-2">
          <p className="m-0 text-xs text-muted">{AUTHOR_ROLE[step.author]}</p>
          {step.text !== null && step.text !== undefined && (
            <div>
              <p className="m-0 mb-1 text-xs font-medium text-muted">{step.kind === "open" ? "The case's description, exactly" : "The comment, exactly"}</p>
              <div className="rounded-control border border-border bg-surface-2 p-2 text-sm" data-testid="team-text">
                <UntrustedText value={step.text} block limits={{ maxChars: 30_000, maxLines: 400 }} />
              </div>
            </div>
          )}
          {step.request ? (
            <div>
              <p className="m-0 mb-1 text-xs font-medium text-muted">The request</p>
              <p className="m-0 break-all font-mono text-xs" data-testid="team-request">
                {step.request.method} {step.request.path} <span className="text-muted">({step.request.content_type})</span>
              </p>
              {step.kind !== "comment" && step.kind !== "open" && (
                <div className="mt-1 text-xs">
                  <Text value={step.request.body} max={600} lines={6} />
                </div>
              )}
            </div>
          ) : (
            hidden && <p className="m-0 text-xs text-muted">The request says what the logs said: it needs log access in ELK.</p>
          )}
        </div>
      </details>
    </li>
  );
}

// ------------------------------------------------------------------ the canary

function Approval({ data }: { data: CaseTeamOut }) {
  const queries = useQueryClient();
  const { announce } = useAnnounce();
  const [asking, setAsking] = useState(false);
  const a = data.approval;
  const hash = data.plan_hash;
  const guard = useGuard(a.can_approve && hash !== null ? null : (a.approve_why_not ?? "Not available."));
  const request = useMemo(() => ({ method: "POST" as const, path: `/api/v1/cases/${data.case_id}/team/approve`, body: approveBody(hash ?? "") }), [data.case_id, hash]);
  if (!a.required) return null;
  return (
    <div className="flex flex-col gap-2 rounded-card border border-border bg-surface-2 p-3" role="group" aria-label="Approval of the first post" data-testid="team-approval">
      <p className="m-0 text-sm font-medium">The first cases need a person&apos;s approval</p>
      <p className="m-0 max-w-prose text-sm text-muted">Nothing is written to Kibana for this case until a person approves exactly the steps listed here. If anything below changes, the approval no longer holds and a new one is needed.</p>
      {a.given ? (
        <p className="m-0 text-sm" data-testid="team-approved">
          <Badge tone="ok">Approved</Badge> A person approved these steps. ARGUS writes them at its next posting run, when posting is on and the write window is open.
        </p>
      ) : (
        <>
          {a.why_not && <p className="m-0 text-sm text-muted">{a.why_not}</p>}
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
            <Button variant="primary" {...guard.props} onClick={guard.press(() => setAsking(true))}>
              Approve these steps
            </Button>
            {guard.hint}
            {a.needs_step_up && a.step_up_url && (
              <a href={a.step_up_url} className="text-sm">
                Confirm it is you
              </a>
            )}
          </div>
        </>
      )}
      <ConfirmDialog
        open={asking}
        onOpenChange={setAsking}
        title={`Approve the Kibana post for case ${data.case_number}`}
        description="You approve exactly the steps listed on this page (their hash is in the request). ARGUS checks your approval again before it writes the first one."
        request={request}
        confirmLabel="Approve these steps"
        onSent={() => {
          announce("Approved. ARGUS writes this case to Kibana at its next posting run.", "ok");
          void changedTeam(queries, data.case_id);
        }}
      />
    </div>
  );
}

// ------------------------------------------------------------------ the section

function Body({ data }: { data: CaseTeamOut }) {
  const title = decisionTitle(data.decision);
  const post = data.post;
  return (
    <>
      <p className="m-0 max-w-prose text-sm text-muted">
        What ARGUS would write to the case in Kibana for this incident, step by step, each by its own Kibana user. Looking at it sends nothing.
      </p>
      <div className="flex flex-col gap-1" role="group" aria-label="What happens now" data-testid="team-decision">
        <p className="m-0 flex flex-wrap items-center gap-2 text-sm">
          <Badge tone={title.tone}>{title.words}</Badge>
          {data.incident_id && <strong>{data.incident_id}</strong>}
          {data.report_version !== null && data.report_version !== undefined && <span className="text-muted">from report version {data.report_version}</span>}
        </p>
        <p className="m-0 max-w-prose text-sm">{data.decision.why}.</p>
        {data.decision.route && <p className="m-0 text-sm text-muted">Why it qualifies: {data.decision.route}.</p>}
        {data.note && <p className="m-0 max-w-prose text-sm text-muted">{data.note}</p>}
      </div>
      {data.problems.length > 0 && (
        <ul className="m-0 flex list-none flex-col gap-1 rounded-control border border-warn/40 bg-warn-soft p-3 text-sm text-warn" aria-label="What stops it" data-testid="team-problems">
          {data.problems.map((p, i) => (
            <li key={i}>
              <Text value={p} max={400} lines={3} />
            </li>
          ))}
        </ul>
      )}
      <Approval data={data} />
      {post && (
        <p className="m-0 flex flex-wrap items-center gap-2 text-sm" data-testid="team-post">
          <Badge tone={post.state === "held" ? "warn" : "ok"}>{post.state === "held" ? "Held" : post.kibana_case_id ? "In Kibana" : "Planned"}</Badge>
          <span>
            {Object.entries(post.steps)
              .map(([k, n]) => `${count(n)} ${STATE_WORDS[k] ?? k}`)
              .join(", ")}
            {post.opened_at && (
              <>
                ; opened <Time value={post.opened_at} />
              </>
            )}
            {post.last_version ? `; report version ${post.last_version} posted` : ""}.
          </span>
          {post.held_reason && <Text value={post.held_reason} max={300} lines={3} />}
        </p>
      )}
      {data.logs_hidden && data.steps.length > 0 && <p className="m-0 max-w-prose text-sm text-muted">Your account may not read the logs, so the words of each comment (they say what the logs said) are hidden here.</p>}
      {data.steps.length > 0 ? (
        <>
          <p className="m-0 text-sm">
            {count(data.steps.length)} {plural(data.steps.length, "step")} by {data.steps.length ? [...new Set(data.steps.map((s) => shortAuthor(s.author)))].join(", ") : "nobody"}, in this order; the lead&apos;s verdict is last.
          </p>
          <ol className="m-0 flex list-none flex-col gap-2 p-0" aria-label="Steps" data-testid="team-steps">
            {data.steps.map((s) => (
              <Step key={s.key} step={s} hidden={data.logs_hidden} />
            ))}
          </ol>
        </>
      ) : (
        <p className="m-0 text-sm text-muted" data-testid="team-nothing">
          {data.decision.action === "update" ? "Nothing new to add to the Kibana case." : "There is nothing to write to Kibana yet."}
        </p>
      )}
    </>
  );
}

/**
 * The Kibana case preview (AR8, D-195): exactly what ARGUS would write to the incident case in
 * Kibana for this case, step by step, by which of the six Kibana users, with each comment in full
 * and each request; whether posting is off (a dry run), why a case is or is not posted, and the
 * approval the first cases need. Reading it writes nothing.
 */
export function TeamSection({ caseId }: { caseId: string }) {
  const found = useQuery(caseTeamOptions(caseId));
  return (
    <section aria-label="Kibana case preview" id="kibana-case" className="flex flex-col gap-3 scroll-mt-4" aria-busy={found.isFetching}>
      <h2 className="m-0 text-lg font-semibold">Kibana case preview</h2>
      {found.isPending && <Loading what="the Kibana case preview" />}
      {found.isError && <Problem error={found.error} what="The Kibana case preview" onRetry={() => void found.refetch()} />}
      {found.isSuccess && <Body data={found.data} />}
    </section>
  );
}

// What argus-admin runs on request (D-328): a connection check (the SIEM, a Kibana key, an AI
// provider) and an uploaded asset map's import, each polled until it is done or failed.
import { useMutation, useQuery, useQueryClient, type QueryKey } from "@tanstack/react-query";
import { useEffect, useId, useRef, useState } from "react";
import { importAssets, startCheck } from "../../client/sdk.gen";
import { assetFileProblem, jobOptions, jobOutcome, jobSettled, type JobOutcome } from "../../lib/admin";
import { unwrap } from "../../lib/call";
import { ApiError } from "../../lib/session";
import { Badge } from "../ui/badge";
import { Button } from "../ui/button";
import { StepUpLink } from "./common";

/** Passed or failed, why it could not run, and what it said (folded). */
export function JobResult({ outcome, startError, readError, what, onConfirmed }: { outcome: JobOutcome; startError: unknown; readError: boolean; what: string; onConfirmed?: () => void }) {
  const failure = startError instanceof ApiError ? startError : startError ? null : undefined;
  return (
    <>
      {failure !== undefined && (
        <p role="alert" className="m-0 text-sm text-danger">
          {failure?.message ?? `The ${what} could not be started.`} {failure?.code === "step_up_required" && <StepUpLink onConfirmed={onConfirmed} />}
        </p>
      )}
      {readError && (
        <p role="alert" className="m-0 text-sm text-danger">
          The {what} could not be read just now; trying again.
        </p>
      )}
      {outcome.error && (
        <p role="alert" className="m-0 text-sm text-danger">
          {outcome.error}
        </p>
      )}
      {outcome.lines.length > 0 && (
        <details className="text-sm" open={outcome.state === "failed"}>
          <summary className="cursor-pointer text-muted">
            What it said ({outcome.lines.length} {outcome.lines.length === 1 ? "line" : "lines"})
          </summary>
          <pre className="m-0 mt-1 max-h-64 overflow-auto rounded-control border border-border bg-surface-2 p-2 font-mono text-xs whitespace-pre-wrap" role="log" aria-label={`What the ${what} said`}>
            {outcome.lines.join("\n")}
          </pre>
        </details>
      )}
    </>
  );
}

export function OutcomeBadge({ outcome, passed = "Passed", failed = "Failed" }: { outcome: JobOutcome; passed?: string; failed?: string }) {
  if (outcome.state === "passed") return <Badge tone="ok">{passed}</Badge>;
  if (outcome.state === "failed") return <Badge tone="danger">{failed}</Badge>;
  return null;
}

/** A button that has argus-admin check one connection (`siem`, `kibana:<key>`, `llm:<provider>`). */
export function CheckButton({ target, label }: { target: string; label: string }) {
  const [id, setId] = useState<number | null>(null);
  const start = useMutation({
    mutationFn: () => unwrap(startCheck({ body: { target } })),
    onSuccess: (job) => setId(job.id),
  });
  const job = useQuery(jobOptions(id));
  const outcome = jobOutcome(job.data);
  const waiting = start.isPending || (id !== null && !jobSettled(job.data));
  return (
    <div className="flex flex-col gap-1.5" data-testid={`check-${target}`}>
      <div className="flex flex-wrap items-center gap-2">
        <Button size="sm" aria-disabled={waiting} onClick={() => !waiting && start.mutate()}>
          {waiting ? "Checking…" : label}
        </Button>
        <OutcomeBadge outcome={outcome} />
      </div>
      <JobResult outcome={outcome} startError={start.error} readError={job.isError} what="check" />
    </div>
  );
}

/** Choose an asset map file (.yaml), read here and sent sealed; argus-admin imports it. */
export function AssetUpload({ refresh }: { refresh: readonly QueryKey[] }) {
  const id = useId();
  const queries = useQueryClient();
  const [file, setFile] = useState<{ name: string; content: string } | null>(null);
  const [refusal, setRefusal] = useState<string | null>(null);
  const [jobId, setJobId] = useState<number | null>(null);
  const send = useMutation({
    mutationFn: (content: string) => unwrap(importAssets({ body: { content } })),
    onSuccess: (job) => {
      setJobId(job.id);
      setFile(null);
    },
  });
  const job = useQuery(jobOptions(jobId));
  const outcome = jobOutcome(job.data);
  const done = jobSettled(job.data);
  const refreshed = useRef<number | null>(null);
  useEffect(() => {
    if (done && refreshed.current !== jobId) {
      refreshed.current = jobId;
      for (const key of refresh) void queries.invalidateQueries({ queryKey: key });
    }
  }, [done, jobId, queries, refresh]);
  const waiting = send.isPending || (jobId !== null && !done);

  async function choose(chosen: File | undefined) {
    setRefusal(null);
    setFile(null);
    send.reset();
    if (chosen === undefined) return;
    const why = assetFileProblem(chosen.name, chosen.size);
    if (why !== null) return setRefusal(why);
    const content = await chosen.text();
    if (content.trim() === "") return setRefusal("The file is empty.");
    setFile({ name: chosen.name, content });
  }

  return (
    <div className="flex flex-col gap-2 border-t border-border pt-3" data-testid="asset-upload">
      <label htmlFor={id} className="text-sm font-semibold">
        Upload an asset map
      </label>
      <p className="m-0 max-w-prose text-sm text-muted">A YAML file of your devices, networks and owners, at most 5 MB. It is sent sealed, imported by argus-admin and then deleted; it needs your password again.</p>
      <input id={id} type="file" accept=".yaml,.yml" disabled={waiting} onChange={(e) => void choose(e.target.files?.[0])} className="text-sm" />
      {refusal && (
        <p role="alert" className="m-0 text-sm text-danger">
          {refusal}
        </p>
      )}
      <div className="flex flex-wrap items-center gap-2">
        <Button size="sm" variant="primary" aria-disabled={file === null || waiting} onClick={() => file !== null && !waiting && send.mutate(file.content)}>
          {waiting ? "Importing…" : file ? `Import ${file.name}` : "Import"}
        </Button>
        <OutcomeBadge outcome={outcome} passed="Imported" failed="Not imported" />
      </div>
      <JobResult outcome={outcome} startError={send.error} readError={job.isError} what="import" onConfirmed={() => file !== null && send.mutate(file.content)} />
    </div>
  );
}

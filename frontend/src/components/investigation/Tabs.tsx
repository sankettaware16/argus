import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useState } from "react";
import { getRawAlert } from "../../client/sdk.gen";
import type { DossierOut, InvestigationDetail, StepOut } from "../../client/types.gen";
import { count } from "../../lib/format";
import { OUTCOMES } from "../../lib/labels";
import { unwrap } from "../../lib/call";
import { alertsOptions } from "../../lib/queries";
import { Loading, Problem } from "../Problem";
import { Time } from "../Time";
import { UntrustedText } from "../UntrustedText";
import { Badge } from "../ui/badge";
import { Button } from "../ui/button";
import { Check } from "../ui/field";
import { DataTable } from "../ui/table";
import { own, theNoun } from "../../lib/site";

export function Facts({ dossier }: { dossier: DossierOut }) {
  const ADDRESS: Record<string, string> = {
    asset: own("asset"),
    campus: own("address"),
    internal: "private address",
    public: `outside ${theNoun()}`,
    special: "special-use address",
    invalid: "not an address",
  };
  return (
    <>
      {dossier.facts.length > 0 && (
        <section aria-label="Key facts" className="flex flex-col gap-1">
          <h3 className="m-0 text-sm font-semibold">Key facts</h3>
          <ul className="m-0 pl-5 text-sm">
            {dossier.facts.map((line, i) => (
              <li key={i}>
                <UntrustedText value={line} limits={{ maxChars: 300, maxLines: 3 }} />
              </li>
            ))}
          </ul>
        </section>
      )}
      {dossier.decoded_paths.length > 0 && (
        <section aria-label="Requests, decoded" className="flex flex-col gap-1">
          <h3 className="m-0 text-sm font-semibold">Requests, decoded</h3>
          <ul className="m-0 pl-5 text-sm">
            {dossier.decoded_paths.map((p, i) => (
              <li key={i} className="font-mono">
                <UntrustedText value={p} limits={{ maxChars: 300, maxLines: 2 }} />
              </li>
            ))}
          </ul>
        </section>
      )}
      {dossier.addresses.length > 0 && (
        <section aria-label="Addresses" className="flex flex-col gap-1">
          <h3 className="m-0 text-sm font-semibold">Addresses</h3>
          <ul className="m-0 pl-5 text-sm">
            {dossier.addresses.map((a) => (
              <li key={a.address}>
                <span className="font-mono">
                  <UntrustedText value={a.address} limits={{ maxChars: 60, maxLines: 1 }} />
                </span>
                : {ADDRESS[a.kind] ?? "an address of a kind this page does not know"}
                {a.asset && (
                  <>
                    {" "}
                    (<UntrustedText value={a.asset} limits={{ maxChars: 100, maxLines: 1 }} />)
                  </>
                )}
              </li>
            ))}
          </ul>
        </section>
      )}
      {dossier.related.length > 0 && (
        <section aria-label="Related investigations" className="flex flex-col gap-1">
          <h3 className="m-0 text-sm font-semibold">Related investigations</h3>
          <ul className="m-0 pl-5 text-sm">
            {dossier.related.map((r) => (
              <li key={r.investigation_id}>
                <Link to="/investigations/$id" params={{ id: r.investigation_id }}>
                  <UntrustedText value={r.rule_name ?? r.rule_id ?? "an investigation"} limits={{ maxChars: 120, maxLines: 1 }} />
                </Link>
                {r.key_fields.map((k, i) => (
                  <span key={i} className="font-mono">
                    {" · "}
                    <UntrustedText value={`${k.field} ${String(k.value ?? "")}`} limits={{ maxChars: 120, maxLines: 1 }} />
                  </span>
                ))}{" "}
                · day from {(r.bucket_start ?? "").slice(0, 10)} · shares {r.shared} {r.shared === 1 ? "thing" : "things"}
              </li>
            ))}
          </ul>
        </section>
      )}
    </>
  );
}

const STEP_WORD: Record<StepOut["status"], string> = { answered: "Answered", deferred: "Not checked yet", manual: "For you", unknown: "No data", other: "Other" };
const STEP_TONE = { answered: "ok", deferred: "neutral", manual: "info", unknown: "warn", other: "neutral" } as const;

/** What ARGUS checked: the rule's own investigation steps and what was found for each. */
export function Checked({ detail }: { detail: InvestigationDetail }) {
  const d = detail.dossier;
  if (!d) return <p className="m-0 text-sm text-muted">Not looked at yet: ARGUS works through new investigations within minutes.</p>;
  return (
    <div className="flex flex-col gap-2">
      <p className="m-0 text-sm text-muted">
        From the rule&apos;s own investigation steps{!d.complete && <> (the newest {count(d.alerts_read)} alerts read)</>}.
      </p>
      {d.steps.length === 0 ? (
        <p className="m-0 text-sm">{d.has_note === false ? "The rule has no investigation steps in its note." : "No step to show."}</p>
      ) : (
        <ol className="m-0 flex list-none flex-col gap-3 p-0 text-sm">
          {d.steps.map((s, i) => (
            <li key={`${s.number}:${i}`} className="flex flex-col gap-1">
              <div>
                <Badge tone={STEP_TONE[s.status]} className="mr-1.5">
                  {STEP_WORD[s.status]}
                </Badge>
                <q>
                  <UntrustedText value={s.text} limits={{ maxChars: 600, maxLines: 6 }} />
                </q>
              </div>
              <div className="text-muted">
                <UntrustedText value={s.sentence} limits={{ maxChars: 300, maxLines: 3 }} />
              </div>
              {s.shown.length > 0 && (
                <ul className="m-0 list-none p-0 text-xs">
                  {s.shown.map((f) => (
                    <li key={f.field}>
                      <span className="font-mono">
                        <UntrustedText value={f.field} limits={{ maxChars: 80, maxLines: 1 }} />
                      </span>
                      {f.stand_in && (
                        <>
                          {" "}
                          (as <span className="font-mono"><UntrustedText value={f.stand_in} limits={{ maxChars: 60, maxLines: 1 }} /></span>)
                        </>
                      )}
                      :{" "}
                      {f.top.map((v, j) => (
                        <span key={j} className="font-mono">
                          {j > 0 && ", "}
                          <UntrustedText value={v.value} limits={{ maxChars: 100, maxLines: 1 }} /> ({v.count})
                        </span>
                      ))}
                      {f.distinct > f.top.length && <> and {f.distinct - f.top.length} more</>}
                    </li>
                  ))}
                </ul>
              )}
            </li>
          ))}
        </ol>
      )}
    </div>
  );
}

function RawAlert({ id, alertId }: { id: string; alertId: string }) {
  const raw = useQuery({
    queryKey: ["raw", id, alertId],
    queryFn: () => unwrap(getRawAlert({ path: { investigation_id: id, alert_id: alertId } })),
    staleTime: 60_000,
  });
  if (raw.isPending) return <Loading what="the raw alert" />;
  if (raw.isError) return <Problem error={raw.error} what="The raw alert" onRetry={() => void raw.refetch()} />;
  return (
    <div className="max-h-96 overflow-auto rounded-control border border-border bg-surface-2 p-2 font-mono text-xs">
      <UntrustedText value={JSON.stringify(raw.data.raw, null, 2)} block limits={{ maxChars: 40_000, maxLines: 1000 }} />
    </div>
  );
}

const MAX_COLUMNS = 12;

/** The newest 200 alerts with the columns a person chooses; one alert as the SIEM stored it, on demand. */
export function Alerts({ detail }: { detail: InvestigationDetail }) {
  const id = detail.investigation.id;
  const [columns, setColumns] = useState<string[] | null>(null);
  const [draft, setDraft] = useState<string[]>([]);
  const [raw, setRaw] = useState<string | null>(null);
  const alerts = useQuery(alertsOptions(id, columns));
  const total = detail.investigation.alert_count;
  const data = alerts.data;
  return (
    <div className="flex flex-col gap-2">
      {data && total > data.items.length && <p className="m-0 text-sm text-muted">The newest {count(data.items.length)} of {count(total)} alerts.</p>}
      <details>
        <summary className="cursor-pointer text-sm font-medium">Choose columns ({count((data?.columns ?? []).length)} of {count(detail.alert_fields.length)} fields shown)</summary>
        <form
          className="mt-2 flex flex-col gap-2"
          aria-label="Choose columns"
          onSubmit={(e) => {
            e.preventDefault();
            setColumns(draft);
          }}
        >
          <p className="m-0 text-xs text-muted">Fields of the newest alerts, with how many of them have it (at most {MAX_COLUMNS}).</p>
          <fieldset className="m-0 grid max-h-56 grid-cols-1 gap-x-4 gap-y-0.5 overflow-auto border-0 p-0 sm:grid-cols-2">
            <legend className="sr-only">Fields</legend>
            {detail.alert_fields.map((f) => (
              <Check
                key={f.field}
                checked={draft.includes(f.field)}
                disabled={!draft.includes(f.field) && draft.length >= MAX_COLUMNS}
                onChange={(e) => setDraft(e.target.checked ? [...draft, f.field] : draft.filter((x) => x !== f.field))}
              >
                <span className="font-mono">
                  <UntrustedText value={f.field} limits={{ maxChars: 120, maxLines: 1 }} />
                </span>{" "}
                <span className="text-muted">({f.count})</span>
              </Check>
            ))}
          </fieldset>
          <div className="flex gap-2">
            <Button type="submit">Show these columns</Button>
            <Button onClick={() => { setDraft([]); setColumns(null); }}>Use the rule&apos;s own columns</Button>
          </div>
        </form>
      </details>
      {alerts.isPending && <Loading what="the alerts" />}
      {alerts.isError && <Problem error={alerts.error} what="The alerts" onRetry={() => void alerts.refetch()} />}
      {data && (
        <div className="relative overflow-x-auto">
          <table className="w-full border-collapse text-sm">
            <caption className="sr-only">Alerts in this investigation</caption>
            <thead>
              <tr>
                {["Event time", ...data.columns, "Entities", "Kibana status", "Raw"].map((h, i) => (
                  <th key={`${h}:${i}`} scope="col" className="border-b border-border-strong px-2 py-1.5 text-left text-xs font-semibold text-muted">
                    {i > 0 && i <= data.columns.length ? <span className="font-mono"><UntrustedText value={h} limits={{ maxChars: 120, maxLines: 1 }} /></span> : h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {data.items.flatMap((a) => [
                <tr key={a.alert_id} className="border-b border-border">
                  <td className="px-2 py-1.5 align-top">
                    <Time value={a.event_time} />
                    {a.duplicate_of && <Badge className="ml-1">repeat</Badge>}
                    {a.late_arrival && <Badge className="ml-1">manual run</Badge>}
                  </td>
                  {data.columns.map((c) => (
                    <td key={c} className="px-2 py-1.5 align-top font-mono text-xs">
                      <UntrustedText value={a.cells[c] ?? ""} limits={{ maxChars: 200, maxLines: 2 }} />
                    </td>
                  ))}
                  <td className="px-2 py-1.5 align-top text-xs">
                    {a.entities.slice(0, 6).map((e, i) => (
                      <span key={i} className="font-mono">
                        {i > 0 && " · "}
                        <UntrustedText value={`${e.kind} ${String(e.value ?? "")}`} limits={{ maxChars: 90, maxLines: 1 }} />
                      </span>
                    ))}
                  </td>
                  <td className="px-2 py-1.5 align-top">
                    <UntrustedText value={a.workflow_status ?? ""} limits={{ maxChars: 20, maxLines: 1 }} />
                  </td>
                  <td className="px-2 py-1.5 align-top">
                    <Button size="sm" aria-expanded={raw === a.alert_id} onClick={() => setRaw(raw === a.alert_id ? null : a.alert_id)}>
                      {raw === a.alert_id ? "Hide raw" : "Show raw"}
                    </Button>
                  </td>
                </tr>,
                ...(raw === a.alert_id
                  ? [
                      <tr key={`${a.alert_id}:raw`}>
                        <td colSpan={data.columns.length + 4} className="px-2 pb-2">
                          <RawAlert id={id} alertId={a.alert_id} />
                        </td>
                      </tr>,
                    ]
                  : []),
              ])}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

/** The reviews so far, newest first. */
export function History({ detail }: { detail: InvestigationDetail }) {
  if (detail.reviews.length === 0) return <p className="m-0 text-sm text-muted">Nobody has reviewed this investigation yet.</p>;
  return (
    <DataTable
      caption="Reviews of this investigation, newest first"
      rows={detail.reviews}
      rowKey={(r) => String(r.id)}
      columns={[
        { key: "when", header: "When", cell: (r) => <Time value={r.created_at} /> },
        { key: "who", header: "Who", cell: (r) => <UntrustedText value={r.reviewer} limits={{ maxChars: 60, maxLines: 1 }} /> },
        { key: "what", header: "What", cell: (r) => `${r.action.replaceAll("_", " ")}${r.outcome ? ` (${OUTCOMES[r.outcome]})` : ""}` },
        { key: "alerts", header: "Alerts then", numeric: true, cell: (r) => count(r.alert_count) },
        { key: "note", header: "Note", cell: (r) => (r.note ? <UntrustedText value={r.note} limits={{ maxChars: 4000, maxLines: 40 }} /> : "—") },
      ]}
    />
  );
}

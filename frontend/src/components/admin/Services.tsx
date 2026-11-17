// ARGUS's services and timers (D-329), for an administrator on System health: what each does,
// whether it is meant to run and runs, a switch for the optional ones (password confirmed; one
// that writes to the SIEM also the typed words) and a restart for the services. argus-admin does
// it as a job; the list is read again when the job is done.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import { switchService } from "../../client/sdk.gen";
import type { ServiceIn, ServiceOut } from "../../client/types.gen";
import { canRestart, jobOptions, jobOutcome, jobSettled, servicesOptions } from "../../lib/admin";
import { unwrap } from "../../lib/call";
import { can, useSession } from "../../lib/session";
import { Time } from "../Time";
import { Badge } from "../ui/badge";
import { Button } from "../ui/button";
import { Card, CardTitle } from "../ui/card";
import { StepUpNote } from "./common";
import { JobResult } from "./jobs";
import { ConfirmSiemWrite } from "./save";

type Asked = Omit<ServiceIn, "confirm"> & { label: string };

const VERB: Record<ServiceIn["action"], string> = { on: "Switching on", off: "Switching off", restart: "Restarting" };

function Unit({ u, busy, current, onAsk }: { u: ServiceOut; busy: boolean; current: string | null; onAsk: (a: Asked) => void }) {
  const ask = (action: ServiceIn["action"]) => !busy && onAsk({ unit: u.unit, action, label: u.label });
  return (
    <li className="flex flex-wrap items-center justify-between gap-2 border-b border-border py-2.5 last:border-b-0" data-testid={`service-${u.unit}`}>
      <div className="flex min-w-0 flex-col gap-1">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-sm font-medium">{u.label}</span>
          <Badge tone={u.running ? "ok" : u.on ? "warn" : "neutral"}>{u.running ? "Running" : u.on ? "Not running" : "Off"}</Badge>
          {u.writes_siem && <Badge tone="warn">writes to the SIEM</Badge>}
          {u.deletes && <Badge tone="warn">deletes data</Badge>}
          {u.core && <Badge>always runs</Badge>}
        </div>
        <span className="font-mono text-xs text-muted">{u.unit}</span>
      </div>
      <div className="flex flex-wrap items-center gap-2">
        {current !== null && <span className="text-sm text-muted">{current}…</span>}
        {u.switchable && (
          <Button size="sm" variant={u.on ? "secondary" : "primary"} aria-disabled={busy} aria-label={`${u.on ? "Switch off" : "Switch on"} ${u.label}`} onClick={() => ask(u.on ? "off" : "on")}>
            {u.on ? "Switch off" : "Switch on"}
          </Button>
        )}
        {canRestart(u) && (
          <Button size="sm" aria-disabled={busy} aria-label={`Restart ${u.label}`} onClick={() => ask("restart")}>
            Restart
          </Button>
        )}
      </div>
    </li>
  );
}

function ServicesView() {
  const queries = useQueryClient();
  const services = useQuery(servicesOptions);
  const [asking, setAsking] = useState<Asked | null>(null);
  const [running, setRunning] = useState<{ asked: Asked; id: number } | null>(null);
  const start = useMutation({
    mutationFn: (v: { asked: Asked; confirm?: string }) => unwrap(switchService({ body: { unit: v.asked.unit, action: v.asked.action, confirm: v.confirm } })),
    onSuccess: (job, v) => {
      setRunning({ asked: v.asked, id: job.id });
      setAsking(null);
    },
    onError: () => setAsking(null),
  });
  const job = useQuery(jobOptions(running?.id ?? null));
  const done = jobSettled(job.data);
  const refreshed = useRef<number | null>(null);
  useEffect(() => {
    if (done && running !== null && refreshed.current !== running.id) {
      refreshed.current = running.id;
      void queries.invalidateQueries({ queryKey: servicesOptions.queryKey });
    }
  }, [done, running, queries]);
  const busy = start.isPending || (running !== null && !done);
  const outcome = jobOutcome(job.data);

  function ask(a: Asked) {
    start.reset();
    const unit = services.data?.units.find((u) => u.unit === a.unit);
    if (a.action === "on" && unit?.writes_siem) setAsking(a);
    else start.mutate({ asked: a });
  }

  return (
    <Card aria-label="Services" data-testid="services">
      <CardTitle>Services</CardTitle>
      <p className="m-0 mb-2 max-w-prose text-sm text-muted">ARGUS&apos;s services and timers. Switching one on or off needs your password again; argus-admin does it within seconds.</p>
      <StepUpNote />
      {services.isPending && <p className="m-0 text-sm text-muted">Loading the services…</p>}
      {services.isError && <p className="m-0 text-sm text-danger">The services could not be read just now.</p>}
      {services.data && (
        <>
          {services.data.units.length === 0 ? (
            <p className="m-0 text-sm text-muted">argus-admin has not reported the services yet; it does every five minutes.</p>
          ) : (
            <ul className="m-0 list-none p-0">
              {services.data.units.map((u) => (
                <Unit key={u.unit} u={u} busy={busy} current={busy && running?.asked.unit === u.unit ? VERB[running.asked.action] : start.isPending && start.variables.asked.unit === u.unit ? VERB[start.variables.asked.action] : null} onAsk={ask} />
              ))}
            </ul>
          )}
          {services.data.at && (
            <p className="m-0 mt-1 text-xs text-muted">
              Checked <Time value={services.data.at} relative />.
            </p>
          )}
        </>
      )}
      {running !== null && done && outcome.state === "passed" && (
        <p role="status" className="m-0 mt-2 text-sm text-ok" data-testid="service-done">
          {running.asked.label}: done.
        </p>
      )}
      {running !== null && done && outcome.state === "failed" && outcome.error === null && outcome.lines.length === 0 && (
        <p role="alert" className="m-0 mt-2 text-sm text-danger">
          {running.asked.label}: it did not work. Try again.
        </p>
      )}
      <JobResult outcome={outcome.state === "failed" ? outcome : { state: "none", lines: [], error: null }} startError={start.error} readError={job.isError} what="switch" />
      <ConfirmSiemWrite
        open={asking !== null}
        onOpenChange={(o) => !o && setAsking(null)}
        words={services.data?.confirm_words ?? ""}
        labels={asking ? [asking.label] : []}
        busy={start.isPending}
        description="Switching this on lets ARGUS write to your SIEM. It needs your password again, and you must type the words below."
        onSend={(typed) => asking && start.mutate({ asked: asking, confirm: typed })}
      />
    </Card>
  );
}

/** Only for an administrator; nothing at all for anyone else (the API refuses them too). */
export function ServicesPanel() {
  const session = useSession();
  return can(session.data, "admin") ? <ServicesView /> : null;
}

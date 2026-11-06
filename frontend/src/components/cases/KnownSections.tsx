import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useId, useMemo, useRef, useState, type ReactNode } from "react";
import { getBlocklist } from "../../client/sdk.gen";
import type { CaseActionStateOut, CaseDetail, KnownOut, NoticeRecordOut } from "../../client/types.gen";
import { useAnnounce } from "../../lib/announce";
import { unwrap } from "../../lib/call";
import { count, plural } from "../../lib/format";
import { useGuard } from "../../lib/guard";
import {
  blockBody,
  blockProblem,
  HOW,
  HOW_KEYS,
  managedWords,
  noticeBody,
  noticeProblem,
  REMINDER_WORDS,
  withdrawBody,
  whenWords,
  withdrawProblem,
  TEXT_MAX,
  TOLD_MAX,
  WHERE_MAX,
} from "../../lib/notice";
import { useNow } from "../../lib/now";
import { changedCase } from "../../lib/queries";
import { ConfirmDialog } from "../ConfirmDialog";
import { useCan } from "../investigation/actions";
import { Loading, Problem } from "../Problem";
import { Time } from "../Time";
import { UntrustedText } from "../UntrustedText";
import { Badge } from "../ui/badge";
import { Button } from "../ui/button";
import { Field, Select, TextArea, TextInput } from "../ui/field";
import { DataTable } from "../ui/table";
import { aKind, aNoun, kind, kindCapital, noun, nounCapital, teamName, unitsWithArticles, zoneLabel } from "../../lib/site";

const CASE_TITLE = "case-title";

function Text({ value, max = 300, lines = 3 }: { value: string; max?: number; lines?: number }) {
  return <UntrustedText value={value} limits={{ maxChars: max, maxLines: lines }} />;
}

function Block({ title, children, hint, id }: { title: string; children: ReactNode; hint?: string; id?: string }) {
  return (
    <section aria-label={title} id={id} className="flex flex-col gap-2 scroll-mt-4">
      <h3 className="m-0 text-base font-semibold">{title}</h3>
      {hint && <p className="m-0 max-w-prose text-sm text-muted">{hint}</p>}
      {children}
    </section>
  );
}

/** After a change the opener may be gone, so the focus goes to the case's title, which stays. */
function useFinish(caseId: string) {
  const queries = useQueryClient();
  const { announce } = useAnnounce();
  const done = useRef(false);
  return {
    sent: () => {
      done.current = true;
    },
    focus: () => {
      if (!done.current) return null;
      done.current = false;
      return document.getElementById(CASE_TITLE);
    },
    finish: async (say: string) => {
      announce(say, "ok");
      await changedCase(queries, caseId);
    },
    reload: () => changedCase(queries, caseId),
  };
}

/** One way to change the case that says why it is not available when it is not (the server's own answer). */
function ActionPanel({ label, state, children, open, onOpen }: { label: string; state: CaseActionStateOut; children: ReactNode; open: boolean; onOpen: () => void }) {
  const why = useId();
  return (
    <li className="flex flex-col gap-2 border-b border-border py-2 last:border-b-0">
      <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
        <Button variant={state.enabled ? "secondary" : "ghost"} aria-disabled={!state.enabled} aria-expanded={state.enabled ? open : undefined} aria-describedby={state.enabled ? undefined : why} onClick={() => state.enabled && onOpen()}>
          {label}
        </Button>
        {!state.enabled && state.why_not && (
          <p id={why} className="m-0 max-w-prose text-sm text-muted">
            <span className="font-medium">Not available: </span>
            <Text value={state.why_not} max={400} lines={4} />
          </p>
        )}
      </div>
      {open && state.enabled && <div className="rounded-card border border-border bg-surface-2 p-3">{children}</div>}
    </li>
  );
}

function When({ id, value, onChange }: { id: string; value: string; onChange: (v: string) => void }) {
  return (
    <Field label={`When (${zoneLabel()})`} hint="leave empty for now" htmlFor={id}>
      <TextInput id={id} type="datetime-local" value={value} onChange={(e) => onChange(e.target.value)} className="max-w-64" />
    </Field>
  );
}

// ------------------------------------------------------------------ the forms

export function NoticeForm({ detail, onDone }: { detail: CaseDetail; onDone: () => void }) {
  const id = useId();
  const now = useNow();
  const after = useFinish(detail.case.id);
  const [d, setD] = useState({ told: "", how: "", at: "", note: "" });
  const [open, setOpen] = useState(false);
  // the version the person had in front of them when they asked to see the request: a silent bump
  // of the case under an open dialog neither empties the form nor changes what they read; the
  // server answers 409 if the case moved (AR4 review, D-186)
  const [saw, setSaw] = useState<number | null>(null);
  const problem = noticeProblem(d, new Date(now));
  const guard = useGuard(problem);
  const request = useMemo(() => ({ method: "POST" as const, path: `/api/v1/cases/${detail.case.id}/notices`, body: noticeBody(saw ?? detail.case.version, d) }), [detail.case.id, detail.case.version, saw, d]);
  return (
    <div className="flex flex-col gap-2">
      <Field label="Who was told" hint={`the owner, ${unitsWithArticles()}`} htmlFor={`${id}-told`}>
        <TextInput id={`${id}-told`} value={d.told} maxLength={TOLD_MAX} onChange={(e) => setD({ ...d, told: e.target.value })} />
      </Field>
      <Field label="How" htmlFor={`${id}-how`}>
        <Select id={`${id}-how`} value={d.how} onChange={(e) => setD({ ...d, how: e.target.value })} className="max-w-64">
          <option value="">Choose…</option>
          {HOW_KEYS.map((k) => (
            <option key={k} value={k}>
              {HOW[k]}
            </option>
          ))}
        </Select>
      </Field>
      <When id={`${id}-at`} value={d.at} onChange={(at) => setD({ ...d, at })} />
      <Field label="A note" hint="optional" htmlFor={`${id}-note`}>
        <TextArea id={`${id}-note`} value={d.note} maxLength={TEXT_MAX} onChange={(e) => setD({ ...d, note: e.target.value })} />
      </Field>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <Button variant="primary" {...guard.props} onClick={guard.press(() => {
            setSaw(detail.case.version);
            setOpen(true);
          })}>
          Review the request
        </Button>
        {guard.hint}
      </div>
      <ConfirmDialog
        open={open}
        onOpenChange={(next) => {
          setOpen(next);
          if (!next) {
            setSaw(null);
            void after.reload();
          }
        }}
        title={`Record that the owner of case ${detail.case.number} was told`}
        description={
          <>
            ARGUS then tracks the case quietly: it leaves the work queues, its device&apos;s alerts are counted instead of raised, and ARGUS speaks again only when something changes. The record is yours and cannot be edited; a mistake is withdrawn. {whenWords(d.at)}
          </>
        }
        request={request}
        confirmLabel="Record the notice"
        finalFocus={after.focus}
        onSent={() => {
          after.sent();
          onDone();
          void after.finish(`Recorded: the owner of case ${detail.case.number} was told.`);
        }}
      />
    </div>
  );
}

export function BlockForm({ detail, onDone }: { detail: CaseDetail; onDone: () => void }) {
  const id = useId();
  const now = useNow();
  const after = useFinish(detail.case.id);
  const [d, setD] = useState({ by: "", where: "", at: "", note: "" });
  const [open, setOpen] = useState(false);
  const [saw, setSaw] = useState<number | null>(null); // see NoticeForm
  const problem = blockProblem(d, new Date(now));
  const guard = useGuard(problem);
  const request = useMemo(() => ({ method: "POST" as const, path: `/api/v1/cases/${detail.case.id}/blocks`, body: blockBody(saw ?? detail.case.version, d) }), [detail.case.id, detail.case.version, saw, d]);
  return (
    <div className="flex flex-col gap-2">
      <Field label="Who blocked it" htmlFor={`${id}-by`}>
        <TextInput id={`${id}-by`} value={d.by} maxLength={TOLD_MAX} onChange={(e) => setD({ ...d, by: e.target.value })} />
      </Field>
      <Field label="Where" hint="DNS, the firewall, the web proxy" htmlFor={`${id}-where`}>
        <TextInput id={`${id}-where`} value={d.where} maxLength={WHERE_MAX} onChange={(e) => setD({ ...d, where: e.target.value })} />
      </Field>
      <When id={`${id}-at`} value={d.at} onChange={(at) => setD({ ...d, at })} />
      <Field label="A note" hint="optional" htmlFor={`${id}-note`}>
        <TextArea id={`${id}-note`} value={d.note} maxLength={TEXT_MAX} onChange={(e) => setD({ ...d, note: e.target.value })} />
      </Field>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <Button variant="primary" {...guard.props} onClick={guard.press(() => {
            setSaw(detail.case.version);
            setOpen(true);
          })}>
          Review the request
        </Button>
        {guard.hint}
      </div>
      <ConfirmDialog
        open={open}
        onOpenChange={(next) => {
          setOpen(next);
          if (!next) {
            setSaw(null);
            void after.reload();
          }
        }}
        title={`Record a network block for case ${detail.case.number}`}
        description={
          <>
            The still-active line then reads “blocked at the network; the device is still infected”. The device is not treated as fixed, and the owner is not told by this. {whenWords(d.at)}
          </>
        }
        request={request}
        confirmLabel="Record the block"
        finalFocus={after.focus}
        onSent={() => {
          after.sent();
          onDone();
          void after.finish(`Recorded: the case ${detail.case.number} servers were blocked at the network.`);
        }}
      />
    </div>
  );
}

export function WithdrawForm({ detail, onDone }: { detail: CaseDetail; onDone: () => void }) {
  const id = useId();
  const after = useFinish(detail.case.id);
  const [d, setD] = useState({ who: "", reason: "" });
  const [open, setOpen] = useState(false);
  const [saw, setSaw] = useState<number | null>(null); // see NoticeForm
  const problem = withdrawProblem(d);
  const guard = useGuard(problem);
  const request = useMemo(() => ({ method: "POST" as const, path: `/api/v1/cases/${detail.case.id}/notices/withdraw`, body: withdrawBody(saw ?? detail.case.version, d) }), [detail.case.id, detail.case.version, saw, d]);
  return (
    <div className="flex flex-col gap-2">
      <Field label="Why it was a mistake" hint="a reason the next person will read" htmlFor={`${id}-reason`}>
        <TextArea id={`${id}-reason`} value={d.reason} maxLength={TEXT_MAX} onChange={(e) => setD({ ...d, reason: e.target.value })} />
      </Field>
      <Field label="Who withdraws it" hint="empty: you" htmlFor={`${id}-who`}>
        <TextInput id={`${id}-who`} value={d.who} maxLength={TOLD_MAX} onChange={(e) => setD({ ...d, who: e.target.value })} className="max-w-64" />
      </Field>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <Button variant="primary" {...guard.props} onClick={guard.press(() => {
            setSaw(detail.case.version);
            setOpen(true);
          })}>
          Review the request
        </Button>
        {guard.hint}
      </div>
      <ConfirmDialog
        open={open}
        onOpenChange={(next) => {
          setOpen(next);
          if (!next) {
            setSaw(null);
            void after.reload();
          }
        }}
        title={`Withdraw the notice on case ${detail.case.number}`}
        description="The case is not notified any more and ARGUS stops absorbing its device's alerts. What it already decided known stays decided, and the notice stays in the record as it was said. Record a notice again if it was true."
        request={request}
        confirmLabel="Withdraw the notice"
        danger
        finalFocus={after.focus}
        onSent={() => {
          after.sent();
          onDone();
          void after.finish(`Withdrawn: case ${detail.case.number} is not notified any more.`);
        }}
      />
    </div>
  );
}

// ------------------------------------------------------------------ what is recorded

function Notices({ notices }: { notices: NoticeRecordOut[] }) {
  if (notices.length === 0) return <p className="m-0 text-sm text-muted">Nothing is recorded yet.</p>;
  return (
    <ul className="m-0 flex list-none flex-col gap-1.5 p-0 text-sm" aria-label="Notices and blocks">
      {notices.map((n, i) => (
        <li key={i} className={n.withdrawn ? "text-muted line-through decoration-1" : undefined} data-testid="notice">
          <Badge tone={n.kind === "owner" ? "info" : "neutral"}>{n.kind === "owner" ? "Owner told" : "Blocked at the network"}</Badge>{" "}
          <Time value={n.at} />:{" "}
          {n.kind === "owner" ? (
            <>
              <Text value={n.told} max={200} lines={2} /> ({HOW[n.how as keyof typeof HOW] ?? "another way"})
            </>
          ) : (
            <>
              <Text value={n.told} max={200} lines={2} />, at <Text value={n.how} max={100} lines={1} />
            </>
          )}
          {n.managed !== null && n.managed !== undefined && n.kind === "owner" && <> · {n.managed ? `${kind()}-managed` : "personal"}</>} · recorded by <Text value={n.by} max={80} lines={1} />
          {n.note && (
            <>
              {" "}
              — <Text value={n.note} max={600} lines={6} />
            </>
          )}
          {n.withdrawn && <span className="no-underline"> (withdrawn: recorded by mistake; kept as it was said)</span>}
        </li>
      ))}
    </ul>
  );
}

function Reminders({ detail, known }: { detail: CaseDetail; known: KnownOut }) {
  const can = useCan("manage_cases");
  const after = useFinish(detail.case.id);
  const [open, setOpen] = useState<string | null>(null);
  if (known.reminders.length === 0) return <p className="m-0 text-sm text-muted">None due.</p>;
  return (
    <ul className="m-0 flex list-none flex-col gap-2 p-0 text-sm" aria-label="Reminders that are due">
      {known.reminders.map((r) => (
        <li key={r.kind} className="flex flex-col gap-1 rounded-control border border-warn/40 bg-warn-soft px-3 py-2" data-testid="reminder">
          <p className="m-0">
            <strong>{REMINDER_WORDS[r.kind] ?? "A reminder this page does not know"}.</strong> <Text value={r.words} max={400} lines={4} /> <span className="text-muted">Suggested <Time value={r.suggested_at} />. It is a suggestion; nothing was sent.</span>
          </p>
          {can && (
            <div>
              <Button size="sm" onClick={() => setOpen(r.kind)}>
                Dismiss this reminder
              </Button>
              <ConfirmDialog
                open={open === r.kind}
                onOpenChange={(next) => {
                  setOpen(next ? r.kind : null);
                  if (!next) void after.reload();
                }}
                title="Dismiss this reminder"
                description="ARGUS stops suggesting it. Nothing about the case changes; the dismissal is kept in the audit trail under your name."
                request={{ method: "POST", path: `/api/v1/cases/${detail.case.id}/reminders/${r.kind}/dismiss` }}
                confirmLabel="Dismiss"
                finalFocus={after.focus}
                onSent={() => {
                  after.sent();
                  void after.finish("Dismissed: ARGUS will not suggest it again.");
                }}
              />
            </div>
          )}
        </li>
      ))}
    </ul>
  );
}

/** The known infection: how much it keeps alerting since the notice, the new destinations nobody flags, and the changes that wait for a person. */
function Known({ known }: { known: KnownOut }) {
  const shown = known.new_destinations.length;
  return (
    <div className="flex flex-col gap-3">
      {known.notified_at ? (
        <>
          <p className="m-0 text-sm" data-testid="known-line">
            <Badge tone="warn">Still active</Badge> {known.line ? <Text value={known.line} max={600} lines={4} /> : null}
          </p>
          <p className="m-0 text-sm text-muted">
            {count(known.alerts)} {plural(known.alerts, "alert")} in {count(known.days)} {plural(known.days, "day")} since the notice; alerts a day: {known.trend}.{" "}
            {known.devices > 0 && `${count(known.devices)} ${plural(known.devices, "device")} named in the case. `}
            {known.last_alert_at && (
              <>
                Last alert <Time value={known.last_alert_at} relative />.
              </>
            )}
          </p>
          {known.alerts_per_day.length > 0 && (
            <DataTable
              reachable
              caption={`Alerts a day since the notice (${zoneLabel()} days)`}
              rows={known.alerts_per_day}
              rowKey={(r) => r.day}
              columns={[
                { key: "day", header: `Day (${zoneLabel()})`, cell: (r) => r.day },
                { key: "n", header: "Alerts", numeric: true, cell: (r) => count(r.alerts) },
              ]}
            />
          )}
        </>
      ) : (
        <p className="m-0 text-sm text-muted">The owner has not been recorded as told, so ARGUS does not treat this case as a known infection: its alerts are judged like any other.</p>
      )}
      <Block title="Changes waiting for a person" hint={`Something new since the notice: a flagged destination, a new kind of flag, ${aKind()} service as target, or much more traffic. It stays in Needs attention until a person reviews it.`}>
        {known.changes.length === 0 ? (
          <p className="m-0 text-sm text-muted">None.</p>
        ) : (
          <ul className="m-0 flex list-none flex-col gap-1 p-0 text-sm" aria-label="Changes since the notice">
            {known.changes.map((c) => (
              <li key={c.investigation_id}>
                <Link to="/alert-groups/$id" params={{ id: c.investigation_id }}>
                  <Text value={c.rule_name} max={120} lines={1} />
                </Link>
                : <Text value={c.why} max={500} lines={4} />
                {c.last_event_at && (
                  <>
                    {" "}
                    <span className="text-muted">
                      (last alert <Time value={c.last_event_at} relative />)
                    </span>
                  </>
                )}
              </li>
            ))}
          </ul>
        )}
      </Block>
      {known.notified_at && (
        <Block title={`${count(known.new_destinations_total)} new ${plural(known.new_destinations_total, "destination")} since the notice`} hint="Places the device reached after the notice that nobody flags. They are counted, not raised; a later flag on one is a change.">
          {shown === 0 ? (
            <p className="m-0 text-sm text-muted">None.</p>
          ) : (
            <>
              <ul className="m-0 flex list-none flex-col gap-0.5 p-0 text-sm" aria-label="New destinations">
                {known.new_destinations.map((n) => (
                  <li key={`${n.kind}:${n.value}`}>
                    <span className="font-mono">
                      <Text value={n.value} max={300} lines={1} />
                    </span>{" "}
                    <span className="text-muted">
                      ({n.kind === "ip" ? "address" : "domain"}, first seen <Time value={n.added_at} />)
                    </span>
                  </li>
                ))}
              </ul>
              {known.new_destinations_total > shown && <p className="m-0 text-sm text-muted">{count(known.new_destinations_total - shown)} more are kept and not listed here.</p>}
            </>
          )}
        </Block>
      )}
    </div>
  );
}

function BlockList({ detail, known }: { detail: CaseDetail; known: KnownOut }) {
  const [open, setOpen] = useState(false);
  const id = detail.case.id;
  const list = useQuery({ queryKey: ["blocklist", id], queryFn: () => unwrap(getBlocklist({ path: { case_id: id } })), enabled: open, staleTime: 30_000 });
  return (
    <Block title="The block list" hint={`The case's outside addresses and domains with the evidence ARGUS has, ready to send to the head of cybersecurity. Shared and popular services, ${noun()} and private addresses are left out.`}>
      <p className="m-0 flex flex-wrap items-center gap-x-4 gap-y-1 text-sm">
        <span>
          {count(known.blocklist_entries)} {plural(known.blocklist_entries, "entry", "entries")} ready.
        </span>
        <a href={`/api/v1/cases/${id}/blocklist.csv`} download>
          Download as CSV
        </a>
        <a href={`/api/v1/cases/${id}/blocklist.txt`} download={`argus-case-${detail.case.number}-blocklist.txt`}>
          Download as text (an e-mail)
        </a>
      </p>
      <details onToggle={(e) => setOpen((e.currentTarget as HTMLDetailsElement).open)}>
        <summary className="cursor-pointer text-sm font-medium">View the list</summary>
        <div className="mt-2 flex flex-col gap-2">
          {open && list.isPending && <Loading what="the block list" />}
          {list.isError && <Problem error={list.error} what="The block list" onRetry={() => void list.refetch()} />}
          {list.data && (
            <>
              {list.data.cut && <p className="m-0 text-sm text-muted">The list is cut at its limit; the download holds the same entries.</p>}
              <DataTable
                reachable
                caption="Block list"
                rows={list.data.entries}
                rowKey={(e) => `${e.type}:${e.value}`}
                empty="Nothing to block yet: no outside address or domain qualifies."
                columns={[
                  { key: "type", header: "Type", cell: (e) => (e.type === "family" ? "domain and every name under it" : e.type) },
                  { key: "value", header: "Value", cell: (e) => <span className="font-mono"><Text value={e.value} max={300} lines={1} /></span> },
                  { key: "evidence", header: "Evidence", cell: (e) => <Text value={e.evidence} max={300} lines={3} /> },
                  { key: "owner", header: "Network owner", cell: (e) => (e.owner ? <Text value={e.owner} max={120} lines={1} /> : "—") },
                  { key: "registered", header: "Registered", cell: (e) => e.registered ?? "—" },
                  { key: "seen", header: `First seen on ${noun()}`, cell: (e) => <Time value={e.first_seen_on_campus} /> },
                  { key: "devices", header: `${nounCapital()} devices`, numeric: true, cell: (e) => count(e.campus_devices) },
                ]}
              />
              {list.data.skipped > 0 && (
                <p className="m-0 text-sm text-muted">
                  {count(list.data.skipped)} {plural(list.data.skipped, "value was", "values were")} left out (shared infrastructure).
                </p>
              )}
            </>
          )}
        </div>
      </details>
    </Block>
  );
}

// ------------------------------------------------------------------ the section

/**
 * AR4b on the case page (D-169, D-176 to D-181): the owner-notified record. Whether the owner was
 * told, who and how; the managed or personal wording; what is still active since the notice and
 * what changed; the reminders that are due; the network blocks and the ready block list; and the
 * ways to record a notice, a block, or withdraw a notice recorded by mistake.
 */
export function KnownSection({ detail }: { detail: CaseDetail }) {
  const known = detail.known;
  const [active, setActive] = useState<string | null>(null);
  if (known === null || known === undefined) return null;
  const key = detail.case.id; // never the version: a silent bump must not empty a form or close a dialog
  const done = () => setActive(null);
  const toggle = (name: string) => setActive((now) => (now === name ? null : name));
  return (
    <section aria-label="Owner notified" id="notified" className="flex flex-col gap-4 scroll-mt-4">
      <h2 className="m-0 text-lg font-semibold">Owner notified</h2>
      <p className="m-0 max-w-prose text-sm text-muted">
        {teamName()} can tell the owner of {aNoun()} device and cannot make them fix it, so a true positive can stay active for weeks. Record who was told; ARGUS then tracks the case quietly and speaks again only if something changes.
      </p>
      <p className="m-0 text-sm" data-testid="managed-words">
        <Badge tone={known.managed === true ? "info" : "neutral"}>{known.managed === true ? `${kindCapital()}-managed` : known.managed === false ? "Personal devices" : "Not told yet"}</Badge> {managedWords(known.managed)}
      </p>
      <Known known={known} />
      <Block title="Reminders that are due" hint="ARGUS only suggests; it sends nothing. A second notice answers the first, a recorded block answers the second.">
        <Reminders detail={detail} known={known} />
      </Block>
      <Block title="What is recorded">
        <Notices notices={known.notices} />
        <ul className="m-0 list-none p-0" aria-label="Record a notice or a block">
          <ActionPanel label={known.notified_at ? "Record another notice" : "Record that the owner was told"} state={known.notify} open={active === "notify"} onOpen={() => toggle("notify")}>
            <NoticeForm key={key} detail={detail} onDone={done} />
          </ActionPanel>
          <ActionPanel label="Record a network block" state={known.block} open={active === "block"} onOpen={() => toggle("block")}>
            <BlockForm key={key} detail={detail} onDone={done} />
          </ActionPanel>
          <ActionPanel label="Withdraw a notice recorded by mistake" state={known.withdraw_notice} open={active === "withdraw"} onOpen={() => toggle("withdraw")}>
            <WithdrawForm key={key} detail={detail} onDone={done} />
          </ActionPanel>
        </ul>
      </Block>
      <BlockList detail={detail} known={known} />
    </section>
  );
}

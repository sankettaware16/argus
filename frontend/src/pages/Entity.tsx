import { useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useId, useState, type ReactNode } from "react";
import { addEntityNote } from "../client/sdk.gen";
import type { CaseRowOut, InvestigationOut } from "../client/types.gen";
import { coverage, IncidentLine, TITLE_NAMES, useEntity, type EntityKind } from "../components/EntityDrawer";
import { Loading, Problem } from "../components/Problem";
import { UntrustedText } from "../components/UntrustedText";
import { Button } from "../components/ui/button";
import { useAnnounce } from "../lib/announce";
import { unwrap } from "../lib/call";
import { isIp } from "../lib/engine";
import { count, plural } from "../lib/format";
import { can, useSession } from "../lib/session";
import { parse } from "../lib/time";
import { dayAndTime, shortDay } from "../lib/when";

export { coverage, TITLE_NAMES };

const NOUN: Record<EntityKind, string> = { device: "Device", account: "Account", site: "Campus site", outside: "Outside address" };

/** The page's noun: an outside name that is not an address is an outside host; never "Device" (E-5). */
export function entityNoun(kind: EntityKind, value: string): string {
  return kind === "outside" && !isIp(value) ? "Outside host" : NOUN[kind];
}

/** "Copy a summary for the owner" (§9.2): what was seen, when, which incident, what to do; no account names, no other day's devices, no threat-list details. */
export function ownerSummary(noun: string, value: string, groups: readonly InvestigationOut[], incidents: readonly CaseRowOut[]): string {
  const firsts = groups.map((g) => parse(g.first_event_at)).filter((d): d is Date => d !== null).sort((a, b) => a.getTime() - b.getTime());
  const lasts = groups.map((g) => parse(g.last_event_at)).filter((d): d is Date => d !== null).sort((a, b) => b.getTime() - a.getTime());
  const alerts = groups.reduce((n, g) => n + g.alert_count, 0);
  const open = incidents.find((c) => c.state !== "closed" && c.state !== "suspected");
  const first = firsts[0];
  const last = lasts[0];
  const lines = [
    `Our security monitoring saw unusual activity from ${noun.toLowerCase()} ${value}.`,
    first && last ? `It was seen from ${dayAndTime(first)} to ${dayAndTime(last)} IST (${count(alerts)} ${plural(alerts, "alert")}).` : `It raised ${count(alerts)} ${plural(alerts, "alert")}.`,
    open ? `It is part of security incident #${open.number}.` : "",
    "Please check whether the activity is expected on this device, and tell the security team what you find. If it is not expected, please do not use the device until the security team says so.",
  ];
  return lines.filter((l) => l !== "").join(" ");
}

function Block({ title, children, testId }: { title: string; children: ReactNode; testId?: string }) {
  return (
    <section aria-label={title} data-testid={testId} className="flex min-w-0 flex-col gap-1.5 rounded-card border border-border bg-surface p-3 break-words">
      <h2 className="m-0 text-base font-semibold">{title}</h2>
      {children}
    </section>
  );
}

function NoteBox({ k, value }: { k: "ip" | "host" | "user" | "domain"; value: string }) {
  const [open, setOpen] = useState(false);
  const [body, setBody] = useState("");
  const [busy, setBusy] = useState(false);
  const id = useId();
  const queries = useQueryClient();
  const { announce } = useAnnounce();
  const mayReview = can(useSession().data, "review");
  if (!mayReview) return null;
  return (
    <div className="flex flex-col gap-2">
      <Button aria-expanded={open} onClick={() => setOpen(!open)}>
        Add a note
      </Button>
      {open && (
        <form
          className="flex flex-col gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            const said = body.trim();
            if (said === "" || busy) return;
            setBusy(true);
            unwrap(addEntityNote({ body: { kind: k, value, body: said } }))
              .then(async () => {
                announce("Saved: note added.", "ok");
                setBody("");
                setOpen(false);
                await queries.invalidateQueries({ queryKey: ["entity-notes", k, value] });
              })
              .catch((err: unknown) => announce(err instanceof Error ? err.message : "The note was not saved; try again.", "danger"))
              .finally(() => setBusy(false));
          }}
        >
          <label htmlFor={id} className="text-sm font-medium">
            Your note
          </label>
          <textarea id={id} rows={2} maxLength={4000} value={body} onChange={(e) => setBody(e.target.value)} placeholder="e.g. Owner called 6 Nov, says it is their backup tool" className="rounded-control border border-border-strong bg-surface px-2 py-1 text-sm text-text" />
          <Button type="submit" variant="primary" aria-disabled={busy || body.trim() === ""}>
            Save the note
          </Button>
        </form>
      )}
    </div>
  );
}

/**
 * An entity's page (docs/p4f-ui-spec.md §9): a device, an account, a campus site or an outside
 * address. Built from what ARGUS already serves (§9.6): the alert groups of the value, the
 * incidents whose title holds it, and its notes; each block says it is read from alert groups, so
 * nothing claims more than it read. The coverage line is always there.
 */
export function EntityPage({ kind, value }: { kind: EntityKind; value: string }) {
  const { k, incidents, groups, notes } = useEntity(kind, value);
  const { announce } = useAnnounce();
  const noun = entityNoun(kind, value);
  const g = groups.data?.items ?? [];
  const inc = incidents.data?.items ?? [];
  const first = g.map((x) => parse(x.first_event_at)).filter((d): d is Date => d !== null).sort((a, b) => a.getTime() - b.getTime())[0];
  const last = g.map((x) => parse(x.last_event_at)).filter((d): d is Date => d !== null).sort((a, b) => b.getTime() - a.getTime())[0];
  const newestNote = notes.data?.items[0];
  return (
    <div className="flex flex-col gap-4">
      <header className="flex flex-col gap-1">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h1 className="m-0 text-2xl font-semibold break-all">
            <span className="text-muted">{noun}</span> <UntrustedText value={value} limits={{ maxChars: 200, maxLines: 1 }} />
          </h1>
          <div className="flex flex-wrap items-start gap-2">
            <NoteBox k={k} value={value} />
            <Button onClick={() => void navigator.clipboard?.writeText(value).then(() => announce("Copied.", "ok"))}>Copy value</Button>
          </div>
        </div>
        <p className="m-0 max-w-[72ch] text-sm text-muted" data-testid="coverage">
          <span aria-hidden="true">ⓘ </span>
          {coverage()}
        </p>
      </header>
      <div className="grid gap-4 md:grid-cols-2">
        <Block title="What ARGUS knows (from alert groups)" testId="entity-knows">
          {groups.isPending ? (
            <Loading what="what ARGUS knows" />
          ) : (
            <ul className="m-0 flex list-none flex-col gap-1 p-0 text-sm">
              <li>{first && last ? `In alerts ${shortDay(first)} – ${shortDay(last)}` : "In no alert ARGUS still keeps"}</li>
              <li>
                {count(g.length)}
                {groups.data?.has_more ? "+" : ""} {plural(g.length, "alert group")}
              </li>
              <li>
                Notes ({notes.data?.items.length ?? 0})
                {newestNote && (
                  <>
                    : “<UntrustedText value={newestNote.body} limits={{ maxChars: 120, maxLines: 1 }} />” — <UntrustedText value={newestNote.author} limits={{ maxChars: 40, maxLines: 1 }} />
                  </>
                )}
              </li>
            </ul>
          )}
        </Block>
        <Block title={`${TITLE_NAMES} · ${inc.length}${incidents.data?.has_more ? "+" : ""}`} testId="entity-incidents">
          {incidents.isError && <Problem error={incidents.error} what="The incidents" />}
          {inc.length === 0 && !incidents.isPending && <p className="m-0 text-sm text-muted">No incident title names it. An incident may still hold it: ARGUS looks in incident titles only.</p>}
          <ul className="m-0 list-none p-0">
            {inc.slice(0, 5).map((c) => (
              <IncidentLine key={c.id} c={c} />
            ))}
          </ul>
        </Block>
      </div>
      <Block title={`Alert groups · ${g.length}${groups.data?.has_more ? "+" : ""} (from alert groups)`} testId="entity-groups">
        {groups.isError && <Problem error={groups.error} what="The alert groups" />}
        {g.length === 0 && !groups.isPending && <p className="m-0 text-sm text-muted">No alert group in the last 5 days.</p>}
        <ul className="m-0 list-none p-0">
          {[...g]
            .sort((a, b) => (b.last_event_at ?? "").localeCompare(a.last_event_at ?? ""))
            .slice(0, 20)
            .map((x) => {
              const at = parse(x.last_event_at);
              return (
                <li key={x.id} className="flex min-h-9 flex-wrap items-center gap-x-2 border-b border-border text-sm">
                  <span className="w-28 shrink-0 text-muted tabular-nums">{at ? dayAndTime(at) : ""}</span>
                  <Link to="/alert-groups/$id" params={{ id: x.id }} className="min-w-0 flex-1 truncate">
                    <UntrustedText value={x.rule_name ?? x.title} limits={{ maxChars: 160, maxLines: 1 }} />
                  </Link>
                  <span className="text-muted tabular-nums">
                    {count(x.alert_count)} {plural(x.alert_count, "alert")}
                  </span>
                </li>
              );
            })}
        </ul>
        {g.length > 20 && (
          <Link to="/search" search={{ advanced: "1", view: "all", kind: k, value }} className="text-sm">
            Show all
          </Link>
        )}
      </Block>
      {kind === "device" && (
        <p className="m-0">
          <Button
            onClick={() => {
              const text = ownerSummary(noun, value, g, inc);
              void navigator.clipboard?.writeText(text).then(
                () => announce("Copied a summary for the owner.", "ok"),
                () => announce("The browser did not let ARGUS copy.", "warn"),
              );
            }}
          >
            Copy a summary for the owner
          </Button>
        </p>
      )}
    </div>
  );
}


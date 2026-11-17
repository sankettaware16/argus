// Threat intel (D-329): the outside sources ARGUS asks about public addresses and names, each with
// its key (set or not, added or replaced like any key: sealed, never shown), whether it is on, its
// free plan's limits, today's and this month's lookups, and a Test of one public address.
import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useMemo } from "react";
import type { SettingOut, SourceUseOut } from "../client/types.gen";
import { AdminOnly, Notice, StepUpNote } from "../components/admin/common";
import { CompactField } from "../components/admin/CompactField";
import { CheckButton } from "../components/admin/jobs";
import { SaveBar, SaveOutcome, SiemWriteGate, useSettingsSave } from "../components/admin/save";
import { Loading, Problem } from "../components/Problem";
import { Time } from "../components/Time";
import { Badge } from "../components/ui/badge";
import { Card } from "../components/ui/card";
import { historyOptions, settingsOptions } from "../lib/admin";
import { count } from "../lib/format";
import { buildChanges } from "../lib/settings";
import { limitWords, sourceState, SOURCES, usageOptions } from "../lib/usage";

const REFRESH = [settingsOptions.queryKey, usageOptions.queryKey, historyOptions.queryKey];

function Source({ s, all, use, state }: { s: (typeof SOURCES)[number]; all: ReadonlyMap<string, SettingOut>; use: SourceUseOut | undefined; state: ReturnType<typeof useSettingsSave> }) {
  const key = all.get(`outside.${s.key}_api_key`);
  const internetdb = s.keyless ? all.get("outside.shodan_internetdb") : undefined;
  const hasKey = key?.is_set ?? use?.key_set ?? false;
  const status = sourceState(hasKey, internetdb ? internetdb.value === true : null);
  return (
    <Card aria-label={s.name} data-testid={`source-${s.key}`} className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center gap-2">
        <h2 className="m-0 text-base font-semibold">{s.name}</h2>
        <Badge tone={status.on ? "ok" : "neutral"}>{status.words}</Badge>
      </div>
      <p className="m-0 max-w-prose text-sm">{s.gives}</p>
      {s.keyless && <p className="m-0 max-w-prose text-sm text-muted">{s.keyless}</p>}
      <dl className="m-0 grid gap-x-4 gap-y-1 text-sm sm:grid-cols-[9rem_1fr]">
        <dt className="text-muted">Its limits</dt>
        <dd className="m-0">{use ? limitWords(use.limits) : "Not counted yet"}</dd>
        <dt className="text-muted">Lookups</dt>
        <dd className="m-0">{use ? `${count(use.today)} today, ${count(use.month)} this month (${count(use.answered_month)} answered)` : "Not counted yet"}</dd>
      </dl>
      {key ? (
        <CompactField setting={key} label={`${key.is_set ? "Replace key" : "Add key"}: ${s.name}`} hint={key.is_set ? "A key is set; it is never shown. Type a new one only to replace it." : "Paste your free personal key from the source's website. It is sent sealed and never shown again."} state={state} />
      ) : (
        <p className="m-0 text-sm text-muted">Its key cannot be read from the settings just now.</p>
      )}
      {internetdb && <CompactField setting={internetdb} label="Use InternetDB when there is no key" state={state} />}
      <div className="border-t border-border pt-2">
        <CheckButton target={`outside:${s.key}`} label={`Test ${s.name}`} />
        <p className="m-0 mt-1 text-xs text-muted">Looks up one public test address with the saved key, within the same limits as ARGUS&apos;s own lookups.</p>
      </div>
    </Card>
  );
}

function ThreatIntelView() {
  const settings = useQuery(settingsOptions);
  const usage = useQuery(usageOptions);
  const state = useSettingsSave(REFRESH);
  const scope = useMemo(() => (settings.data?.sections ?? []).flatMap((s) => s.settings).filter((s) => SOURCES.some((x) => s.key === `outside.${x.key}_api_key`) || s.key === "outside.shodan_internetdb"), [settings.data]);
  const all = useMemo(() => new Map(scope.map((s) => [s.key, s])), [scope]);
  const built = useMemo(() => buildChanges(scope, state.drafts, state.resets), [scope, state.drafts, state.resets]);
  const labels = useMemo(() => new Map(scope.map((s) => [s.key, s.label])), [scope]);

  if (settings.isPending) return <Loading what="the threat-intel sources" />;
  if (settings.isError) return <Problem error={settings.error} what="The threat-intel sources" onRetry={() => void settings.refetch()} />;
  const out = settings.data;
  const uses = new Map((usage.data?.sources ?? []).map((u) => [u.source, u]));
  return (
    <>
      <div className="flex flex-col gap-1">
        <h1 className="m-0 text-2xl font-semibold">Threat intel</h1>
        <p className="m-0 max-w-prose text-sm text-muted">
          The outside sources ARGUS asks about public addresses and names during an investigation. Each is off until it has a key; their free plans are enough, and ARGUS stays below their limits. The rest of their settings are in{" "}
          <Link to="/settings" search={{ section: "outside" }}>
            Settings, Outside sources
          </Link>
          .
        </p>
      </div>
      {!out.applier.running && (
        <Notice tone="warn" testId="applier-down">
          argus-admin is not running: changes you save wait until it runs.
        </Notice>
      )}
      {usage.isError && <Notice tone="warn">The lookups could not be counted just now.</Notice>}
      {usage.data?.sources_at && (
        <p className="m-0 text-xs text-muted">
          Lookups counted <Time value={usage.data.sources_at} relative />.
        </p>
      )}
      <StepUpNote />
      <SaveOutcome state={state} labels={labels} />
      <div className="grid gap-3 lg:grid-cols-3">
        {SOURCES.map((s) => (
          <Source key={s.key} s={s} all={all} use={uses.get(s.key)} state={state} />
        ))}
      </div>
      <SaveBar state={state} built={built} onSave={() => state.press(scope, built)} />
      <SiemWriteGate state={state} words={out.confirm_words} />
    </>
  );
}

export function ThreatIntel() {
  return (
    <AdminOnly what="Threat intel">
      <ThreatIntelView />
    </AdminOnly>
  );
}

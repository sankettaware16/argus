// AI and agents (D-328): the AI providers ARGUS may ask, their keys, switches and spending
// limits, the kill switch, the AI tasks and the agents that use them. Its settings are saved like
// Settings' (argus-admin applies them); a key is typed, sent sealed and never shown again. The
// agents are shown, not edited: their instructions are pinned and tested against the gold set.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { switchLlm } from "../client/sdk.gen";
import type { AgentOut, AiOut, AiProviderOut, AiPurposeOut, SettingOut } from "../client/types.gen";
import { AdminOnly, Notice, StepUpNote } from "../components/admin/common";
import { CheckButton, JobResult } from "../components/admin/jobs";
import { SaveBar, SaveOutcome, SiemWriteGate, useSettingsSave, type SettingsSave } from "../components/admin/save";
import { CompactField } from "../components/admin/CompactField";
import { Loading, Problem } from "../components/Problem";
import { Time } from "../components/Time";
import { Badge } from "../components/ui/badge";
import { Button } from "../components/ui/button";
import { Card, CardTitle } from "../components/ui/card";
import { historyOptions, jobOptions, jobOutcome, jobSettled, settingsOptions } from "../lib/admin";
import { aiChanges, aiLabels, aiOptions, aiSummary, byKey, callsWords, memberStates, modelsBySize, packMembers, providerSettings, purposeSettings, readingSetting, spendWords } from "../lib/ai";
import { unwrap } from "../lib/call";
import { buildChanges } from "../lib/settings";

const REFRESH = [aiOptions.queryKey, settingsOptions.queryKey, historyOptions.queryKey];

function Fact({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="contents">
      <dt className="text-muted">{label}</dt>
      <dd className="m-0 min-w-0 break-words">{children}</dd>
    </div>
  );
}

/** Stop or resume every AI call (argus-admin sets it, as `argus llm stop` / `resume`). */
function KillSwitch({ stopped }: { stopped: boolean }) {
  const queries = useQueryClient();
  const [id, setId] = useState<number | null>(null);
  const start = useMutation({
    mutationFn: (stop: boolean) => unwrap(switchLlm({ body: { stop } })),
    onSuccess: (job) => setId(job.id),
  });
  const job = useQuery(jobOptions(id));
  const done = jobSettled(job.data);
  const refreshed = useRef<number | null>(null);
  useEffect(() => {
    if (done && refreshed.current !== id) {
      refreshed.current = id;
      void queries.invalidateQueries({ queryKey: aiOptions.queryKey });
    }
  }, [done, id, queries]);
  const waiting = start.isPending || (id !== null && !done);
  const outcome = jobOutcome(job.data);
  return (
    <div className="flex flex-col gap-1.5" data-testid="kill-switch">
      <div>
        {stopped ? (
          <Button variant="primary" aria-disabled={waiting} onClick={() => !waiting && start.mutate(false)}>
            {waiting ? "Resuming…" : "Resume AI calls"}
          </Button>
        ) : (
          <Button variant="danger" aria-disabled={waiting} onClick={() => !waiting && start.mutate(true)}>
            {waiting ? "Stopping…" : "Stop all AI calls"}
          </Button>
        )}
      </div>
      {outcome.state === "failed" && outcome.error === null && (
        <p role="alert" className="m-0 text-sm text-danger">
          The switch did not change. Try again.
        </p>
      )}
      <JobResult outcome={outcome.state === "failed" ? outcome : { state: "none", lines: [], error: null }} startError={start.error} readError={job.isError} what="switch" />
    </div>
  );
}

function Status({ ai }: { ai: AiOut }) {
  return (
    <Card aria-label="Status" data-testid="ai-status">
      <CardTitle>Status</CardTitle>
      {ai.stopped ? (
        <Notice tone="warn" testId="ai-stopped">
          All AI calls are stopped. ARGUS still works; nothing is sent to any provider until you resume.
        </Notice>
      ) : !ai.any_key ? (
        <Notice tone="info" testId="ai-off">
          The AI is off: add a key for at least one provider below. ARGUS still works without it.
        </Notice>
      ) : (
        <p className="m-0 text-sm" data-testid="ai-summary">
          {aiSummary(ai)}
        </p>
      )}
      <p className="m-0 my-2 text-sm text-muted">
        This month {spendWords(ai.month_usd, ai.monthly_cap_usd, "no monthly limit")}; today {spendWords(ai.today_usd, ai.daily_cap_usd, "no daily limit")}.
      </p>
      <KillSwitch stopped={ai.stopped} />
    </Card>
  );
}

function Spending({ ai, all, state }: { ai: AiOut; all: ReadonlyMap<string, SettingOut>; state: SettingsSave }) {
  return (
    <Card aria-label="Spending" data-testid="ai-spending">
      <CardTitle>Spending</CardTitle>
      <p className="m-0 mb-2 max-w-prose text-sm text-muted">What the paid providers may cost together. The free providers cost nothing; when a limit is reached ARGUS uses only the free ones.</p>
      <dl className="m-0 mb-3 grid gap-x-4 gap-y-1 text-sm sm:grid-cols-[10rem_1fr]">
        <Fact label="Spent this month">{spendWords(ai.month_usd, ai.monthly_cap_usd, "no monthly limit")}</Fact>
        <Fact label="Spent today">{spendWords(ai.today_usd, ai.daily_cap_usd, "no daily limit")}</Fact>
      </dl>
      <div className="grid gap-3 sm:grid-cols-2">
        <CompactField setting={all.get("llm.monthly_cap_usd")} label="Monthly limit (USD)" hint="The most all paid providers may cost together in a month." state={state} />
        <CompactField setting={all.get("llm.daily_cap_usd")} label="Daily limit (USD)" hint="Empty: the monthly limit only." state={state} />
      </div>
    </Card>
  );
}

const TRUST: Record<string, string> = {
  cloud: "On the internet: only pseudonymized text is sent",
  self_hosted: "A machine of your organisation",
};

function Provider({ p, all, state }: { p: AiProviderOut; all: ReadonlyMap<string, SettingOut>; state: SettingsSave }) {
  const own = providerSettings(all, p);
  const models = modelsBySize(p.models);
  return (
    <Card aria-label={`Provider ${p.name}`} data-testid={`provider-${p.name}`} className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center gap-2">
        <h3 className="m-0 text-base font-semibold">{p.name}</h3>
        <Badge tone={p.paid ? "warn" : "ok"}>{p.paid ? "Paid" : "Free"}</Badge>
        <Badge tone={p.enabled ? "ok" : "neutral"}>{p.enabled ? "On" : "Off"}</Badge>
        {p.keys.length > 0 && !p.keys.some((k) => k.is_set) && <Badge>No key yet</Badge>}
      </div>
      {p.alarm && (
        <Notice tone="warn" testId={`alarm-${p.name}`}>
          {p.alarm}
        </Notice>
      )}
      <dl className="m-0 grid gap-x-4 gap-y-1 text-sm sm:grid-cols-[8rem_1fr]">
        <Fact label="Where it runs">{TRUST[p.trust] ?? p.trust}</Fact>
        <Fact label="Models">
          {models.length === 0 ? (
            "None listed"
          ) : (
            <ul className="m-0 list-none p-0">
              {models.map(([size, name]) => (
                <li key={size}>
                  <span className="text-muted">{size}:</span> <span className="font-mono text-xs">{name}</span>
                </li>
              ))}
            </ul>
          )}
        </Fact>
        <Fact label="Calls">{callsWords(p.ok_month, p.calls_month)}</Fact>
        {p.paid && (
          <>
            <Fact label="This month">{spendWords(p.month_usd, p.monthly_cap_usd)}</Fact>
            <Fact label="Today">{spendWords(p.today_usd, p.daily_cap_usd)}</Fact>
          </>
        )}
      </dl>
      <CompactField setting={own.enabled} label="Use this provider" state={state} />
      {own.keys.map(({ key, setting }) =>
        setting ? (
          <CompactField key={key.name} setting={setting} label={`${key.is_set ? "Replace key" : "Add key"}: ${key.name}`} hint={key.is_set ? "A key is set; it is never shown. Type a new one only to replace it." : "Paste the API key the provider gave you. It is sent sealed and never shown again."} state={state} />
        ) : (
          <p key={key.name} className="m-0 text-sm">
            {key.name}: <Badge tone={key.is_set ? "ok" : "neutral"}>{key.is_set ? "Set" : "Not set"}</Badge>
          </p>
        ),
      )}
      {p.paid && (
        <div className="grid gap-3 sm:grid-cols-2">
          <CompactField setting={own.monthly} label="Its monthly limit (USD)" hint="Empty: the overall limit only." state={state} />
          <CompactField setting={own.daily} label="Its daily limit (USD)" hint="Empty: the overall daily limit only." state={state} />
        </div>
      )}
      <div className="border-t border-border pt-2">
        <CheckButton target={`llm:${p.name}`} label={`Test ${p.name}`} />
        <p className="m-0 mt-1 text-xs text-muted">Asks for its list of models with the saved key; no prompt is sent.</p>
      </div>
    </Card>
  );
}

function Purpose({ p, all, state }: { p: AiPurposeOut; all: ReadonlyMap<string, SettingOut>; state: SettingsSave }) {
  const own = purposeSettings(all, p.task);
  return (
    <div className="flex flex-col gap-2 border-b border-border py-3 last:border-b-0" data-testid={`purpose-${p.task}`}>
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <p className="m-0 text-sm font-semibold">{p.label}</p>
        <span className="text-sm text-muted">
          {p.calls_today} {p.calls_today === 1 ? "call" : "calls"} today{p.calls_per_day !== null ? ` of ${p.calls_per_day} a day` : " (no daily limit)"}
        </span>
      </div>
      <div className="grid gap-3 md:grid-cols-3">
        <CompactField setting={own.calls} label="Calls a day" hint="Empty: no limit of its own." state={state} />
        <CompactField setting={own.providers} label="Providers, in order" state={state} />
        <CompactField setting={own.tier} label="Model size" state={state} />
      </div>
    </div>
  );
}

function Agent({ a }: { a: AgentOut }) {
  const list = (xs: string[] | undefined) => (xs === undefined || xs.length === 0 ? "None" : xs.join(", "));
  const calls = a.calls_month ?? 0;
  return (
    <li className="flex flex-col gap-1.5 border-b border-border py-3 last:border-b-0" data-testid={`agent-${a.name}`}>
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-sm font-semibold">{a.name}</span>
        {a.kind && <Badge>{a.kind}</Badge>}
        <Badge tone={a.on ? "ok" : "neutral"}>{a.on ? "On" : "Off"}</Badge>
        {a.version && <span className="text-xs text-muted">version {a.version}</span>}
      </div>
      {a.mission && <p className="m-0 max-w-prose text-sm">{a.mission}</p>}
      {a.problem && (
        <Notice tone="danger" testId={`agent-problem-${a.name}`}>
          {a.problem}
        </Notice>
      )}
      <dl className="m-0 grid gap-x-4 gap-y-1 text-sm sm:grid-cols-[8rem_1fr]">
        <Fact label="Model size">{a.tier ?? "Not set"}</Fact>
        <Fact label="Tools">{list(a.tools)}</Fact>
        {(a.specialists ?? []).length > 0 && <Fact label="Specialists">{list(a.specialists)}</Fact>}
        <Fact label="Runs when">{list(a.triggers)}</Fact>
        <Fact label="Calls">{calls === 0 ? "No calls this month" : `${calls} ${calls === 1 ? "call" : "calls"} this month`}</Fact>
        {!a.on && a.enabled_version && a.enabled_version !== a.version && <Fact label="Runs in code">version {a.enabled_version}</Fact>}
      </dl>
    </li>
  );
}

/** ARGUS's own team first: the tested default pack, each member in one line, with its state. */
function Pack({ ai }: { ai: AiOut }) {
  const members = packMembers(ai);
  const specialists = ai.agents.find((a) => a.name === "investigator")?.specialists ?? [];
  return (
    <Card aria-label="ARGUS's team" data-testid="ai-pack">
      <div className="flex flex-wrap items-center gap-2">
        <CardTitle className="m-0">ARGUS&apos;s team (the default pack)</CardTitle>
        <Badge tone="ok">Default pack · tested</Badge>
      </div>
      <p className="m-0 mt-1 mb-2 max-w-prose text-sm text-muted">The investigation agents (measured against the gold set) and the Kibana case team (run on a real SIEM) that come with ARGUS. They are on by default; what each uses (providers, limits, keys) is set below.</p>
      <ul className="m-0 grid list-none gap-2 p-0 md:grid-cols-2">
        {members.map((m) => (
          <li key={m.key} className="flex flex-col gap-1 rounded-card bg-bg px-4 py-3" data-testid={`pack-${m.key}`}>
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-sm font-semibold">{m.name}</span>
              {memberStates(m).map((st) => (
                <Badge key={st.text} tone={st.tone}>
                  {st.text}
                </Badge>
              ))}
            </div>
            <p className="m-0 text-sm">{m.does}</p>
            {m.key === "investigator" && specialists.length > 0 && <p className="m-0 text-xs text-muted">Its specialists: {specialists.join(", ")}</p>}
          </li>
        ))}
      </ul>
      <p className="m-0 mt-3 text-sm text-muted" data-testid="pack-later">
        Your own agents and workflows: coming later.
      </p>
    </Card>
  );
}

function Team({ ai }: { ai: AiOut }) {
  return (
    <Card aria-label="Case team" data-testid="ai-team">
      <CardTitle>Case team</CardTitle>
      <p className="m-0 mb-2 max-w-prose text-sm text-muted">The Kibana users that write confirmed incidents as cases. Each needs its own Kibana key.</p>
      <ul className="m-0 grid list-none gap-1 p-0 text-sm sm:grid-cols-2">
        {ai.team.map((t) => (
          <li key={t.user} className="flex items-center justify-between gap-2 rounded-control border border-border px-2 py-1">
            <span className="font-mono text-xs">{t.user}</span>
            <Badge tone={t.is_set ? "ok" : "neutral"}>{t.is_set ? "Set" : "Not set"}</Badge>
          </li>
        ))}
      </ul>
      <p className="m-0 mt-2 text-sm">
        {ai.team_keys_expire ? <>The keys expire on {ai.team_keys_expire}. </> : <>No expiry date is recorded for the keys. </>}
        <Link to="/settings" search={{ section: "case_team" }}>
          Set the keys in Settings, Kibana cases
        </Link>
      </p>
    </Card>
  );
}

function AiView() {
  const data = useQuery(aiOptions);
  const settings = useQuery(settingsOptions);
  const state = useSettingsSave(REFRESH);
  const reading = useMemo(() => {
    const found = settings.data?.sections.flatMap((s) => s.settings).find((s) => s.key === "risk.reading");
    return data.data ? readingSetting(data.data.readings_on, found) : undefined;
  }, [data.data, settings.data]);
  const scope = useMemo(() => [...(data.data?.settings ?? []), ...(reading ? [reading] : [])], [data.data, reading]);
  const all = useMemo(() => byKey(scope), [scope]);
  const built = useMemo(() => aiChanges(buildChanges(scope, state.drafts, state.resets), scope), [scope, state.drafts, state.resets]);
  const labels = useMemo(() => {
    const out = data.data ? aiLabels(data.data) : new Map<string, string>();
    if (reading) out.set(reading.key, reading.label);
    return out;
  }, [data.data, reading]);

  if (data.isPending) return <Loading what="the AI settings" />;
  if (data.isError) return <Problem error={data.error} what="The AI settings" onRetry={() => void data.refetch()} />;
  const ai = data.data;
  return (
    <>
      <div className="flex flex-col gap-1">
        <h1 className="page-h">AI and agents</h1>
        <p className="page-sub">Which AI providers ARGUS may ask, their keys and spending limits, and the agents that use them. A change is applied by argus-admin like any setting; the result shows here within a few seconds.</p>
      </div>
      {!ai.applier.running && (
        <Notice tone="warn" testId="applier-down">
          argus-admin is not running: changes you save wait until it runs.
          {ai.applier.last_seen && (
            <>
              {" "}
              Last seen <Time value={ai.applier.last_seen} relative />.
            </>
          )}
        </Notice>
      )}
      {ai.problem && (
        <Notice tone="danger" testId="ai-problem" role="alert">
          {ai.problem}
        </Notice>
      )}
      <StepUpNote />
      <SaveOutcome state={state} labels={labels} />
      <Pack ai={ai} />
      <Status ai={ai} />
      <Spending ai={ai} all={all} state={state} />
      <section aria-labelledby="providers-title" className="flex flex-col gap-3">
        <h2 id="providers-title" className="m-0 text-lg font-semibold">
          Providers
        </h2>
        {ai.providers.length === 0 ? (
          <p className="m-0 text-sm text-muted">No provider is listed on this host.</p>
        ) : (
          <div className="grid gap-3 lg:grid-cols-2">
            {ai.providers.map((p) => (
              <Provider key={p.name} p={p} all={all} state={state} />
            ))}
          </div>
        )}
      </section>
      <Card aria-label="AI tasks" data-testid="ai-tasks">
        <CardTitle>AI tasks</CardTitle>
        <p className="m-0 mb-1 max-w-prose text-sm text-muted">What ARGUS uses the AI for, how often a day, which providers it may ask and the model size.</p>
        {reading && <CompactField setting={all.get(reading.key)} label="ARGUS AI readings" hint="ARGUS AI writes its reading of each presented incident. Off: no reading is written." state={state} />}
        {ai.purposes.map((p) => (
          <Purpose key={p.task} p={p} all={all} state={state} />
        ))}
      </Card>
      <Card aria-label="Agents" data-testid="ai-agents">
        <CardTitle>Agents</CardTitle>
        <p className="m-0 mb-1 max-w-prose text-sm text-muted" data-testid="agents-note">
          An agent&apos;s instructions are fixed and tested against the gold set before it runs; a new version comes with an ARGUS release, not from this page. What you can change here is what they use: the providers, the limits and the tasks above.
        </p>
        {ai.agents.length === 0 ? (
          <p className="m-0 text-sm text-muted">No agent is installed on this host.</p>
        ) : (
          <ul className="m-0 list-none p-0">
            {ai.agents.map((a) => (
              <Agent key={a.name} a={a} />
            ))}
          </ul>
        )}
      </Card>
      <Team ai={ai} />
      <SaveBar state={state} built={built} onSave={() => state.press(scope, built)} />
      <SiemWriteGate state={state} words={settings.data?.confirm_words ?? ""} />
      <p className="m-0 text-xs text-muted">Amounts are in US dollars.</p>
    </>
  );
}

export function AiAgents() {
  return (
    <AdminOnly what="AI and agents">
      <AiView />
    </AdminOnly>
  );
}

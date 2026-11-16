// First-time setup (D-327): four steps that ask what ARGUS cannot find out itself, then argus-admin
// runs `argus init` with the answers. Everything typed stays in this component's state; the two
// keys go only in the final request, to be sealed, and are shown nowhere (the review says "set").
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useEffect, useState, type ReactNode } from "react";
import { inspectTls, startSetup } from "../client/sdk.gen";
import { AdminOnly, Notice, StepUpLink, StepUpNote } from "../components/admin/common";
import { ListEditor } from "../components/admin/SettingField";
import { Loading, Problem } from "../components/Problem";
import { Time } from "../components/Time";
import { Button } from "../components/ui/button";
import { Card, CardTitle } from "../components/ui/card";
import { Field, TextInput } from "../components/ui/field";
import { jobOptions, jobSettled, settingsOptions } from "../lib/admin";
import { unwrap } from "../lib/call";
import { cn } from "../lib/cn";
import { ApiError } from "../lib/session";
import { allProblems, buildSetup, emptySetup, readInspected, reviewLines, setupOutput, stepProblems, STEPS, type SetupForm, type Step } from "../lib/setup";

type Set = <K extends keyof SetupForm>(key: K, value: SetupForm[K]) => void;

function Err({ text }: { text?: string }) {
  return text ? (
    <p role="alert" className="m-0 text-sm text-danger">
      {text}
    </p>
  ) : null;
}

function Radio({ name, value, checked, onChange, children }: { name: string; value: string; checked: boolean; onChange: () => void; children: ReactNode }) {
  return (
    <label className="flex items-start gap-2 text-sm">
      <input type="radio" name={name} value={value} checked={checked} onChange={onChange} className="mt-1 size-4 accent-accent" />
      <span>{children}</span>
    </label>
  );
}

/** "Check the certificate": argus-admin reads what the address presents; nothing is trusted yet. */
function CertificateCheck({ url, onAnchor, name }: { url: string; onAnchor: (anchor: string | null) => void; name: string }) {
  const [asked, setAsked] = useState<{ url: string; id: number } | null>(null);
  const start = useMutation({
    mutationFn: (u: string) => unwrap(inspectTls({ body: { url: u } })),
    onSuccess: (job, u) => setAsked({ url: u, id: job.id }),
  });
  const current = asked !== null && asked.url === url.trim() ? asked.id : null;
  const job = useQuery(jobOptions(current));
  const seen = job.data !== undefined && jobSettled(job.data) ? readInspected(job.data.result) : null;
  const anchor = seen?.anchor ?? null;
  useEffect(() => {
    onAnchor(anchor);
  }, [anchor, onAnchor]);
  const failure = start.isError ? (start.error instanceof ApiError ? start.error : null) : null;
  const waiting = start.isPending || (current !== null && !jobSettled(job.data));
  return (
    <div className="flex flex-col gap-2" data-testid={`${name}-check`}>
      <div>
        <Button aria-disabled={waiting || url.trim() === ""} onClick={() => !waiting && url.trim() !== "" && start.mutate(url.trim())}>
          {waiting ? "Checking…" : "Check the certificate"}
        </Button>
      </div>
      {failure && (
        <p role="alert" className="m-0 text-sm text-danger">
          {failure.message} {failure.code === "step_up_required" && <StepUpLink />}
        </p>
      )}
      {job.isError && <Err text="The check could not be read. Try again." />}
      {seen?.error && <Err text={seen.error} />}
      {seen && !seen.error && (
        <div className="flex flex-col gap-2 text-sm" data-testid="chain">
          <p className="m-0 text-muted">
            {url.trim()} presented {seen.chain.length === 1 ? "this certificate" : `these ${seen.chain.length} certificates`}. Nothing is trusted yet.
          </p>
          <ol className="m-0 flex list-none flex-col gap-1.5 p-0">
            {seen.chain.map((c) => (
              <li key={c.fingerprint} className="rounded-control border border-border bg-surface-2 p-2">
                <p className="m-0 font-medium">{c.subject}</p>
                <p className="m-0 text-xs text-muted">
                  Issued by {c.self_signed ? "itself (self-signed)" : c.issuer}; valid until {c.not_after.slice(0, 10)}
                </p>
                <p className="m-0 font-mono text-xs break-all">{c.fingerprint}</p>
              </li>
            ))}
          </ol>
          <div className="rounded-control border border-info/40 bg-info-soft p-2 text-info">
            <p className="m-0 font-medium">The certificate authority&apos;s fingerprint (SHA-256)</p>
            <p className="m-0 font-mono text-xs break-all" data-testid="anchor">
              {seen.anchor}
            </p>
            <p className="m-0 mt-1">Ask your SIEM administrator for their authority&apos;s fingerprint and compare. Trust it only if the two are the same.</p>
          </div>
        </div>
      )}
    </div>
  );
}

let zones: string[] | null = null;
function zoneNames(): string[] {
  if (zones === null) {
    try {
      zones = (Intl as unknown as { supportedValuesOf?: (k: string) => string[] }).supportedValuesOf?.("timeZone") ?? [];
    } catch {
      zones = [];
    }
  }
  return zones;
}

function Organisation({ f, set, bad }: { f: SetupForm; set: Set; bad: Record<string, string> }) {
  const zones = zoneNames();
  return (
    <div className="flex flex-col gap-3">
      <Field label="Organisation name" hint="e.g. Example University" htmlFor="o-name">
        <TextInput id="o-name" value={f.name} onChange={(e) => set("name", e.target.value)} />
        <Err text={bad.name} />
      </Field>
      <Field label="Security team's name" hint="shown in the page header and report footers" htmlFor="o-short">
        <TextInput id="o-short" value={f.short_name} onChange={(e) => set("short_name", e.target.value)} />
        <Err text={bad.short_name} />
      </Field>
      <Field label="What kind of organisation" hint="a lower-case noun, e.g. university" htmlFor="o-kind">
        <TextInput id="o-kind" value={f.kind} onChange={(e) => set("kind", e.target.value)} className="max-w-xs" />
        <Err text={bad.kind} />
      </Field>
      <div className="flex flex-col gap-1">
        <span className="text-sm font-medium">Your own domains</span>
        <p className="m-0 text-sm text-muted">ARGUS treats these as inside. At least one.</p>
        <ListEditor id="o-domains" label="Own domains" items={f.own_domains} onChange={(d) => set("own_domains", Array.isArray(d) ? d : [])} disabled={false} />
        <Err text={bad.own_domains} />
      </div>
      <div className="flex flex-col gap-1">
        <span className="text-sm font-medium">Your public networks</span>
        <p className="m-0 text-sm text-muted">Address ranges that belong to you, like 203.0.113.0/24. May be empty.</p>
        <ListEditor id="o-networks" label="Own networks" items={f.own_networks} onChange={(d) => set("own_networks", Array.isArray(d) ? d : [])} disabled={false} />
        <Err text={bad.own_networks} />
      </div>
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Time zone" hint="times are shown in it" htmlFor="o-zone">
          <TextInput id="o-zone" list="zones" value={f.timezone} onChange={(e) => set("timezone", e.target.value)} />
          <datalist id="zones">
            {zones.map((z) => (
              <option key={z} value={z} />
            ))}
          </datalist>
          <Err text={bad.timezone} />
        </Field>
        <Field label="Short label for it" hint="e.g. IST; optional" htmlFor="o-label">
          <TextInput id="o-label" value={f.timezone_label} onChange={(e) => set("timezone_label", e.target.value)} className="max-w-32" />
        </Field>
      </div>
      <Field label="Incident id prefix" hint="incident ids look like SOC-IR-2026-1027-01" htmlFor="o-prefix">
        <TextInput id="o-prefix" value={f.incident_id_prefix} onChange={(e) => set("incident_id_prefix", e.target.value)} className="max-w-xs" />
        <Err text={bad.incident_id_prefix} />
      </Field>
    </div>
  );
}

function Siem({ f, set, bad, anchor, onAnchor }: { f: SetupForm; set: Set; bad: Record<string, string>; anchor: string | null; onAnchor: (a: string | null) => void }) {
  return (
    <div className="flex flex-col gap-3">
      <Field label="The SIEM's address" hint="Elasticsearch, e.g. https://siem.example.org:9200" htmlFor="s-url">
        <TextInput
          id="s-url"
          value={f.siem_url}
          autoComplete="off"
          onChange={(e) => {
            set("siem_url", e.target.value);
            if (f.siem_trust === "chain") {
              set("siem_trust", "");
              set("siem_fingerprint", "");
            }
          }}
        />
        <Err text={bad.siem_url} />
      </Field>
      <CertificateCheck name="siem" url={f.siem_url} onAnchor={onAnchor} />
      <fieldset className="m-0 flex flex-col gap-2 rounded-control border border-border p-3">
        <legend className="px-1 text-sm font-medium">How ARGUS trusts the SIEM&apos;s certificate</legend>
        <TrustChoices
          group="siem-trust"
          trust={f.siem_trust}
          fingerprint={f.siem_fingerprint}
          anchor={anchor}
          onTrust={(t, fp) => {
            set("siem_trust", t === "system" ? "system" : "chain");
            set("siem_fingerprint", fp);
          }}
        />
        <Err text={bad.siem_trust ?? bad.siem_fingerprint} />
      </fieldset>
      <Field label="The read-only API key" hint="stays hidden; it is sealed so only argus-admin can read it" htmlFor="s-key">
        <TextInput id="s-key" type="password" autoComplete="off" spellCheck={false} value={f.siem_key} onChange={(e) => set("siem_key", e.target.value)} className="max-w-xl" />
        <Err text={bad.siem_key} />
      </Field>
      <Field label="When the key expires" hint="a date like 2027-03-01, or 90d from today" htmlFor="s-exp">
        <TextInput id="s-exp" value={f.siem_expires} onChange={(e) => set("siem_expires", e.target.value)} className="max-w-48" />
        <Err text={bad.siem_expires} />
      </Field>
      <div className="flex flex-col gap-1">
        <span className="text-sm font-medium">Index patterns of your logs</span>
        <p className="m-0 text-sm text-muted">The key&apos;s starting role may read these, for example logs-*.</p>
        <ListEditor id="s-patterns" label="Log index patterns" items={f.log_patterns} onChange={(d) => set("log_patterns", Array.isArray(d) ? d : [])} disabled={false} />
        <Err text={bad.log_patterns} />
      </div>
    </div>
  );
}

/** Trust the authority whose fingerprint the check just showed, or say the system already trusts it. */
function TrustChoices({ group, trust, fingerprint, anchor, onTrust }: { group: string; trust: string; fingerprint: string; anchor: string | null; onTrust: (trust: "chain" | "system", fingerprint: string) => void }) {
  return (
    <>
      <Radio name={group} value="chain" checked={trust === "chain"} onChange={() => anchor !== null && onTrust("chain", anchor)}>
        <strong>Trust this certificate authority</strong>
        <span className="block text-muted">Only after you compared its fingerprint with what your SIEM administrator gave you. ARGUS then trusts that authority alone.</span>
        {anchor === null && trust !== "chain" && <span className="block text-muted">Check the certificate first, to choose this.</span>}
        {trust === "chain" && fingerprint !== "" && <span className="block font-mono text-xs break-all">{fingerprint}</span>}
      </Radio>
      <Radio name={group} value="system" checked={trust === "system"} onChange={() => onTrust("system", "")}>
        <strong>My system already trusts it</strong>
        <span className="block text-muted">The certificate comes from an authority this computer already knows (a public one, or one your organisation installed).</span>
      </Radio>
    </>
  );
}

function Kibana({ f, set, bad, anchor, onAnchor }: { f: SetupForm; set: Set; bad: Record<string, string>; anchor: string | null; onAnchor: (a: string | null) => void }) {
  return (
    <div className="flex flex-col gap-3">
      <Radio name="k-use" value="no" checked={!f.use_kibana} onChange={() => set("use_kibana", false)}>
        <strong>I do not use Kibana with ARGUS</strong>
        <span className="block text-muted">ARGUS reads Elasticsearch only. It cannot show or read back cases in Kibana.</span>
      </Radio>
      <Radio name="k-use" value="yes" checked={f.use_kibana} onChange={() => set("use_kibana", true)}>
        <strong>Connect Kibana</strong>
        <span className="block text-muted">ARGUS reads your cases back from it. It writes nothing there until you turn that on in Settings.</span>
      </Radio>
      {f.use_kibana && (
        <>
          <Field label="Kibana's address" hint="e.g. https://siem.example.org:5601" htmlFor="k-url">
            <TextInput id="k-url" value={f.kibana_url} autoComplete="off" onChange={(e) => set("kibana_url", e.target.value)} />
            <Err text={bad.kibana_url} />
          </Field>
          <CertificateCheck name="kibana" url={f.kibana_url} onAnchor={onAnchor} />
          <fieldset className="m-0 flex flex-col gap-2 rounded-control border border-border p-3">
            <legend className="px-1 text-sm font-medium">How ARGUS trusts Kibana&apos;s certificate</legend>
            <Radio name="kibana-trust" value="same" checked={f.kibana_trust === "same"} onChange={() => { set("kibana_trust", "same"); set("kibana_fingerprint", ""); }}>
              <strong>The same authority as the SIEM</strong>
              <span className="block text-muted">Kibana&apos;s certificate comes from the authority you trusted for the SIEM.</span>
            </Radio>
            <TrustChoices
              group="kibana-trust"
              trust={f.kibana_trust}
              fingerprint={f.kibana_fingerprint}
              anchor={anchor}
              onTrust={(t, fp) => {
                set("kibana_trust", t);
                set("kibana_fingerprint", fp);
              }}
            />
            <Err text={bad.kibana_fingerprint} />
          </fieldset>
          <Field label="Kibana's read-only API key" hint="optional; without it Kibana stays off" htmlFor="k-key">
            <TextInput id="k-key" type="password" autoComplete="off" spellCheck={false} value={f.kibana_key} onChange={(e) => set("kibana_key", e.target.value)} className="max-w-xl" />
            <Err text={bad.kibana_key} />
          </Field>
          {f.kibana_key.trim() !== "" && (
            <Field label="When that key expires" hint="a date or 90d" htmlFor="k-exp">
              <TextInput id="k-exp" value={f.kibana_expires} onChange={(e) => set("kibana_expires", e.target.value)} className="max-w-48" />
              <Err text={bad.kibana_expires} />
            </Field>
          )}
          <Field label="Kibana space with the Security alerts" hint="optional; ARGUS finds it when left empty" htmlFor="k-space">
            <TextInput id="k-space" value={f.space} onChange={(e) => set("space", e.target.value)} className="max-w-xs" />
          </Field>
        </>
      )}
    </div>
  );
}

function Review({ f, onJump }: { f: SetupForm; onJump: (s: Step) => void }) {
  return (
    <div className="flex flex-col gap-3">
      <dl className="m-0 grid gap-x-4 gap-y-1 text-sm sm:grid-cols-[12rem_1fr]" data-testid="review">
        {reviewLines(f).map((l) => (
          <div key={l.label} className="contents">
            <dt className="text-muted">{l.label}</dt>
            <dd className="m-0 break-words">{l.value}</dd>
          </div>
        ))}
        <div className="contents">
          <dt className="text-muted">Site discovery</dt>
          <dd className="m-0">ARGUS looks at your SIEM and writes down what it finds (log families, the Kibana space)</dd>
        </div>
        <div className="contents">
          <dt className="text-muted">AI providers</dt>
          <dd className="m-0">off for now; you add them later in Settings</dd>
        </div>
      </dl>
      {allProblems(f) && (
        <Notice tone="warn" testId="review-problem">
          Something above is not filled in correctly.{" "}
          <Button size="sm" onClick={() => onJump(allProblems(f) ?? "organisation")}>
            Go to it
          </Button>
        </Notice>
      )}
    </div>
  );
}

/** The setup job: its output as it comes, then "ARGUS is collecting" or what to fix. */
function Running({ id, onBack }: { id: number; onBack: () => void }) {
  const job = useQuery(jobOptions(id));
  const queries = useQueryClient();
  const done = jobSettled(job.data);
  useEffect(() => {
    if (done) void queries.invalidateQueries({ queryKey: settingsOptions.queryKey });
  }, [done, queries]);
  const out = setupOutput(job.data?.result ?? null);
  const ok = done && job.data?.state === "done" && out.ok;
  return (
    <Card aria-label="The setup" data-testid="running">
      <CardTitle>{!done ? "Running the setup…" : ok ? "ARGUS is collecting" : "The setup did not finish"}</CardTitle>
      {!done && <p className="m-0 mb-2 text-sm text-muted">This takes a few minutes. You can leave this page open; nothing is lost if you close it.</p>}
      {ok && <p className="m-0 mb-2 text-sm">ARGUS is connected and has started collecting alerts. Its first results appear on Today within a few minutes.</p>}
      {done && !ok && <p className="m-0 mb-2 text-sm text-danger">{out.error ?? "The setup stopped with an error. What it said is below; your answers are kept, so fix what it names and run it again."}</p>}
      {job.isError && <Err text="The setup's progress could not be read just now; trying again." />}
      <pre className="m-0 max-h-80 overflow-auto rounded-control border border-border bg-surface-2 p-2 font-mono text-xs whitespace-pre-wrap" role="log" aria-label="What the setup says" data-testid="setup-output">
        {out.lines.length > 0 ? out.lines.join("\n") : done ? "No output." : "Waiting for argus-admin to start it…"}
      </pre>
      {job.data && <p className="m-0 mt-1 text-xs text-muted">Started <Time value={job.data.created_at} />.</p>}
      <div className="mt-3 flex gap-2">
        {ok && (
          <Link to="/" className="inline-flex min-h-8 items-center rounded-control border border-accent bg-accent px-3 text-sm font-medium text-accent-fg no-underline hover:bg-accent-hover">
            Go to Today
          </Link>
        )}
        {done && !ok && <Button onClick={onBack}>Back to fix</Button>}
      </div>
    </Card>
  );
}

function SetupView() {
  const settings = useQuery(settingsOptions);
  const [form, setForm] = useState<SetupForm>(() => emptySetup());
  const [step, setStep] = useState<Step>("organisation");
  const [shown, setShown] = useState(false);
  const [again, setAgain] = useState(false);
  const [job, setJob] = useState<number | null>(null);
  const [siemAnchor, setSiemAnchor] = useState<string | null>(null);
  const [kibanaAnchor, setKibanaAnchor] = useState<string | null>(null);
  const set: Set = (key, value) => setForm((old) => ({ ...old, [key]: value }));
  const run = useMutation({
    mutationFn: () => unwrap(startSetup({ body: buildSetup(form) })),
    onSuccess: (out) => setJob(out.id),
  });
  if (settings.isPending) return <Loading what="the setup" />;
  if (settings.isError) return <Problem error={settings.error} what="The setup" onRetry={() => void settings.refetch()} />;
  const out = settings.data;
  const index = STEPS.findIndex((s) => s.key === step);
  const bad = shown ? stepProblems(step, form) : {};
  const failure = run.isError && run.error instanceof ApiError ? run.error : null;

  function next() {
    setShown(true);
    if (Object.keys(stepProblems(step, form)).length === 0) {
      setStep(STEPS[index + 1]?.key ?? step);
      setShown(false);
    }
  }
  const head = (
    <div className="flex flex-col gap-1">
      <h1 className="m-0 text-2xl font-semibold">First-time setup</h1>
      <p className="m-0 max-w-prose text-sm text-muted">Tell ARGUS about your organisation and connect it to your SIEM. It only reads your SIEM; the keys you give it are read-only.</p>
    </div>
  );
  if (!out.setup_needed && !again && job === null) {
    return (
      <>
        {head}
        <Notice tone="info" testId="already">
          ARGUS is already connected to a SIEM. To change something, use <Link to="/settings">Settings</Link>. Running the setup again replaces the connection.{" "}
          <Button size="sm" onClick={() => setAgain(true)}>
            Run the setup again
          </Button>
        </Notice>
      </>
    );
  }
  return (
    <>
      {head}
      {!out.applier.running && <Notice tone="warn" testId="applier-down">argus-admin is not running: the setup starts when it runs.</Notice>}
      {job !== null ? (
        <Running id={job} onBack={() => { setJob(null); run.reset(); setStep("organisation"); }} />
      ) : (
        <>
          <ol className="m-0 flex list-none flex-wrap gap-2 p-0 text-sm" aria-label="Steps">
            {STEPS.map((s, i) => (
              <li key={s.key} aria-current={s.key === step ? "step" : undefined} className={cn("rounded-full border px-3 py-0.5", s.key === step ? "border-accent bg-accent-soft font-semibold" : "border-border text-muted")}>
                {i + 1}. {s.label}
              </li>
            ))}
          </ol>
          <Card aria-label={STEPS[index]?.label}>
            <CardTitle>{STEPS[index]?.label}</CardTitle>
            {step === "organisation" && <Organisation f={form} set={set} bad={bad} />}
            {step === "siem" && <Siem f={form} set={set} bad={bad} anchor={siemAnchor} onAnchor={setSiemAnchor} />}
            {step === "kibana" && <Kibana f={form} set={set} bad={bad} anchor={kibanaAnchor} onAnchor={setKibanaAnchor} />}
            {step === "review" && <Review f={form} onJump={(s) => { setStep(s); setShown(true); }} />}
          </Card>
          {step === "review" && <StepUpNote />}
          {failure && (
            <Notice tone="danger" role="alert" testId="run-error">
              {failure.message} {failure.code === "step_up_required" && <><StepUpLink /> Then press the button again; your answers are kept here.</>}
            </Notice>
          )}
          <div className="flex flex-wrap gap-2">
            {index > 0 && (
              <Button onClick={() => { setStep(STEPS[index - 1]?.key ?? step); setShown(false); }}>Back</Button>
            )}
            {step !== "review" ? (
              <Button variant="primary" onClick={next}>
                Next
              </Button>
            ) : (
              <Button variant="primary" aria-disabled={run.isPending || allProblems(form) !== null} onClick={() => !run.isPending && allProblems(form) === null && run.mutate()}>
                {run.isPending ? "Starting…" : "Run the setup"}
              </Button>
            )}
          </div>
        </>
      )}
    </>
  );
}

export function Setup() {
  return (
    <AdminOnly what="First-time setup">
      <SetupView />
    </AdminOnly>
  );
}

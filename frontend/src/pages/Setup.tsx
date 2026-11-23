// First-time setup (D-327, D-330): chapters, one question each, then argus-admin runs `argus init`
// with the answers. ARGUS may make its own read-only keys with an Elastic administrator's login
// (used once, sealed, never stored) or take pasted keys; the AI and threat-intel keys and the
// asset map may come along. Everything typed stays in this component's state; the keys go only
// in the final request, to be sealed, and are shown nowhere (the review says "set").
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useCallback, useEffect, useId, useRef, useState, type ComponentProps, type ReactNode } from "react";
import { inspectTls, startSetup } from "../client/sdk.gen";
import type { AiProviderOut } from "../client/types.gen";
import { AdminOnly, StepUpLink } from "../components/admin/common";
import { Loading, Problem } from "../components/Problem";
import { assetFileProblem, jobOptions, jobSettled, settingsOptions } from "../lib/admin";
import { aiOptions } from "../lib/ai";
import { unwrap } from "../lib/call";
import { useNow } from "../lib/now";
import { parse } from "../lib/time";
import { cn } from "../lib/cn";
import { ApiError, can, sessionQuery, useSession } from "../lib/session";
import { allProblems, buildSetup, CA_MAX, currentZone, zoneList, caProblem, errorChapter, loneLeafIssuer, markSetupLeft, tidyUrl, elasticPlan, emptySetup, INTEL, readInspected, reviewLines, runChecklist, setupOutput, stepProblems, STEPS, type SetupForm, type Step } from "../lib/setup";

type Set = <K extends keyof SetupForm>(key: K, value: SetupForm[K]) => void;
type Stage = "intro" | Step | "running";

const listOf = (text: string) => text.split(",").map((x) => x.trim());
const textOf = (list: readonly string[]) => list.filter((x) => x.trim() !== "").join(", ");

function Err({ text }: { text?: string }) {
  return text ? (
    <p role="alert" className="setup-error">
      {text}
    </p>
  ) : null;
}

function Field({ label, hint, children, error, id }: { label: string; hint?: string; children: ReactNode; error?: string; id: string }) {
  return (
    <div>
      <label htmlFor={id} className="setup-label">
        {label} {hint && <span className="setup-hint">{hint}</span>}
      </label>
      {children}
      <Err text={error} />
    </div>
  );
}

function Input(props: ComponentProps<"input">) {
  return <input {...props} className={cn("setup-input", props.className)} />;
}

/** A choice among a few, as big tiles (a radio group). */
function Choices<T extends string>({ label, value, options, onChange }: { label: string; value: T | ""; options: { value: T; title: ReactNode; body: ReactNode }[]; onChange: (v: T) => void }) {
  return (
    <div role="radiogroup" aria-label={label} className="grid gap-3 sm:grid-cols-2">
      {options.map((o) => (
        <button key={o.value} type="button" role="radio" aria-checked={value === o.value} className="setup-choice" onClick={() => onChange(o.value)}>
          <span className="text-lg font-semibold">{o.title}</span>
          <span className="text-[0.9375rem] text-(--s-muted)">{o.body}</span>
        </button>
      ))}
    </div>
  );
}

/** "Check the certificate": argus-admin reads what the address presents; nothing is trusted yet. */
function CertificateCheck({ url: typed, onAnchor, onLeaf, name }: { url: string; onAnchor: (anchor: string | null) => void; onLeaf?: (issuer: string | null) => void; name: string }) {
  const url = tidyUrl(typed);
  const [asked, setAsked] = useState<{ url: string; id: number } | null>(null);
  const start = useMutation({
    mutationFn: (u: string) => unwrap(inspectTls({ body: { url: u } })),
    onSuccess: (job, u) => setAsked({ url: u, id: job.id }),
  });
  const current = asked !== null && asked.url === url ? asked.id : null;
  const job = useQuery(jobOptions(current));
  const seen = job.data !== undefined && jobSettled(job.data) ? readInspected(job.data.result) : null;
  const anchor = seen?.anchor ?? null;
  const leaf = loneLeafIssuer(seen);
  useEffect(() => {
    onAnchor(anchor);
  }, [anchor, onAnchor]);
  useEffect(() => {
    onLeaf?.(leaf);
  }, [leaf, onLeaf]);
  const failure = start.isError ? (start.error instanceof ApiError ? start.error : null) : null;
  const waiting = start.isPending || (current !== null && !jobSettled(job.data));
  return (
    <div className="flex flex-col gap-3" data-testid={`${name}-check`}>
      <div>
        <button type="button" className="setup-pill setup-pill-quiet" aria-disabled={waiting || url === ""} onClick={() => !waiting && url !== "" && start.mutate(url)}>
          {waiting ? "Checking…" : "Check the certificate"}
        </button>
      </div>
      {failure && (
        <p role="alert" className="setup-error">
          {failure.message} {failure.code === "step_up_required" && <StepUpLink />}
        </p>
      )}
      {job.isError && <Err text="The check could not be read. Try again." />}
      {seen?.error && <Err text={seen.error} />}
      {seen && !seen.error && (
        <div className="flex flex-col gap-2 text-[0.9375rem]" data-testid="chain">
          <p className="m-0 text-(--s-muted)">
            {url} presented {seen.chain.length === 1 ? "this certificate" : `these ${seen.chain.length} certificates`}. Nothing is trusted yet.
          </p>
          <ol className="m-0 flex list-none flex-col gap-2 p-0">
            {seen.chain.map((c) => (
              <li key={c.fingerprint} className="rounded-2xl bg-(--s-bg) p-3">
                <p className="m-0 font-medium">{c.subject}</p>
                <p className="m-0 text-sm text-(--s-muted)">
                  Issued by {c.self_signed ? "itself (self-signed)" : c.issuer}; valid until {c.not_after.slice(0, 10)}
                </p>
                <p className="m-0 font-mono text-xs break-all">{c.fingerprint}</p>
              </li>
            ))}
          </ol>
          <div className="rounded-2xl border border-(--s-line) p-3">
            <p className="m-0 font-medium">The certificate authority&apos;s fingerprint (SHA-256)</p>
            <p className="m-0 font-mono text-xs break-all" data-testid="anchor">
              {seen.anchor}
            </p>
            <p className="m-0 mt-1 text-(--s-muted)">Ask your SIEM administrator for their authority&apos;s fingerprint and compare. Trust it only if the two are the same.</p>
          </div>
        </div>
      )}
    </div>
  );
}

/** Trust the authority the check just showed, or say the system already trusts it. */
type TrustWay = "chain" | "system" | "same" | "file";

function Trust({ trust, anchor, fingerprint, onTrust, same }: { trust: string; anchor: string | null; fingerprint: string; onTrust: (trust: TrustWay, fingerprint: string) => void; same?: boolean }) {
  const options: { value: TrustWay; title: ReactNode; body: ReactNode }[] = [
    {
      value: "chain",
      title: "Trust this certificate authority",
      body: (
        <>
          Only after you compared its fingerprint with your SIEM administrator&apos;s.
          {anchor === null && trust !== "chain" && <> Check the certificate first.</>}
          {trust === "chain" && fingerprint !== "" && <span className="mt-1 block font-mono text-xs break-all">{fingerprint}</span>}
        </>
      ),
    },
    { value: "system", title: "My system already trusts it", body: "It comes from an authority this computer already knows: a public one, or one your organisation installed." },
    { value: "file", title: "Upload the CA certificate", body: "The certificate of the authority that signed it, as a .pem, .crt or .cer file, or pasted." },
  ];
  if (same) options.unshift({ value: "same", title: "The same authority as the SIEM", body: "Kibana's certificate comes from the authority you trusted for the SIEM." });
  return (
    <Choices
      label="How ARGUS trusts the certificate"
      value={trust as TrustWay | ""}
      options={options}
      onChange={(v) => {
        if (v === "chain") {
          if (anchor !== null) onTrust("chain", anchor);
        } else onTrust(v, "");
      }}
    />
  );
}

/** The CA certificate, from a file or pasted: read here, checked, sent as text with the answers. */
function CaUpload({ value, onChange, path, onPath, error, what }: { value: { name: string; pem: string } | null; onChange: (ca: { name: string; pem: string } | null) => void; path: string; onPath: (path: string) => void; error?: string; what: string }) {
  const id = useId();
  const [refusal, setRefusal] = useState<string | null>(null);
  async function choose(file: File | undefined) {
    setRefusal(null);
    if (file === undefined) return;
    if (file.size > CA_MAX) return setRefusal("That is larger than 64 KB: a CA certificate is a few KB.");
    const pem = await file.text();
    const why = caProblem(file.name, pem);
    if (why !== null) return setRefusal(why);
    onChange({ name: file.name, pem });
  }
  return (
    <div className="setup-tile flex flex-col gap-3" data-testid={`${what}-ca`}>
      {value !== null && value.name !== "" ? (
        <p className="m-0 flex flex-wrap items-center gap-3">
          <span className="setup-check" data-state="done" aria-hidden="true">
            ✓
          </span>
          <span>
            <strong>{value.name}</strong> will be trusted for the {what === "siem" ? "SIEM" : "Kibana"} address.
          </span>
          <button type="button" className="setup-link" onClick={() => onChange(null)}>
            Remove
          </button>
        </p>
      ) : (
        <>
          <div>
            <label htmlFor={`${id}-file`} className="setup-label">
              The CA certificate file <span className="setup-hint">.pem, .crt or .cer</span>
            </label>
            <input id={`${id}-file`} type="file" accept=".pem,.crt,.cer" className="text-[0.9375rem]" onChange={(e) => void choose(e.target.files?.[0])} />
          </div>
          <div>
            <label htmlFor={`${id}-paste`} className="setup-label">
              Or paste it <span className="setup-hint">the text from -----BEGIN CERTIFICATE----- to the END line</span>
            </label>
            <textarea id={`${id}-paste`} rows={4} spellCheck={false} className="setup-input font-mono text-xs" value={value?.pem ?? ""} onChange={(e) => onChange(e.target.value.trim() === "" ? null : { name: "", pem: e.target.value })} />
          </div>
          {value === null && (
            <div>
              <label htmlFor={`${id}-path`} className="setup-label">
                Or the path of the file on the ARGUS server <span className="setup-hint">when Elastic runs on this machine</span>
              </label>
              <Input id={`${id}-path`} value={path} placeholder="/etc/elasticsearch/certs/ca/ca.crt" autoComplete="off" spellCheck={false} className="font-mono" onChange={(e) => onPath(e.target.value)} />
            </div>
          )}
        </>
      )}
      <Err text={refusal ?? error} />
    </div>
  );
}

function Organisation({ f, set, bad }: { f: SetupForm; set: Set; bad: Record<string, string> }) {
  const id = useId();
  const [zones] = useState(() => zoneList());
  return (
    <div className="setup-tile grid gap-5 sm:grid-cols-2">
      <div className="sm:col-span-2">
        <Field id={`${id}-name`} label="Organisation name" hint="e.g. Northwind Logistics" error={bad.name}>
          <Input id={`${id}-name`} value={f.name} onChange={(e) => set("name", e.target.value)} />
        </Field>
      </div>
      <Field id={`${id}-short`} label="Security team's name" hint="in the header and reports" error={bad.short_name}>
        <Input id={`${id}-short`} value={f.short_name} onChange={(e) => set("short_name", e.target.value)} />
      </Field>
      <Field id={`${id}-kind`} label="What kind of organisation" hint="e.g. company, hospital, university" error={bad.kind}>
        <Input id={`${id}-kind`} value={f.kind} onChange={(e) => set("kind", e.target.value)} />
      </Field>
      <div className="sm:col-span-2">
        <Field id={`${id}-domains`} label="Your own domains" error={bad.own_domains}>
          <p className="m-0 mb-2 text-[0.9375rem] text-(--s-muted)">Your domain, e.g. example.edu: every subdomain (mail.example.edu, cs.example.edu) is included. Add a row for each other domain you own.</p>
          <Rows id={`${id}-domains`} label="Your own domains" items={f.own_domains} placeholder="example.edu" add="Add another domain" onChange={(v) => set("own_domains", v)} />
        </Field>
      </div>
      <div className="sm:col-span-2">
        <Field id={`${id}-networks`} label="Your public networks" hint="optional" error={bad.own_networks}>
          <p className="m-0 mb-2 text-[0.9375rem] text-(--s-muted)">Your public ranges, e.g. 203.0.113.0/24, one per row. Private ranges (10.x, 172.16–31.x, 192.168.x) are always yours.</p>
          <Rows id={`${id}-networks`} label="Your public networks" items={f.own_networks} placeholder="203.0.113.0/24" add="Add another range" onChange={(v) => set("own_networks", v)} />
        </Field>
      </div>
      <Field id={`${id}-zone`} label="Time zone" hint="times are shown in it" error={bad.timezone}>
        <Input id={`${id}-zone`} list={`${id}-zones`} value={f.timezone} onBlur={(e) => set("timezone", currentZone(e.target.value))} onChange={(e) => set("timezone", e.target.value)} />
        <datalist id={`${id}-zones`}>
          {zones.map((z) => (
            <option key={z} value={z} />
          ))}
        </datalist>
      </Field>
      <Field id={`${id}-label`} label="Short label for it" hint="optional, e.g. CET">
        <Input id={`${id}-label`} value={f.timezone_label} onChange={(e) => set("timezone_label", e.target.value)} />
      </Field>
      <Field id={`${id}-prefix`} label="Incident id prefix" hint="ids look like SOC-IR-2026-1027-01" error={bad.incident_id_prefix}>
        <Input id={`${id}-prefix`} value={f.incident_id_prefix} onChange={(e) => set("incident_id_prefix", e.target.value)} />
      </Field>
      <p className="m-0 text-sm text-(--s-muted) sm:col-span-2">You can change these later in Settings → Organisation and data sources.</p>
    </div>
  );
}

/** A list typed one item per row, with a row added or removed by the person. */
function Rows({ id, label, items, placeholder, add, onChange }: { id: string; label: string; items: string[]; placeholder: string; add: string; onChange: (items: string[]) => void }) {
  const rows = items.length === 0 ? [""] : items;
  return (
    <div role="group" aria-label={label} className="flex flex-col gap-2">
      {rows.map((value, i) => (
        <div key={i} className="flex items-center gap-3">
          <Input id={i === 0 ? id : undefined} aria-label={`${label}, row ${i + 1}`} value={value} placeholder={placeholder} autoComplete="off" spellCheck={false} onChange={(e) => onChange(rows.map((x, j) => (j === i ? e.target.value : x)))} />
          {rows.length > 1 && (
            <button type="button" className="setup-link text-[0.9375rem]" aria-label={`Remove row ${i + 1} of ${label.toLowerCase()}`} onClick={() => onChange(rows.filter((_, j) => j !== i))}>
              Remove
            </button>
          )}
        </div>
      ))}
      <div>
        <button type="button" className="setup-link text-[0.9375rem]" onClick={() => onChange([...rows, ""])}>
          + {add}
        </button>
      </div>
    </div>
  );
}

/** What to say when a server sends only its own certificate: its CA has to be uploaded. */
function LeafNote({ issuer, what }: { issuer: string; what: string }) {
  return (
    <p role="status" className="m-0 rounded-2xl border border-(--s-line) p-4 text-[0.9375rem]" data-testid="lone-leaf">
      Your {what} sends only its own certificate, signed by <strong>{issuer}</strong>. Upload that CA&apos;s certificate (on an Elastic server it is often <code>config/certs/ca/ca.crt</code>, or ask your Elastic administrator), or give its path on this server if Elastic runs here.
    </p>
  );
}

function Siem({ f, set, bad, anchor, onAnchor }: { f: SetupForm; set: Set; bad: Record<string, string>; anchor: string | null; onAnchor: (a: string | null) => void }) {
  const id = useId();
  const [leaf, setLeaf] = useState<string | null>(null);
  const trust = f.siem_trust;
  const onLeaf = useCallback(
    (issuer: string | null) => {
      setLeaf(issuer);
      if (issuer !== null && trust === "") set("siem_trust", "file");
    },
    [trust, set],
  );
  const [patterns, setPatterns] = useState(() => textOf(f.log_patterns));
  return (
    <div className="flex flex-col gap-4">
      <div className="setup-tile flex flex-col gap-4">
        <Field id={`${id}-url`} label="The SIEM's address" hint="Elasticsearch, e.g. https://siem.example.org:9200" error={bad.siem_url}>
          <Input
            id={`${id}-url`}
            value={f.siem_url}
            autoComplete="off"
            spellCheck={false}
            onBlur={(e) => set("siem_url", tidyUrl(e.target.value))}
            onChange={(e) => {
              set("siem_url", e.target.value);
              if (f.siem_trust === "chain") {
                set("siem_trust", "");
                set("siem_fingerprint", "");
              }
            }}
          />
        </Field>
        <CertificateCheck name="siem" url={f.siem_url} onAnchor={onAnchor} onLeaf={onLeaf} />
      </div>
      {leaf !== null && <LeafNote issuer={leaf} what="SIEM" />}
      <Trust
        trust={f.siem_trust}
        anchor={anchor}
        fingerprint={f.siem_fingerprint}
        onTrust={(t, fp) => {
          set("siem_trust", t === "same" ? "system" : t);
          set("siem_fingerprint", fp);
        }}
      />
      <Err text={bad.siem_trust ?? bad.siem_fingerprint} />
      {f.siem_trust === "file" && <CaUpload what="siem" value={f.siem_ca} onChange={(ca) => set("siem_ca", ca)} path={f.siem_ca_path} onPath={(p) => set("siem_ca_path", p)} error={bad.siem_ca} />}
      <div className="setup-tile">
        <Field id={`${id}-patterns`} label="Index patterns of your logs" hint="separated by commas, e.g. logs-*" error={bad.log_patterns}>
          <Input
            id={`${id}-patterns`}
            value={patterns}
            onChange={(e) => {
              setPatterns(e.target.value);
              set("log_patterns", listOf(e.target.value));
            }}
          />
        </Field>
      </div>
    </div>
  );
}

function Access({ f, set, bad }: { f: SetupForm; set: Set; bad: Record<string, string> }) {
  const id = useId();
  return (
    <div className="flex flex-col gap-4">
      <Choices
        label="How ARGUS gets its access"
        value={f.access}
        onChange={(v) => set("access", v)}
        options={[
          {
            value: "login",
            title: (
              <>
                Let ARGUS create its own access <span className="ml-1 rounded-full bg-(--s-accent) px-2 py-0.5 align-middle text-xs font-medium text-white">Recommended</span>
              </>
            ),
            body: "An Elastic administrator signs in once. ARGUS makes read-only keys for itself and, if you like, its Kibana case team. The login is used once and never stored.",
          },
          { value: "paste", title: "Paste read-only keys", body: "You make the keys in Kibana's Dev Tools yourself and paste them here." },
        ]}
      />
      <Err text={bad.access} />
      {f.access === "login" && (
        <div className="setup-tile flex flex-col gap-4">
          <div className="grid gap-4 sm:grid-cols-2">
            <Field id={`${id}-user`} label="Administrator's user name" error={bad.admin_user}>
              <Input id={`${id}-user`} value={f.admin_user} autoComplete="off" spellCheck={false} onChange={(e) => set("admin_user", e.target.value)} />
            </Field>
            <Field id={`${id}-password`} label="Password" hint="used once, never stored" error={bad.admin_password}>
              <Input id={`${id}-password`} type="password" value={f.admin_password} autoComplete="off" onChange={(e) => set("admin_password", e.target.value)} />
            </Field>
          </div>
          <label className="flex items-start gap-3 text-[0.9375rem]">
            <input type="checkbox" className="mt-1 size-5 accent-(--s-accent)" checked={f.provision_team} onChange={(e) => set("provision_team", e.target.checked)} />
            <span>
              <strong>ARGUS&apos;s own team (recommended)</strong>
              <span className="block text-(--s-muted)">The tested default pack: seven Kibana users that write confirmed incidents as cases, each with its own key. Posting stays off until you switch it on. Needs Kibana.</span>
            </span>
          </label>
          <p className="m-0 text-sm text-(--s-muted)">The login needs the right to make API keys (manage_api_key or manage_security). It is sealed in this browser, used by argus-admin for this run only, and deleted with it.</p>
        </div>
      )}
      {f.access === "paste" && (
        <div className="setup-tile grid gap-4 sm:grid-cols-[1fr_12rem]">
          <Field id={`${id}-key`} label="The read-only API key" hint="its encoded form" error={bad.siem_key}>
            <Input id={`${id}-key`} type="password" autoComplete="off" spellCheck={false} value={f.siem_key} onChange={(e) => set("siem_key", e.target.value)} />
          </Field>
          <Field id={`${id}-expires`} label="Expires" hint="a date or 90d" error={bad.siem_expires}>
            <Input id={`${id}-expires`} value={f.siem_expires} onChange={(e) => set("siem_expires", e.target.value)} />
          </Field>
        </div>
      )}
    </div>
  );
}

function Kibana({ f, set, bad, anchor, onAnchor }: { f: SetupForm; set: Set; bad: Record<string, string>; anchor: string | null; onAnchor: (a: string | null) => void }) {
  const id = useId();
  const [leaf, setLeaf] = useState<string | null>(null);
  return (
    <div className="flex flex-col gap-4">
      <Choices
        label="Kibana"
        value={f.use_kibana ? "yes" : "no"}
        onChange={(v) => set("use_kibana", v === "yes")}
        options={[
          { value: "yes", title: "Connect Kibana", body: "ARGUS reads your cases back from it; it writes nothing there until you switch that on." },
          { value: "no", title: "Not now", body: "ARGUS reads Elasticsearch only. You can connect Kibana later in Settings." },
        ]}
      />
      {f.use_kibana && (
        <>
          <div className="setup-tile flex flex-col gap-4">
            <Field id={`${id}-url`} label="Kibana's address" hint="e.g. https://siem.example.org:5601" error={bad.kibana_url}>
              <Input id={`${id}-url`} value={f.kibana_url} autoComplete="off" spellCheck={false} onBlur={(e) => set("kibana_url", tidyUrl(e.target.value))} onChange={(e) => set("kibana_url", e.target.value)} />
            </Field>
            <CertificateCheck name="kibana" url={f.kibana_url} onAnchor={onAnchor} onLeaf={setLeaf} />
          </div>
          {leaf !== null && <LeafNote issuer={leaf} what="Kibana" />}
          <Trust
            same
            trust={f.kibana_trust}
            anchor={anchor}
            fingerprint={f.kibana_fingerprint}
            onTrust={(t, fp) => {
              set("kibana_trust", t);
              set("kibana_fingerprint", fp);
            }}
          />
          <Err text={bad.kibana_fingerprint} />
          {f.kibana_trust === "file" && <CaUpload what="kibana" value={f.kibana_ca} onChange={(ca) => set("kibana_ca", ca)} path={f.kibana_ca_path} onPath={(p) => set("kibana_ca_path", p)} error={bad.kibana_ca} />}
          <div className="setup-tile grid gap-4 sm:grid-cols-2">
            {f.access !== "login" && (
              <>
                <Field id={`${id}-key`} label="Kibana's read-only API key" hint="optional; without it Kibana stays off" error={bad.kibana_key}>
                  <Input id={`${id}-key`} type="password" autoComplete="off" spellCheck={false} value={f.kibana_key} onChange={(e) => set("kibana_key", e.target.value)} />
                </Field>
                <Field id={`${id}-exp`} label="When that key expires" hint="a date or 90d" error={bad.kibana_expires}>
                  <Input id={`${id}-exp`} value={f.kibana_expires} onChange={(e) => set("kibana_expires", e.target.value)} />
                </Field>
              </>
            )}
            <Field id={`${id}-space`} label="Kibana space with the Security alerts" hint="optional; found when empty">
              <Input id={`${id}-space`} value={f.space} onChange={(e) => set("space", e.target.value)} />
            </Field>
          </div>
        </>
      )}
    </div>
  );
}

function Ai({ f, set, bad, providers }: { f: SetupForm; set: Set; bad: Record<string, string>; providers: AiProviderOut[] | null }) {
  const id = useId();
  if (providers === null) return <p className="setup-sub">The AI providers could not be read just now. Add their keys after the setup in AI and agents.</p>;
  const shown = providers.filter((p) => p.keys.length > 0);
  if (shown.length === 0) return <p className="setup-sub">No AI provider is listed on this server. You can add one later.</p>;
  return (
    <ul className="setup-tile m-0 flex list-none flex-col divide-y divide-(--s-line) p-0">
      {shown.map((p) => {
        const key = p.keys[0]?.name ?? "";
        return (
          <li key={p.name} className="grid items-center gap-3 px-6 py-4 sm:grid-cols-[12rem_1fr]">
            <label htmlFor={`${id}-${p.name}`} className="flex flex-col">
              <span className="text-lg font-semibold">{p.name}</span>
              <span className="text-sm text-(--s-muted)">{p.paid ? "Paid, capped by your limits" : "Free"}</span>
            </label>
            <div>
              <Input id={`${id}-${p.name}`} type="password" autoComplete="off" spellCheck={false} placeholder={key} aria-describedby={`${id}-${p.name}-k`} value={f.ai_keys[key] ?? ""} onChange={(e) => set("ai_keys", { ...f.ai_keys, [key]: e.target.value })} />
              <span id={`${id}-${p.name}-k`} className="sr-only">
                {key}
              </span>
              <Err text={bad[`ai.${key}`]} />
            </div>
          </li>
        );
      })}
    </ul>
  );
}

function Intel({ f, set, bad }: { f: SetupForm; set: Set; bad: Record<string, string> }) {
  const id = useId();
  return (
    <ul className="setup-tile m-0 flex list-none flex-col divide-y divide-(--s-line) p-0">
      {INTEL.map((s) => (
        <li key={s.key} className="grid items-center gap-3 px-6 py-4 sm:grid-cols-[12rem_1fr]">
          <label htmlFor={`${id}-${s.key}`} className="flex flex-col">
            <span className="text-lg font-semibold">{s.name}</span>
            <span className="text-sm text-(--s-muted)">{s.gives}</span>
          </label>
          <div>
            <Input id={`${id}-${s.key}`} type="password" autoComplete="off" spellCheck={false} placeholder="Its API key" value={f.intel_keys[s.key]} onChange={(e) => set("intel_keys", { ...f.intel_keys, [s.key]: e.target.value })} />
            <Err text={bad[`intel.${s.key}`]} />
          </div>
        </li>
      ))}
    </ul>
  );
}

function Assets({ f, set }: { f: SetupForm; set: Set }) {
  const id = useId();
  const [refusal, setRefusal] = useState<string | null>(null);
  async function choose(file: File | undefined) {
    setRefusal(null);
    if (file === undefined) return;
    const why = assetFileProblem(file.name, file.size);
    if (why !== null) return setRefusal(why);
    const content = await file.text();
    if (content.trim() === "") return setRefusal("The file is empty.");
    set("asset_map", { name: file.name, content });
  }
  return (
    <div className="setup-tile flex flex-col gap-4">
      <p className="m-0 text-[1.0625rem]">Before ARGUS asks an AI or an outside source about anything, it needs to know which addresses are yours and what they are. That is the asset map: a YAML file of your networks, devices and their owners, at most 5 MB.</p>
      {f.asset_map === null ? (
        <div>
          <label htmlFor={id} className="setup-label">
            Choose the asset map file
          </label>
          <input id={id} type="file" accept=".yaml,.yml" className="text-[0.9375rem]" onChange={(e) => void choose(e.target.files?.[0])} />
        </div>
      ) : (
        <p className="m-0 flex flex-wrap items-center gap-3" data-testid="asset-chosen">
          <span className="setup-check" data-state="done" aria-hidden="true">
            ✓
          </span>
          <span>
            <strong>{f.asset_map.name}</strong> is ready; it is sent sealed and imported after the setup.
          </span>
          <button type="button" className="setup-link" onClick={() => set("asset_map", null)}>
            Remove
          </button>
        </p>
      )}
      <Err text={refusal ?? undefined} />
      <p className="m-0 text-sm text-(--s-muted)">You can also add it, or a newer one, later in Settings → Asset map.</p>
    </div>
  );
}

function Review({ f, onJump }: { f: SetupForm; onJump: (s: Step) => void }) {
  const plan = elasticPlan(f);
  const wrong = allProblems(f);
  return (
    <div className="flex flex-col gap-4">
      {plan.length > 0 && (
        <div className="setup-tile" data-testid="elastic-plan">
          <h2 className="m-0 mb-2 text-xl font-semibold">ARGUS will create in Elastic</h2>
          <ul className="m-0 flex flex-col gap-1 pl-5 text-[0.9375rem]">
            {plan.map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
          <p className="m-0 mt-2 text-sm text-(--s-muted)">Then it forgets the administrator&apos;s login.</p>
        </div>
      )}
      <dl className="setup-tile m-0 grid gap-x-6 gap-y-2 text-[0.9375rem] sm:grid-cols-[12rem_1fr]" data-testid="review">
        {reviewLines(f).map((l) => (
          <div key={l.label} className="contents">
            <dt className="text-(--s-muted)">{l.label}</dt>
            <dd className="m-0 break-words">{l.value}</dd>
          </div>
        ))}
      </dl>
      {wrong && (
        <p role="status" className="setup-error" data-testid="review-problem">
          Something is not filled in correctly.{" "}
          <button type="button" className="setup-link" onClick={() => onJump(wrong)}>
            Go to it ›
          </button>
        </p>
      )}
    </div>
  );
}

/** The run: its checklist while argus-admin works, then the finale (or what to fix). */
function Running({ id, f, onBack }: { id: number; f: SetupForm; onBack: (to: Step | null) => void }) {
  const job = useQuery(jobOptions(id));
  const queries = useQueryClient();
  const done = jobSettled(job.data);
  useEffect(() => {
    if (!done) return;
    void queries.invalidateQueries({ queryKey: settingsOptions.queryKey });
    void queries.invalidateQueries({ queryKey: sessionQuery.queryKey }); // the setup is no longer pending
    markSetupLeft();
  }, [done, queries]);
  const out = setupOutput(job.data?.result ?? null);
  const ok = done && job.data?.state === "done" && out.ok;
  const steps = runChecklist(f);
  const head = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    head.current?.focus();
  }, [ok, done]);
  if (ok) {
    return (
      <section className="cine setup flex min-h-screen flex-col items-center justify-center px-4 py-16 text-center" data-testid="running" aria-labelledby="setup-ready">
        <div className="setup-chapter flex max-w-3xl flex-col items-center gap-6">
          <h1 id="setup-ready" ref={head} tabIndex={-1} className="setup-h">
            ARGUS is <span className="setup-grad">ready.</span>
          </h1>
          <p className="setup-sub">It is connected and has started collecting alerts. Its first results appear on Today within a few minutes.</p>
          <Link to="/" className="setup-pill">
            Open Today
          </Link>
          {out.after.length > 0 && (
            <ul className="m-0 flex list-none flex-col gap-1 p-0 text-left text-[0.9375rem]" data-testid="setup-after">
              {out.after.map((line) => (
                <li key={line} className="flex items-start gap-2">
                  <span aria-hidden="true" className="text-(--s-ok)">
                    ✓
                  </span>
                  {line}
                </li>
              ))}
            </ul>
          )}
          <details className="w-full max-w-2xl text-left">
            <summary className="setup-link cursor-pointer">What the setup said ›</summary>
            <pre className="m-0 mt-2 max-h-72 overflow-auto rounded-2xl bg-(--s-tile) p-3 font-mono text-xs whitespace-pre-wrap" role="log" aria-label="What the setup says" data-testid="setup-output">
              {out.lines.length > 0 ? out.lines.join("\n") : "No output."}
            </pre>
          </details>
        </div>
      </section>
    );
  }
  return (
    <section className="mx-auto flex w-full max-w-3xl flex-col gap-8 px-4 py-16" data-testid="running" aria-labelledby="setup-run">
      <div className="setup-chapter flex flex-col gap-4">
        <h1 id="setup-run" ref={head} tabIndex={-1} className="setup-h">
          {done ? "The setup did not finish." : "Setting up ARGUS."}
        </h1>
        <p className="setup-sub">{done ? (out.error ?? "It stopped with an error. What it said is below; your answers are kept, so fix what it names and run it again.") : "This takes a few minutes. You can leave this page open; nothing is lost if you close it."}</p>
      </div>
      <ol className="setup-tile m-0 flex list-none flex-col gap-4 p-6" aria-label="What the setup does" aria-busy={!done}>
        {steps.map((s, i) => (
          <li key={s} className="flex items-center gap-4 text-[1.0625rem]">
            <span className="setup-check" data-state={done ? "failed" : i === 0 ? "working" : "waiting"} aria-hidden="true">
              {done ? "!" : ""}
            </span>
            {s}
          </li>
        ))}
      </ol>
      {job.isError && <Err text="The setup's progress could not be read just now; trying again." />}
      <details open={done}>
        <summary className="setup-link cursor-pointer">What the setup says ›</summary>
        <pre className="m-0 mt-2 max-h-80 overflow-auto rounded-2xl bg-(--s-tile) p-3 font-mono text-xs whitespace-pre-wrap" role="log" aria-label="What the setup says" data-testid="setup-output">
          {out.lines.length > 0 ? out.lines.join("\n") : done ? "No output." : "Waiting for argus-admin to start it…"}
        </pre>
      </details>
      {done && (
        <div>
          <button type="button" className="setup-pill" onClick={() => onBack(errorChapter([out.error ?? "", ...out.lines].join("\n")))}>
            Back to fix
          </button>
        </div>
      )}
    </section>
  );
}

function Intro({ already, applierDown, onBegin, exit }: { already: boolean; applierDown: boolean; onBegin: () => void; exit: ReactNode }) {
  const [more, setMore] = useState(false);
  return (
    <section className="cine setup relative flex min-h-screen flex-col items-center justify-center px-4 py-16 text-center" aria-labelledby="setup-intro">
      <div className="absolute inset-x-0 top-0">{exit}</div>
      <div className="setup-chapter flex max-w-3xl flex-col items-center gap-6">
        <p className="m-0 text-sm font-semibold tracking-[0.2em] text-(--s-muted)">ARGUS</p>
        <h1 id="setup-intro" className="setup-h">
          {already ? (
            <>
              ARGUS is <span className="setup-grad">connected.</span>
            </>
          ) : (
            <>
              Meet your <span className="setup-grad">first‑line analyst.</span>
            </>
          )}
        </h1>
        <p className="setup-sub">{already ? "Running the setup again replaces the connection to your SIEM. To change one thing, use Settings." : "It watches every alert of your SIEM, groups and investigates them, and leaves your team a short, explained queue. Setting it up takes a few minutes."}</p>
        {applierDown && <p className="setup-error">argus-admin is not running: the setup starts when it runs.</p>}
        <div className="flex flex-wrap items-center justify-center gap-4">
          {already ? (
            <>
              <Link to="/" className="setup-pill">
                Open Today
              </Link>
              <button type="button" className="setup-pill setup-pill-quiet" onClick={onBegin} data-testid="already">
                Run the setup again
              </button>
            </>
          ) : (
            <>
              <button type="button" className="setup-pill" onClick={onBegin}>
                Begin
              </button>
              <button type="button" className="setup-link" aria-expanded={more} onClick={() => setMore((m) => !m)}>
                What you need ›
              </button>
            </>
          )}
        </div>
        {more && (
          <ul className="m-0 flex list-none flex-col gap-1 p-0 text-[1.0625rem] text-(--s-muted)">
            <li>Your SIEM&apos;s address</li>
            <li>An Elastic administrator&apos;s login, or read-only keys you made</li>
            <li>Optional: Kibana, AI and threat-intel keys, your asset map</li>
          </ul>
        )}
      </div>
    </section>
  );
}

function Progress({ index }: { index: number }) {
  const steps = STEPS.length;
  return (
    <div className="flex flex-col gap-3">
      <div className="setup-progress" role="progressbar" aria-label="Setup progress" aria-valuemin={1} aria-valuemax={steps} aria-valuenow={index + 1} aria-valuetext={`Step ${index + 1} of ${steps}: ${STEPS[index]?.label ?? ""}`}>
        {/* the width is set through the CSSOM: the policy refuses a style attribute */}
        <span ref={(el) => el?.style.setProperty("width", `${((index + 1) / steps) * 100}%`)} />
      </div>
      <ol className="m-0 flex list-none items-center gap-2 p-0" aria-label="Steps">
        {STEPS.map((s, i) => (
          <li key={s.key} className="setup-dot" data-state={i < index ? "done" : i === index ? "current" : "next"} aria-current={i === index ? "step" : undefined}>
            <span className="sr-only">
              {i + 1}. {s.label}
            </span>
          </li>
        ))}
      </ol>
    </div>
  );
}

function SetupView() {
  const session = useSession();
  const settings = useQuery(settingsOptions);
  const ai = useQuery({ ...aiOptions, enabled: can(session.data, "admin") });
  const [form, setForm] = useState<SetupForm>(() => emptySetup());
  const [stage, setStage] = useState<Stage>("intro");
  const [shown, setShown] = useState(false);
  const [job, setJob] = useState<number | null>(null);
  const [siemAnchor, setSiemAnchor] = useState<string | null>(null);
  const [kibanaAnchor, setKibanaAnchor] = useState<string | null>(null);
  const head = useRef<HTMLHeadingElement>(null);
  const set: Set = (key, value) => setForm((old) => ({ ...old, [key]: value }));
  const [autoRun, setAutoRun] = useState(false);
  const until = parse(session.data?.step_up_valid_until);
  const now = useNow(15_000);
  const fresh = until !== null && until.getTime() > now;
  const run = useMutation({
    mutationFn: () => unwrap(startSetup({ body: buildSetup(form) })),
    onSuccess: (out) => {
      setJob(out.id);
      setStage("running");
    },
  });
  useEffect(() => {
    if (stage !== "intro" && stage !== "running") head.current?.focus();
  }, [stage]);
  /** Once the password is confirmed in the other tab: the setup asked for runs by itself. */
  const runWhenReady = () => {
    if (stage === "review" && allProblems(form) === null && !run.isPending) {
      setAutoRun(true);
      run.mutate();
    }
  };
  if (settings.isPending) return <Loading what="the setup" />;
  if (settings.isError) return <Problem error={settings.error} what="The setup" onRetry={() => void settings.refetch()} />;
  const out = settings.data;
  const exit = (
    <header className="mx-auto flex w-full max-w-5xl items-center justify-between px-4 py-4">
      <span className="text-sm font-semibold tracking-[0.2em]">ARGUS</span>
      <Link to="/" className="setup-link text-[0.9375rem]" onClick={markSetupLeft}>
        Exit setup
      </Link>
    </header>
  );
  if (stage === "intro") {
    return (
      <div className="setup">
        <Intro already={!out.setup_needed} applierDown={!out.applier.running} onBegin={() => setStage("organisation")} exit={exit} />
      </div>
    );
  }
  if (stage === "running" && job !== null) {
    return (
      <div className="setup">
        {exit}
        <Running
          id={job}
          f={form}
          onBack={(to) => {
            setJob(null);
            run.reset();
            setStage(to ?? "review");
            setShown(to !== null);
          }}
        />
      </div>
    );
  }
  const step = stage as Step;
  const index = STEPS.findIndex((s) => s.key === step);
  const chapter = STEPS[index] ?? STEPS[0];
  const bad = shown ? stepProblems(step, form) : {};
  const failure = run.isError && run.error instanceof ApiError ? run.error : null;
  const go = (to: Step) => {
    setStage(to);
    setShown(false);
  };
  function next() {
    setShown(true);
    if (Object.keys(stepProblems(step, form)).length === 0) go(STEPS[index + 1]?.key ?? step);
  }
  function skip() {
    if (step === "ai") set("ai_keys", {});
    if (step === "intel") set("intel_keys", { virustotal: "", shodan: "", censys: "" });
    if (step === "assets") set("asset_map", null);
    go(STEPS[index + 1]?.key ?? step);
  }
  return (
    <div className="setup">
      {exit}
      <div className="mx-auto flex w-full max-w-3xl flex-col gap-8 px-4 pt-4 pb-24">
        <Progress index={index} />
        <section key={step} className="setup-chapter flex flex-col gap-8" aria-labelledby="setup-chapter">
          <div className="flex flex-col gap-3">
            <p className="m-0 text-sm font-semibold text-(--s-muted)">
              Step {index + 1} of {STEPS.length}
              {chapter?.optional ? " · optional" : ""}
            </p>
            <h1 id="setup-chapter" ref={head} tabIndex={-1} className="setup-h">
              {chapter?.title}
            </h1>
            <p className="setup-sub">{chapter?.sub}</p>
          </div>
          {step === "organisation" && <Organisation f={form} set={set} bad={bad} />}
          {step === "siem" && <Siem f={form} set={set} bad={bad} anchor={siemAnchor} onAnchor={setSiemAnchor} />}
          {step === "access" && <Access f={form} set={set} bad={bad} />}
          {step === "kibana" && <Kibana f={form} set={set} bad={bad} anchor={kibanaAnchor} onAnchor={setKibanaAnchor} />}
          {step === "ai" && <Ai f={form} set={set} bad={bad} providers={ai.isError ? null : (ai.data?.providers ?? [])} />}
          {step === "intel" && <Intel f={form} set={set} bad={bad} />}
          {step === "assets" && <Assets f={form} set={set} />}
          {step === "review" && <Review f={form} onJump={(s) => { go(s); setShown(true); }} />}
          {step === "review" && (
            <div className="flex flex-col items-start gap-3" data-testid="review-step-up">
              {fresh ? (
                <p className="m-0 text-[0.9375rem] text-(--s-muted)">Your password is confirmed: you can run the setup.</p>
              ) : (
                <>
                  <p className="m-0 text-[0.9375rem] text-(--s-muted)">Running the setup needs your password confirmed in the last five minutes. Confirm it in a new tab; this page then runs the setup by itself.</p>
                  <StepUpLink className="setup-pill setup-pill-quiet" suffix=" (opens a tab)" onConfirmed={runWhenReady} />
                </>
              )}
              {autoRun && (
                <p role="status" className="m-0 text-[0.9375rem]" data-testid="auto-run">
                  Password confirmed: running the setup…
                </p>
              )}
            </div>
          )}
          {failure && (
            <p role="alert" className="setup-error" data-testid="run-error">
              {failure.message} {failure.code === "step_up_required" && <><StepUpLink onConfirmed={runWhenReady} /> The setup then runs by itself; your answers are kept here.</>}
              {/domain|public suffix/i.test(failure.message) && (
                <>
                  {" "}
                  <button type="button" className="setup-link" onClick={() => { run.reset(); go("organisation"); }}>
                    Change the domains ›
                  </button>
                </>
              )}
            </p>
          )}
          <div className="flex flex-wrap items-center gap-6">
            {step !== "review" ? (
              <button type="button" className="setup-pill" onClick={next}>
                Continue
              </button>
            ) : (
              <button type="button" className="setup-pill" aria-disabled={run.isPending || allProblems(form) !== null} onClick={() => !run.isPending && allProblems(form) === null && run.mutate()}>
                {run.isPending ? "Starting…" : "Run the setup"}
              </button>
            )}
            {chapter?.optional && (
              <button type="button" className="setup-link" onClick={skip}>
                Skip ›
              </button>
            )}
            <button type="button" className="setup-link" onClick={() => (index > 0 ? go(STEPS[index - 1]?.key ?? step) : setStage("intro"))}>
              ‹ Back
            </button>
          </div>
        </section>
      </div>
    </div>
  );
}

export function Setup() {
  return (
    <AdminOnly what="First-time setup">
      <SetupView />
    </AdminOnly>
  );
}

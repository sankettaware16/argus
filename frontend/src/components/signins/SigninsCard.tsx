import type { SigninDeviceOut, SigninsOut } from "../../client/types.gen";
import { count, plural } from "../../lib/format";
import { DIRECTORY_ACCOUNT, DirectoryCard, useDirectory } from "../DirectoryCard";
import { EntityChip } from "../incident/Parts";
import { Time } from "../Time";
import { UntrustedText } from "../UntrustedText";
import { Badge, type Tone } from "../ui/badge";
import { DataTable } from "../ui/table";

const STATE: Record<SigninDeviceOut["state"], { label: string; tone: Tone }> = {
  likely: { label: "Probable user", tone: "ok" },
  possible: { label: "Possible users", tone: "info" },
  shared: { label: "Shared address", tone: "warn" },
  none_seen: { label: "No sign-in seen", tone: "neutral" },
  unknown: { label: "Not known", tone: "warn" },
};
const SHOWN = 10;

function Text({ value, max = 200, lines = 2 }: { value: string; max?: number; lines?: number }) {
  return <UntrustedText value={value} limits={{ maxChars: max, maxLines: lines }} />;
}

/** The one account behind a device, when the sign-ins name just one ("likely"). Pure. */
export function probableUser(d: Pick<SigninDeviceOut, "state" | "accounts">): string | null {
  return d.state === "likely" ? (d.accounts[0]?.user ?? null) : null;
}

/** One address's sign-ins, when the card has them. Pure. */
export function signinsOf(signins: SigninsOut | null | undefined, address: string): SigninDeviceOut | null {
  return signins?.devices.find((d) => d.address === address) ?? null;
}

const accountObject = (user: string) => ({ kind: "account" as const, label: user, role: "affected" as const });

/** The site's directory answer for an account (D-337), asked when shown; nothing when the feature is off. */
export function WhoThisIs({ account }: { account: string }) {
  const directory = useDirectory();
  if (directory === null || !DIRECTORY_ACCOUNT.test(account)) return null;
  return (
    <section aria-label={`Who ${account} is`} className="flex flex-col gap-1 rounded-control border border-border p-2" data-testid="who-this-is">
      <h4 className="m-0 text-sm font-semibold">
        Who this is (from {directory}): <Text value={account} max={64} lines={1} />
      </h4>
      <DirectoryCard account={account} />
    </section>
  );
}

/**
 * Who used one device, short: the state, each account as a chip (it opens the account drawer),
 * and for a probable user the directory's answer in place. The server's words stand in for the
 * chips when it sends no names (an account that may not read the logs).
 */
export function DeviceUser({ device, directory = true }: { device: SigninDeviceOut; directory?: boolean }) {
  const state = STATE[device.state];
  const one = probableUser(device);
  const shown = device.accounts.slice(0, 5);
  return (
    <div className="flex flex-col gap-1.5" data-testid="device-user" data-state={device.state}>
      <p className="m-0 flex flex-wrap items-center gap-1.5 text-sm">
        <Badge tone={state.tone}>{state.label}</Badge>
        {shown.map((a) => (
          <EntityChip key={a.user} object={accountObject(a.user)} />
        ))}
        {device.accounts.length > shown.length && <span className="text-xs text-muted">+{device.accounts.length - shown.length}</span>}
        {shown.length === 0 && device.state !== "none_seen" && (
          <span className="text-muted">
            <Text value={device.words} max={300} lines={2} />
          </span>
        )}
      </p>
      {directory && one && <WhoThisIs account={one} />}
    </div>
  );
}

function Device({ device }: { device: SigninDeviceOut }) {
  const state = STATE[device.state];
  const one = probableUser(device);
  return (
    <li className="flex flex-col gap-1.5 border-b border-border py-2 last:border-b-0">
      <div className="flex flex-wrap items-center gap-2">
        <code className="text-sm">{device.address}</code>
        <Badge tone={state.tone}>{state.label}</Badge>
      </div>
      {/* the words hold account names for someone who may read them: untrusted text, from the logs */}
      <p className="m-0 max-w-prose text-sm">
        <Text value={device.words} max={600} lines={4} />
      </p>
      {device.accounts.length > 0 && (
        <DataTable
          reachable
          caption={`Accounts that signed in from ${device.address}`}
          rows={device.accounts}
          rowKey={(a) => a.user}
          columns={[
            { key: "user", header: "Account", cell: (a) => <EntityChip object={accountObject(a.user)} /> },
            { key: "n", header: "Sign-ins", numeric: true, cell: (a) => `${count(a.successes)}${a.failures > 0 ? `, ${count(a.failures)} failed` : ""}` },
            { key: "first", header: "First", cell: (a) => <Time value={a.first_at} /> },
            { key: "last", header: "Last", cell: (a) => <Time value={a.last_at} /> },
            { key: "browser", header: "Browser", cell: (a) => <Text value={a.devices.join("; ") || "unknown browser"} max={160} lines={2} /> },
          ]}
        />
      )}
      {one && <WhoThisIs account={one} />}
      {device.hands.length > 1 && (
        <p className="m-0 text-sm text-muted">The address changed hands: one account on each of these days.</p>
      )}
      {device.failed_only.length > 0 && (
        <p className="m-0 text-sm text-muted">
          Failed sign-ins only, from: <Text value={device.failed_only.join(", ")} max={300} lines={2} />.
        </p>
      )}
      {device.gaps.length > 0 && device.state !== "unknown" && (
        <p className="m-0 text-sm text-muted">{device.gaps.map((g) => `${g.day}: ${g.words}`).join("; ")}.</p>
      )}
    </li>
  );
}

/**
 * Who used the device(s) (AR6, D-216): the probable users of an investigation's or a case's internal
 * addresses, from the SSO sign-ins ARGUS kept. A lead, not proof (the server's own `lead` wording
 * is shown above it). Account names are personal data from the logs: they are shown only to an
 * account that may read the logs (the server sends none otherwise, and `hidden` says so), and
 * always as untrusted text.
 */
export function SigninsCard({ signins, id = "signins", level = 3 }: { signins: SigninsOut | null | undefined; id?: string; level?: 2 | 3 }) {
  if (signins == null) return null;
  const Heading = level === 2 ? "h2" : "h3";
  const title = signins.devices_total === 1 ? "Who used this device" : "Who used these devices";
  const rest = signins.devices.slice(SHOWN);
  return (
    <section aria-label={title} id={id} className="flex flex-col gap-2 scroll-mt-4">
      <Heading className={level === 2 ? "m-0 text-lg font-semibold" : "m-0 text-sm font-semibold"}>{title}</Heading>
      {!signins.enabled && signins.devices.length === 0 ? (
        <p className="m-0 text-sm text-muted">ARGUS is not reading the sign-in logs yet, so it cannot say who used {signins.devices_total === 1 ? "it" : "them"}.</p>
      ) : (
        <>
          <p className="m-0 max-w-prose text-sm text-muted">{signins.lead}</p>
          {signins.hidden && <p className="m-0 text-sm text-muted">Your account cannot read the logs in ELK, so the accounts are hidden: only how many are shown.</p>}
          {signins.states.length > 0 && (
            <p className="m-0 flex flex-wrap items-center gap-1.5 text-sm">
              {count(signins.devices_total)} {plural(signins.devices_total, "device")}:
              {signins.states.map((s) => (
                <Badge key={s.state} tone={STATE[s.state].tone}>
                  {count(s.devices)} {STATE[s.state].label.toLowerCase()}
                </Badge>
              ))}
            </p>
          )}
          <ul className="m-0 flex list-none flex-col p-0">
            {signins.devices.slice(0, SHOWN).map((d) => (
              <Device key={d.address} device={d} />
            ))}
          </ul>
          {rest.length > 0 && (
            <details>
              <summary className="cursor-pointer text-sm font-medium">
                {count(rest.length)} more {plural(rest.length, "device")}
              </summary>
              <ul className="m-0 flex list-none flex-col p-0">
                {rest.map((d) => (
                  <Device key={d.address} device={d} />
                ))}
              </ul>
            </details>
          )}
          {signins.devices_total > signins.devices.length && <p className="m-0 text-sm text-muted">{count(signins.devices_total - signins.devices.length)} more devices are not listed.</p>}
        </>
      )}
    </section>
  );
}

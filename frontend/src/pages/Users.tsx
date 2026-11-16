// Users and roles (D-327): who may sign in and what they may do. A new person, or a person who
// forgot their password, gets a one-time link; an administrator never types or sees a password.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { createUser, setUserCapabilities } from "../client/sdk.gen";
import type { AccountLinkOut, AccountOut, RoleOut } from "../client/types.gen";
import { AdminOnly, CopyButton, Modal, Notice, StepUpLink, StepUpNote } from "../components/admin/common";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { Loading, Problem } from "../components/Problem";
import { Time } from "../components/Time";
import { Badge } from "../components/ui/badge";
import { Button } from "../components/ui/button";
import { Card, CardTitle } from "../components/ui/card";
import { Check, Field, Select, TextInput } from "../components/ui/field";
import { DataTable } from "../components/ui/table";
import { usersOptions } from "../lib/admin";
import { unwrap } from "../lib/call";
import { ApiError, useSession } from "../lib/session";
import { capabilityWords, CAPABILITIES, EMPTY_PERSON, fullLink, LINK_HOURS, newPersonBody, personProblems, readOnlyWhy, roleBody, roleLabel, type Capability, type PersonForm, type RoleKey } from "../lib/users";

function problemText(e: unknown): { text: string; stepUp: boolean } {
  return e instanceof ApiError ? { text: e.message, stepUp: e.code === "step_up_required" } : { text: "That could not be done.", stepUp: false };
}

function RolePicker({ roles, role, capabilities, onChange, error }: { roles: readonly RoleOut[]; role: RoleKey | "custom"; capabilities: readonly Capability[]; onChange: (role: RoleKey | "custom", capabilities: readonly Capability[]) => void; error?: string }) {
  const about = roles.find((r) => r.key === role)?.about;
  return (
    <div className="flex flex-col gap-2">
      <Field label="Role" htmlFor="person-role">
        <Select id="person-role" value={role} onChange={(e) => onChange(e.target.value as RoleKey | "custom", capabilities)}>
          {roles.map((r) => (
            <option key={r.key} value={r.key}>
              {r.label}
            </option>
          ))}
          <option value="custom">Custom: choose what they may do</option>
        </Select>
      </Field>
      {about && <p className="m-0 text-sm text-muted">{about}</p>}
      {role === "custom" && (
        <fieldset className="m-0 flex flex-col gap-1 rounded-control border border-border p-2">
          <legend className="px-1 text-sm font-medium">What this person may do</legend>
          {CAPABILITIES.map((c) => (
            <Check key={c.name} checked={c.name === "view" || capabilities.includes(c.name)} disabled={c.name === "view"} onChange={(e) => onChange(role, e.target.checked ? [...capabilities, c.name] : capabilities.filter((x) => x !== c.name))}>
              {c.label}
            </Check>
          ))}
          {error && (
            <p role="alert" className="m-0 text-sm text-danger">
              {error}
            </p>
          )}
        </fieldset>
      )}
    </div>
  );
}

/** The one-time link, shown once, with what to do with it. */
function LinkShown({ result, onDone }: { result: AccountLinkOut; onDone: () => void }) {
  const link = fullLink(result.link, window.location.origin);
  return (
    <div className="flex flex-col gap-2" data-testid="link-shown">
      <Notice tone="warn">
        Give this link to {result.user.display_name}. It works once, for {LINK_HOURS} hours, and ARGUS cannot show it again.
      </Notice>
      <label htmlFor="one-time-link" className="text-sm font-medium">
        {result.user.display_name}&apos;s link to set a password
      </label>
      <div className="flex gap-2">
        <TextInput id="one-time-link" readOnly value={link} onFocus={(e) => e.currentTarget.select()} className="font-mono" />
        <CopyButton text={link} />
      </div>
      <p className="m-0 text-sm text-muted">
        Expires <Time value={result.expires_at} />. They choose their own password when they open it.
      </p>
      <div className="flex justify-end">
        <Button variant="primary" onClick={onDone}>
          I have given it
        </Button>
      </div>
    </div>
  );
}

function AddPerson({ open, onOpenChange, roles }: { open: boolean; onOpenChange: (o: boolean) => void; roles: readonly RoleOut[] }) {
  const queries = useQueryClient();
  const [form, setForm] = useState<PersonForm>(EMPTY_PERSON);
  const [shown, setShown] = useState(false);
  const [result, setResult] = useState<AccountLinkOut | null>(null);
  const create = useMutation({
    mutationFn: (f: PersonForm) => unwrap(createUser({ body: newPersonBody(f) })),
    onSuccess: (out) => {
      setResult(out);
      void queries.invalidateQueries({ queryKey: usersOptions.queryKey });
    },
  });
  const problems = personProblems(form);
  const failure = create.isError ? problemText(create.error) : null;
  function close(o: boolean) {
    if (!o) {
      setForm(EMPTY_PERSON);
      setResult(null);
      setShown(false);
      create.reset();
    }
    onOpenChange(o);
  }
  return (
    <Modal open={open} onOpenChange={close} title={result ? "Person added" : "Add a person"} description={result ? undefined : "They get a one-time link to set their own password. You never see or type a password."}>
      {result ? (
        <LinkShown result={result} onDone={() => close(false)} />
      ) : (
        <form
          className="flex flex-col gap-3"
          noValidate
          onSubmit={(e) => {
            e.preventDefault();
            setShown(true);
            if (Object.keys(problems).length === 0 && !create.isPending) create.mutate(form);
          }}
        >
          <Field label="Name" hint="as ARGUS shows it" htmlFor="person-name">
            <TextInput id="person-name" value={form.display_name} maxLength={80} autoComplete="off" onChange={(e) => setForm({ ...form, display_name: e.target.value })} />
            {shown && problems.display_name && <p role="alert" className="m-0 text-sm text-danger">{problems.display_name}</p>}
          </Field>
          <Field label="Sign-in name" hint="lower case, e.g. asha.rao" htmlFor="person-username">
            <TextInput id="person-username" value={form.username} maxLength={32} autoComplete="off" autoCapitalize="none" spellCheck={false} onChange={(e) => setForm({ ...form, username: e.target.value })} />
            {shown && problems.username && <p role="alert" className="m-0 text-sm text-danger">{problems.username}</p>}
          </Field>
          <RolePicker roles={roles} role={form.role} capabilities={form.capabilities} error={shown ? problems.capabilities : undefined} onChange={(role, capabilities) => setForm({ ...form, role, capabilities })} />
          {failure && (
            <p role="alert" className="m-0 text-sm text-danger" data-testid="add-error">
              {failure.text} {failure.stepUp && <StepUpLink />}
            </p>
          )}
          <div className="flex justify-end gap-2">
            <Button onClick={() => close(false)}>Cancel</Button>
            <Button type="submit" variant="primary" aria-disabled={create.isPending}>
              {create.isPending ? "Adding…" : "Add the person"}
            </Button>
          </div>
        </form>
      )}
    </Modal>
  );
}

function ChangeRole({ user, roles, onClose }: { user: AccountOut | null; roles: readonly RoleOut[]; onClose: () => void }) {
  const queries = useQueryClient();
  const [role, setRole] = useState<RoleKey | "custom">("viewer");
  const [caps, setCaps] = useState<readonly Capability[]>(["view"]);
  const [seen, setSeen] = useState<number | null>(null);
  if ((user?.id ?? null) !== seen) {
    setSeen(user?.id ?? null);
    if (user) {
      setRole(user.role === "custom" || user.role === "elk" ? "custom" : user.role);
      setCaps(user.capabilities);
    }
  }
  const save = useMutation({
    mutationFn: (v: { id: number; role: RoleKey | "custom"; caps: readonly Capability[] }) => unwrap(setUserCapabilities({ path: { user_id: v.id }, body: roleBody(v.role, v.caps) })),
    onSuccess: () => {
      void queries.invalidateQueries({ queryKey: usersOptions.queryKey });
      onClose();
    },
  });
  const failure = save.isError ? problemText(save.error) : null;
  const bad = role === "custom" && caps.length === 0 ? "Choose at least one thing the person may do." : undefined;
  return (
    <Modal
      open={user !== null}
      onOpenChange={(o) => {
        if (!o) {
          save.reset();
          onClose();
        }
      }}
      title={`Change ${user?.display_name ?? "the"}'s role`}
      description="Takes effect the next time the person's session reads its access (within a minute)."
    >
      <RolePicker roles={roles} role={role} capabilities={caps} error={bad} onChange={(r, c) => (setRole(r), setCaps(c))} />
      {failure && (
        <p role="alert" className="m-0 text-sm text-danger">
          {failure.text} {failure.stepUp && <StepUpLink />}
        </p>
      )}
      <div className="flex justify-end gap-2">
        <Button onClick={onClose}>Cancel</Button>
        <Button variant="primary" aria-disabled={save.isPending || bad !== undefined} onClick={() => user && !bad && !save.isPending && save.mutate({ id: user.id, role, caps })}>
          {save.isPending ? "Saving…" : "Save the role"}
        </Button>
      </div>
    </Modal>
  );
}

type Action = { kind: "off" | "on" | "sessions" | "link"; user: AccountOut };

function status(u: AccountOut): { tone: "ok" | "neutral" | "warn"; text: string } {
  if (u.disabled) return { tone: "neutral", text: "Switched off" };
  if (u.link_open) return { tone: "warn", text: "Link not used yet" };
  return { tone: "ok", text: "Active" };
}

function UsersView() {
  const queries = useQueryClient();
  const me = useSession().data?.user.id;
  const data = useQuery(usersOptions);
  const [adding, setAdding] = useState(false);
  const [role, setRole] = useState<AccountOut | null>(null);
  const [action, setAction] = useState<Action | null>(null);
  const [link, setLink] = useState<AccountLinkOut | null>(null);
  if (data.isPending) return <Loading what="the people" />;
  if (data.isError) return <Problem error={data.error} what="The people" onRetry={() => void data.refetch()} />;
  const { users, roles } = data.data;
  const refresh = () => void queries.invalidateQueries({ queryKey: usersOptions.queryKey });
  const path = action ? `/api/v1/admin/users/${action.user.id}` : "";
  const words: Record<Action["kind"], { title: string; what: string; confirm: string }> = {
    off: { title: `Switch off ${action?.user.display_name ?? ""}?`, what: "They can no longer sign in and every open session ends. Nothing they did is removed. You can switch them on again.", confirm: "Switch off" },
    on: { title: `Switch on ${action?.user.display_name ?? ""}?`, what: "They can sign in again with their old password.", confirm: "Switch on" },
    sessions: { title: `End ${action?.user.display_name ?? ""}'s sessions?`, what: "Every browser they are signed in on is signed out now. They can sign in again.", confirm: "End the sessions" },
    link: { title: `New password link for ${action?.user.display_name ?? ""}?`, what: "Makes a one-time link they use to choose a new password. An older unused link stops working. You will see the link once.", confirm: "Make the link" },
  };
  const request = !action
    ? { method: "POST" as const, path: "/api/v1/admin/users/0/link", body: undefined }
    : action.kind === "off" || action.kind === "on"
      ? { method: "PUT" as const, path: `${path}/access`, body: { disabled: action.kind === "off" } }
      : action.kind === "sessions"
        ? { method: "POST" as const, path: `${path}/sessions/end`, body: undefined }
        : { method: "POST" as const, path: `${path}/link`, body: undefined };
  const w = action ? words[action.kind] : words.off;
  return (
    <>
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="flex flex-col gap-1">
          <h1 className="m-0 text-2xl font-semibold">Users and roles</h1>
          <p className="m-0 max-w-prose text-sm text-muted">Who may sign in to ARGUS and what they may do. A new person, or someone who forgot their password, gets a one-time link; you never type or see a password.</p>
        </div>
        <Button variant="primary" onClick={() => setAdding(true)}>
          Add a person
        </Button>
      </div>
      <StepUpNote />
      <Card aria-label="People">
        <DataTable
          caption="People who can sign in to ARGUS"
          rows={users}
          rowKey={(u) => String(u.id)}
          columns={[
            { key: "name", header: "Name", cell: (u) => <strong>{u.display_name}</strong> },
            { key: "user", header: "Sign-in name", cell: (u) => <span className="font-mono text-xs">{u.username}</span> },
            { key: "role", header: "Role", cell: (u) => roleLabel(u, roles) },
            { key: "seen", header: "Last seen", cell: (u) => (u.last_seen_at ? <Time value={u.last_seen_at} relative /> : <span className="text-muted">Never</span>) },
            { key: "sessions", header: "Sessions", numeric: true, cell: (u) => u.open_sessions },
            {
              key: "status",
              header: "Status",
              cell: (u) => (
                <span className="flex flex-wrap gap-1">
                  <Badge tone={status(u).tone}>{status(u).text}</Badge>
                  {u.break_glass && <Badge tone="warn">Emergency account</Badge>}
                  {u.managed_in_elk && <Badge tone="info">ELK sign-in</Badge>}
                </span>
              ),
            },
            {
              key: "actions",
              header: "Actions",
              cell: (u) => {
                const why = readOnlyWhy(u);
                if (why) return <span className="text-xs text-muted">{why}</span>;
                const you = u.id === me;
                return (
                  <span className="flex flex-wrap gap-1">
                    {!you && (
                      <Button size="sm" aria-label={`Change role of ${u.display_name}`} onClick={() => setRole(u)}>
                        Change role
                      </Button>
                    )}
                    <Button size="sm" aria-label={`New password link for ${u.display_name}`} onClick={() => setAction({ kind: "link", user: u })}>
                      New password link
                    </Button>
                    {!you && (
                      <Button size="sm" aria-label={`${u.disabled ? "Switch on" : "Switch off"} ${u.display_name}`} onClick={() => setAction({ kind: u.disabled ? "on" : "off", user: u })}>
                        {u.disabled ? "Switch on" : "Switch off"}
                      </Button>
                    )}
                    {u.open_sessions > 0 && !you && (
                      <Button size="sm" aria-label={`End the sessions of ${u.display_name}`} onClick={() => setAction({ kind: "sessions", user: u })}>
                        End sessions
                      </Button>
                    )}
                    {you && <span className="text-xs text-muted">This is you</span>}
                  </span>
                );
              },
            },
          ]}
          reachable
        />
      </Card>
      <Card aria-label="What each role may do">
        <CardTitle>What the roles mean</CardTitle>
        <dl className="m-0 grid gap-x-4 gap-y-2 text-sm sm:grid-cols-[10rem_1fr]">
          {roles.map((r) => (
            <div key={r.key} className="contents">
              <dt className="font-semibold">{r.label}</dt>
              <dd className="m-0">
                {r.about}
                <span className="block text-xs text-muted">{r.capabilities.map(capabilityWords).join(" · ")}</span>
              </dd>
            </div>
          ))}
          <div className="contents">
            <dt className="font-semibold">Custom</dt>
            <dd className="m-0">Pick exactly what a person may do, when no role fits.</dd>
          </div>
        </dl>
      </Card>
      <AddPerson open={adding} onOpenChange={setAdding} roles={roles} />
      <ChangeRole user={role} roles={roles} onClose={() => setRole(null)} />
      <ConfirmDialog
        open={action !== null}
        onOpenChange={(o) => !o && setAction(null)}
        title={w.title}
        description={w.what}
        request={request}
        confirmLabel={w.confirm}
        danger={action?.kind === "off" || action?.kind === "sessions"}
        onSent={(sent) => {
          refresh();
          if (action?.kind === "link") setLink(sent.data as AccountLinkOut);
        }}
      />
      <Modal open={link !== null} onOpenChange={(o) => !o && setLink(null)} title="One-time link">
        {link && <LinkShown result={link} onDone={() => setLink(null)} />}
      </Modal>
    </>
  );
}

export function Users() {
  return (
    <AdminOnly what="Users and roles">
      <UsersView />
    </AdminOnly>
  );
}

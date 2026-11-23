import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { getDirectoryAccount } from "../client/sdk.gen";
import type { DirectoryOut, DirectoryPersonOut } from "../client/types.gen";
import { unwrap } from "../lib/call";
import { can, useSession } from "../lib/session";
import { Loading, Problem } from "./Problem";
import { UntrustedText } from "./UntrustedText";

/** What an account name may hold for the site's directory (the API's own pattern). */
export const DIRECTORY_ACCOUNT = /^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$/;

/** The directory's name when the site has one and the person may ask it; else null (the feature is off). */
export function useDirectory(): string | null {
  return useSession().data?.directory ?? null;
}

/** The sentence under the result when there is no person to show. Pure. */
export function directoryWords(d: Pick<DirectoryOut, "outcome" | "directory" | "why" | "account">, admin: boolean): string {
  if (d.outcome === "not_found") return `${d.directory} has no account ${d.account}.`;
  if (d.outcome === "expired") return `${d.directory} no longer accepts ARGUS's saved session${d.why ? ` (${d.why})` : ""}. ${admin ? "Save a new one in Settings › Account directory." : "Ask an administrator to save a new one in Settings."}`;
  if (d.outcome === "error") return `${d.directory} did not answer${d.why ? ` (${d.why})` : ""}. Try again in a minute.`;
  return "";
}

function Lines({ person }: { person: DirectoryPersonOut }) {
  const rows: [string, string][] = [];
  if (person.name) rows.push(["Name", person.name]);
  if (person.kind) rows.push(["Kind of account", person.kind]);
  if (person.department) rows.push(["Department", person.department]);
  for (const d of person.details) if (d.label !== "Department") rows.push([d.label, d.value]);
  return (
    <dl className="m-0 grid grid-cols-[minmax(8rem,auto)_1fr] gap-x-4 gap-y-1 text-sm" data-testid="directory-lines">
      {rows.map(([label, value]) => (
        <div key={label} className="contents">
          <dt className="text-muted">{label}</dt>
          <dd className="m-0 min-w-0 break-words">
            <UntrustedText value={value} limits={{ maxChars: 200, maxLines: 2 }} />
          </dd>
        </div>
      ))}
    </dl>
  );
}

/**
 * Who an account belongs to, from the site's own directory (D-337): asked when shown, kept by the
 * server for a while, never stored. Without a person (the session expired, no answer) it still
 * shows what the account's name alone says.
 */
export function DirectoryCard({ account, link = false }: { account: string; link?: boolean }) {
  const session = useSession();
  const q = useQuery({
    queryKey: ["directory", account.toLowerCase()],
    queryFn: () => unwrap(getDirectoryAccount({ path: { account } })),
    staleTime: 10 * 60_000,
    retry: false,
  });
  if (q.isPending) return <Loading what="the directory's answer" />;
  if (q.isError) return <Problem error={q.error} what="The directory" onRetry={() => void q.refetch()} />;
  const d = q.data;
  const words = directoryWords(d, can(session.data, "admin"));
  return (
    <div className="flex flex-col gap-2" data-testid="directory-card" data-outcome={d.outcome}>
      {d.person && <Lines person={d.person} />}
      {words !== "" && (
        <p className="m-0 text-sm" role={d.outcome === "expired" ? "alert" : undefined} data-testid="directory-words">
          {words}
        </p>
      )}
      {!d.person && d.described && (
        <>
          <p className="m-0 text-sm text-muted">What the account&apos;s name alone says:</p>
          <Lines person={d.described} />
        </>
      )}
      <p className="m-0 text-xs text-muted">
        From {d.directory}, asked now and not stored. A name is for the investigation only: do not copy it into notes, reports or Kibana.
      </p>
      {link && (
        <Link to="/entities/$kind/$value" params={{ kind: "account", value: account }} className="text-sm">
          What ARGUS has seen of {account} ›
        </Link>
      )}
    </div>
  );
}

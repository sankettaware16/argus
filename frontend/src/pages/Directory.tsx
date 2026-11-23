import { useNavigate } from "@tanstack/react-router";
import { useId, useState } from "react";
import { DIRECTORY_ACCOUNT, DirectoryCard, useDirectory } from "../components/DirectoryCard";
import { Button } from "../components/ui/button";
import { TextInput } from "../components/ui/field";

/**
 * Account look-up (D-337): one box for an account name, answered
 * by the site's own account directory. Shown only where the site has a directory and the person
 * may see account names.
 */
export function DirectoryPage({ account }: { account?: string }) {
  const navigate = useNavigate();
  const id = useId();
  const directory = useDirectory();
  const [text, setText] = useState(account ?? "");
  const typed = text.trim();
  const bad = typed !== "" && !DIRECTORY_ACCOUNT.test(typed);
  if (directory === null) {
    return (
      <div className="flex flex-col gap-2">
        <h1 className="page-h">Account look-up</h1>
        <p className="m-0 max-w-[72ch] text-sm text-muted">This is not available: the site has no account directory set up in ARGUS, or your role may not see account names.</p>
      </div>
    );
  }
  return (
    <div className="flex max-w-[52rem] flex-col gap-4">
      <header className="flex flex-col gap-1">
        <h1 className="page-h">Account look-up</h1>
        <p className="m-0 max-w-[72ch] text-sm text-muted">Who an account belongs to, from {directory}: the name, the kind of account and the department. Each look-up is recorded in ARGUS&apos;s audit log.</p>
      </header>
      <form
        role="search"
        className="flex flex-wrap items-end gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          if (typed !== "" && !bad) void navigate({ to: "/account-lookup", search: { account: typed } });
        }}
      >
        <div className="flex min-w-0 flex-1 flex-col gap-1">
          <label htmlFor={`${id}-a`} className="text-sm font-medium">
            Account name
          </label>
          <TextInput id={`${id}-a`} value={text} maxLength={64} autoComplete="off" spellCheck={false} aria-invalid={bad} onChange={(e) => setText(e.target.value)} data-testid="directory-box" />
        </div>
        <Button type="submit" variant="primary" disabled={typed === "" || bad}>
          Look up
        </Button>
      </form>
      {bad && <p className="m-0 text-sm text-danger">An account name has letters, digits, dots and dashes only.</p>}
      {account !== undefined && (
        <section aria-label={`Account ${account}`} className="flex flex-col gap-2 rounded-card bg-surface p-3">
          <h2 className="m-0 text-base font-semibold break-all">{account}</h2>
          <DirectoryCard key={account} account={account} link />
        </section>
      )}
    </div>
  );
}

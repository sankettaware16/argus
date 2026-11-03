import { useSession } from "../lib/session";

const BOX = "m-0 flex flex-wrap items-baseline gap-x-2 gap-y-1 border-b px-4 py-2 text-sm text-text";

/**
 * What the classic pages said on every page and the app must too (Q-B4 review 2): an emergency
 * (break-glass) session, and ELK sign-in that ARGUS cannot confirm right now. In both, nothing
 * the person reviews reaches Kibana, so the person must know before they rely on it.
 */
export function AccessBanner() {
  const session = useSession().data;
  if (!session) return null;
  if (session.break_glass) {
    return (
      <p role="alert" className={`${BOX} border-danger/50 bg-danger-soft`}>
        <strong>Emergency (break-glass) session.</strong>
        <span>ELK could not be asked, so you can view and review only. Nothing you do is sent to Kibana, and every action is recorded.</span>
        <a href="/access">Details</a>
      </p>
    );
  }
  if (session.unverified) {
    const reviews = session.unverified.why === "outage";
    return (
      <p role="status" className={`${BOX} border-warn/50 bg-warn-soft`}>
        <strong>ARGUS cannot confirm your access in ELK right now.</strong>
        <span>
          You can read{reviews ? " and review (reviews are saved here, not sent to Kibana)" : ""}; changes that need ELK wait.
        </span>
        <a href="/access">Details</a>
      </p>
    );
  }
  return null;
}

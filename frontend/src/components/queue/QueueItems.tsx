import { Link } from "@tanstack/react-router";
import type { QueueCaseOut, QueueSingleOut } from "../../client/types.gen";
import { count, plural } from "../../lib/format";
import { stanceHeadline } from "../../lib/verdict";
import { StateChip } from "../chips";
import { Time } from "../Time";
import { UntrustedText } from "../UntrustedText";
import { Badge, SeverityBadge, type Tone } from "../ui/badge";

export const KIND_WORDS: Record<QueueCaseOut["kind"], [Tone, string]> = {
  suggested: ["info", "Suggested by ARGUS"],
  changed: ["warn", "Changed since the owner was told"],
  attention: ["warn", "Needs a person"],
  unowned: ["neutral", "Nobody owns it"],
  new: ["info", "New work in a worked case"],
};

/** ARGUS's verdict or reading in one line; a recommendation or reading is marked by words, not by colour alone. */
function Stance({ s }: { s: QueueCaseOut["stance"] }) {
  return (
    <p className="m-0 text-sm font-medium" data-testid="queue-stance">
      <UntrustedText value={stanceHeadline(s)} limits={{ maxChars: 300, maxLines: 2 }} />
    </p>
  );
}

/** A case that needs a person: ARGUS's verdict, its devices and severity, and why it is here. */
export function QueueCase({ c }: { c: QueueCaseOut }) {
  const [tone, kind] = KIND_WORDS[c.kind];
  return (
    <li className="flex flex-col gap-1 rounded-card border border-border bg-surface p-3 shadow-card" data-testid="queue-case">
      <div className="flex flex-wrap items-center gap-2">
        <Link to="/cases/$id" params={{ id: c.id }} className="text-base font-semibold">
          Case {c.number}: <UntrustedText value={c.title} limits={{ maxChars: 160, maxLines: 2 }} />
        </Link>
        <Badge tone={tone}>{kind}</Badge>
        <SeverityBadge severity={c.severity} />
      </div>
      <Stance s={c.stance} />
      <p className="m-0 text-sm">
        <span className="text-muted">Why it is here: </span>
        <UntrustedText value={c.why} limits={{ maxChars: 400, maxLines: 3 }} />
        {c.notified_at && (
          <>
            {" "}
            <span className="text-muted">
              (owner told <Time value={c.notified_at} />)
            </span>
          </>
        )}
      </p>
      {c.changes.length > 0 && (
        <ul className="m-0 pl-5 text-sm" aria-label="What changed">
          {c.changes.map((w, i) => (
            <li key={i}>
              <UntrustedText value={w} limits={{ maxChars: 300, maxLines: 3 }} />
            </li>
          ))}
        </ul>
      )}
      <p className="m-0 text-sm text-muted">
        {c.devices.length > 0 ? (
          <>
            {plural(c.devices_total, "Device")}:{" "}
            {c.devices.map((d, i) => (
              <span key={d} className="font-mono">
                {i > 0 && ", "}
                <UntrustedText value={d} limits={{ maxChars: 80, maxLines: 1 }} />
              </span>
            ))}
            {c.devices_total > c.devices.length && ` and ${count(c.devices_total - c.devices.length)} more`}
            {" · "}
          </>
        ) : (
          "No device named yet · "
        )}
        {count(c.investigations)} {plural(c.investigations, "investigation")}, {count(c.unreviewed)} to review · {count(c.alerts)} {plural(c.alerts, "alert")}
        {c.last_alert_at && (
          <>
            {" "}
            · last <Time value={c.last_alert_at} relative />
          </>
        )}
        {c.waiting_for_approval > 0 && ` · ${c.waiting_for_approval} ${plural(c.waiting_for_approval, "request")} waiting for an approver`}
      </p>
      <p className="m-0 flex flex-wrap gap-x-4 gap-y-1 text-sm">
        {c.first_investigation_id ? (
          <Link to="/investigations/$id" params={{ id: c.first_investigation_id }} className="inline-flex min-h-8 items-center">
            Review the first investigation
          </Link>
        ) : null}
        <Link to="/cases/$id" params={{ id: c.id }} className="inline-flex min-h-8 items-center">
          Open the case
        </Link>
      </p>
    </li>
  );
}

/** A single investigation in Needs attention that belongs to no case. */
export function QueueSingle({ s }: { s: QueueSingleOut }) {
  const i = s.investigation;
  return (
    <li className="flex flex-col gap-1 border-b border-border py-2 last:border-b-0" data-testid="queue-single">
      <div className="flex flex-wrap items-center gap-2">
        <Link to="/investigations/$id" params={{ id: i.id }} className="font-medium">
          <UntrustedText value={i.rule_name ?? i.rule_id} limits={{ maxChars: 160, maxLines: 2 }} />
        </Link>
        <SeverityBadge severity={i.severity} />
        <StateChip state={i.human_state} />
      </div>
      <Stance s={s.stance} />
      <p className="m-0 text-sm text-muted">
        {i.key_fields.map((k, n) => (
          <span key={n} className="font-mono">
            {n > 0 && " · "}
            <UntrustedText value={`${k.field} ${String(k.value ?? "")}`} limits={{ maxChars: 120, maxLines: 1 }} />
          </span>
        ))}
        {i.key_fields.length > 0 && " · "}
        {count(i.alert_count)} {plural(i.alert_count, "alert")}
        {i.reasons[0] && (
          <>
            {" · "}
            <UntrustedText value={i.reasons[0]} limits={{ maxChars: 200, maxLines: 2 }} />
          </>
        )}
      </p>
    </li>
  );
}

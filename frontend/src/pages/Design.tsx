import { Tabs } from "@base-ui/react/tabs";
import { type ReactNode, useState } from "react";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { Time } from "../components/Time";
import { UntrustedText } from "../components/UntrustedText";
import { Badge, SeverityBadge, type Tone } from "../components/ui/badge";
import { Button } from "../components/ui/button";
import { Card, CardTitle } from "../components/ui/card";
import { useAnnounce } from "../lib/announce";
import { HOSTILE } from "../lib/hostile";
import { zoneLabel } from "../lib/site";

const TOKENS: { name: string; role: string; swatch: string }[] = [
  { name: "bg", role: "page background", swatch: "bg-bg" },
  { name: "surface", role: "cards and panels", swatch: "bg-surface" },
  { name: "surface-2", role: "sidebars, code, quiet areas", swatch: "bg-surface-2" },
  { name: "border", role: "lines between things", swatch: "bg-border" },
  { name: "text", role: "body text", swatch: "bg-text" },
  { name: "muted", role: "secondary text", swatch: "bg-muted" },
  { name: "accent", role: "links and the main action", swatch: "bg-accent" },
  { name: "critical", role: "critical severity", swatch: "bg-critical" },
  { name: "high", role: "high severity", swatch: "bg-high" },
  { name: "medium", role: "medium severity", swatch: "bg-medium" },
  { name: "low", role: "low severity", swatch: "bg-low" },
  { name: "ok", role: "healthy, done", swatch: "bg-ok" },
  { name: "warn", role: "needs a look", swatch: "bg-warn" },
  { name: "danger", role: "failed, stopped, destructive", swatch: "bg-danger" },
  { name: "marker", role: "hidden characters in untrusted text", swatch: "bg-marker" },
];

const TONES: Tone[] = ["neutral", "ok", "warn", "danger", "info"];

const EXAMPLE = {
  method: "POST" as const,
  path: "/api/v1/investigations/00000000-0000-4000-8000-000000000000/reviews",
  body: {
    action: "reviewed",
    outcome: "benign_expected",
    note: "Scanner run by the lab \u202egnp.exe\u202c, see ticket",
    version: 3,
  },
};

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <Card>
      <CardTitle>{title}</CardTitle>
      {children}
    </Card>
  );
}

/** /app/design: the design system, and the safety parts of Q-B1 shown working. */
export function Design() {
  const { announce } = useAnnounce();
  const [confirming, setConfirming] = useState(false);
  const [sevenMinutesAgo] = useState(() => new Date(Date.now() - 7 * 60_000));
  return (
    <>
      <h1 className="m-0 text-2xl font-semibold">Design system</h1>
      <p className="m-0 max-w-prose text-muted">
        The colours, components and safety parts every page of the app is built from. Colours follow the system’s light
        or dark setting; each colour that carries meaning comes with words.
      </p>

      <Section title="Colours">
        <ul className="m-0 grid list-none grid-cols-1 gap-2 p-0 sm:grid-cols-2 lg:grid-cols-3">
          {TOKENS.map((t) => (
            <li key={t.name} className="flex items-center gap-3">
              <span className={`inline-block size-8 shrink-0 rounded-control border border-border ${t.swatch}`} aria-hidden="true" />
              <span className="text-sm">
                <code>{t.name}</code> <span className="text-muted">· {t.role}</span>
              </span>
            </li>
          ))}
        </ul>
      </Section>

      <Section title="Text">
        <p className="m-0 text-2xl font-semibold">Page title</p>
        <p className="m-0 text-base font-semibold">Section title</p>
        <p className="m-0">Body text for summaries and explanations, in plain words.</p>
        <p className="m-0 text-sm text-muted">Secondary text: where a value came from, and when.</p>
        <p className="m-0">
          <code>code and raw values</code> · <kbd>j</kbd> <kbd>k</kbd> keys
        </p>
      </Section>

      <Section title="Buttons">
        <div className="flex flex-wrap gap-2">
          <Button variant="primary">Main action</Button>
          <Button>Secondary</Button>
          <Button variant="ghost">Quiet</Button>
          <Button variant="danger">Destructive</Button>
          <Button disabled>Not available</Button>
          <Button size="sm">Small</Button>
        </div>
      </Section>

      <Section title="Labels">
        <div className="flex flex-wrap gap-2">
          <SeverityBadge severity="critical" />
          <SeverityBadge severity="high" />
          <SeverityBadge severity="medium" />
          <SeverityBadge severity="low" />
          <SeverityBadge severity={null} />
          {TONES.map((tone) => (
            <Badge key={tone} tone={tone}>
              {tone}
            </Badge>
          ))}
        </div>
      </Section>

      <Section title="Times">
        <p className="m-0">
          Shown in {zoneLabel()}, UTC on hover: <Time value="2026-10-23T09:30:00Z" /> · relative: <Time value={sevenMinutesAgo} relative />
        </p>
      </Section>

      <Section title="Tabs">
        <Tabs.Root defaultValue="overview">
          <Tabs.List aria-label="Example tabs" className="flex gap-1 border-b border-border">
            {["overview", "evidence", "timeline"].map((v) => (
              <Tabs.Tab
                key={v}
                value={v}
                className="min-h-8 cursor-pointer rounded-t-control border-0 bg-transparent px-3 text-sm text-muted capitalize aria-selected:bg-accent-soft aria-selected:font-semibold aria-selected:text-text"
              >
                {v}
              </Tabs.Tab>
            ))}
          </Tabs.List>
          <Tabs.Panel value="overview" className="pt-3 text-sm">The summary comes first.</Tabs.Panel>
          <Tabs.Panel value="evidence" className="pt-3 text-sm">Evidence, each fact with where it came from.</Tabs.Panel>
          <Tabs.Panel value="timeline" className="pt-3 text-sm">What happened, in order.</Tabs.Panel>
        </Tabs.Root>
      </Section>

      <Section title="Untrusted text">
        <p className="m-0 mb-3 max-w-prose text-sm text-muted">
          Everything from logs, alerts, Kibana, people and models is shown as text only: never as markup or a link, capped in
          length, with hidden and reordering characters shown as markers, and a domain written with non-ASCII letters shown
          with its real (ASCII) form beside it.
        </p>
        <dl className="m-0 grid grid-cols-1 gap-x-4 gap-y-2 md:grid-cols-[14rem_1fr]" data-testid="hostile">
          {HOSTILE.map((h) => (
            <div key={h.name} className="contents">
              <dt className="text-sm font-medium">{h.name}</dt>
              <dd className="m-0 min-w-0 rounded-control bg-surface-2 px-2 py-1 text-sm">
                <UntrustedText value={h.value} block />
              </dd>
            </div>
          ))}
        </dl>
      </Section>

      <Section title="Confirm dialog">
        <p className="m-0 mb-3 max-w-prose text-sm text-muted">
          Every change shows the exact request before it is sent, and sends exactly what it showed. This example sends
          nothing.
        </p>
        <Button variant="primary" onClick={() => setConfirming(true)}>
          Review this example
        </Button>
        <ConfirmDialog
          open={confirming}
          onOpenChange={setConfirming}
          title="Send this review?"
          description="ARGUS records the review under your name. (Example: nothing is sent.)"
          request={EXAMPLE}
          confirmLabel="Send the review"
          send={async () => {
            await new Promise((done) => setTimeout(done, 300));
            return { status: 0, data: null }; // an example: nothing goes out
          }}
          onSent={() => announce("Nothing was sent: this was an example.", "ok")}
        />
      </Section>

      <Section title="Messages">
        <p className="m-0 mb-3 max-w-prose text-sm text-muted">
          Results are said in words, on screen and to screen readers, and stay until dismissed.
        </p>
        <div className="flex flex-wrap gap-2">
          <Button onClick={() => announce("The review was saved.", "ok")}>A result</Button>
          <Button onClick={() => announce("Two alerts arrived after your review.", "warn")}>A warning</Button>
          <Button onClick={() => announce("The review could not be saved: the investigation changed. Read it again.", "danger")}>
            A failure
          </Button>
        </div>
      </Section>
    </>
  );
}

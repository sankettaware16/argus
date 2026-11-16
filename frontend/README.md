# ARGUS app (`/app`)

The React app served by `argus web` at `/app` (Phase 3 plan §7.5; Q-B1 builds the foundation,
Q-B2 to Q-B4 its pages). The build is committed (DQ25) in `src/argus/web/spa/`, so a deploy
needs no Node; `argus doctor` says when that build is older than these sources.

## Toolchain (DQ25)
Node 24 and npm 11 from `~/.local/opt/node24` (never the system Node 20). Exact pins, install
scripts blocked, only releases at least 14 days old (`.npmrc`); add or change a package with
`npm install --save-exact --before=<date 14 days ago> <name>@<version>` and record why. Heavy
commands (installs, builds, Playwright, Stryker) go through `scripts/heavy.sh`.

```bash
export PATH=$HOME/.local/opt/node24/bin:$PATH
scripts/heavy.sh --mem 3G scripts/frontend_gate.sh data/gate/frontend   # the whole gate
npm run typecheck && npm run lint && npm test                          # while working
npm run client          # regenerate src/client from docs/api/openapi-v1.json (Hey API)
npm run build           # writes ../src/argus/web/spa and checks the initial JS budget
uv run python ../scripts/frontend_build.py manifest   # then record what it was built from
```

`npm run lint` also fails when `src/client` is not what the committed spec makes. The browser
checks (CSP and Trusted Types tripwire, hostile values, axe with WCAG 2.2, the stale-build
reload) are pytest tests: `tests/integration/web/test_app_browser.py`, in Chromium and Firefox.

## Rules (plan §7.5)
- The CSP is never loosened; `/app` adds Trusted Types (`trusted-types 'none'`), so nothing may
  assign a string to `innerHTML` or any other markup sink. The lint refuses
  `dangerouslySetInnerHTML`, style attributes, `innerHTML`, `insertAdjacentHTML`, `eval` and the
  rest; `tests/lint.test.ts` proves each one.
- Untrusted text (logs, alerts, Kibana, people, models) is shown only through `UntrustedText`.
- Every change shows its exact request in `ConfirmDialog` and sends what it showed: give it the
  `request` (method, path, body) and an `onSent`; it copies the request when it opens and sends
  that copy itself through `sendExact` (`src/lib/api.ts`), method, path and body text as shown.
  Never pass a `send` of your own outside tests and `/app/design`, and never send a change
  through a generated SDK function after the dialog (it would serialize the body again).
- Components are Base UI with Tailwind classes (no Radix, sonner, vaul or CDNs); colours are
  the tokens in `src/styles.css` (OKLCH, light and dark from the system), always with words.
- Charts (Q-B2): drawn by React as SVG (`components/charts/`, geometry in `lib/chart.ts`), never by
  ECharts: its painter assigns `innerHTML`, which Trusted Types refuse. Every chart has a table
  beside it (a `details` "As a table", or the breakdown's own table) and a text label.
- Untrusted text goes through `UntrustedText`; in an `<option>` or an `aria-label`, where markup
  cannot go, through `optionText` (hidden characters written as markers).
- A number the code works out for a size or place (a virtual list's rows) is set through the
  CSSOM in `components/Sized.tsx`, the one place that does it; the lint still refuses the JSX
  `style` prop. The CSP allows it (the browser suite's tripwire counts 0 violations).
- A change composed in a visible form (a review, a gold answer) is sent from that form with the
  typed client; a change ARGUS composed (Accept, Ask the AI, a group's confirmation) shows its
  exact request in `ConfirmDialog` first. Every failure is said by `lib/failure.ts`: plain words,
  never retried (401 leaves for /signin, 403 `csrf` reads the session once).
- Tests: `tests/helpers.tsx` has the mock API (`mockApi()`, MSW), the fixtures and `renderApp(path)`,
  the app with its router, queries and messages at an address.

## Cases, approvals and Check more (Q-B3)
- Pages: `/app/cases` (the list), `/app/cases/<id>` (a case in analyst order), `/app/approvals` (the
  queue); "Check more" is a section of an investigation's Overview and of a case's Members.
  A case's permanent link `/go/case/<uuid>` leads to its page.
- Every change a person gives (take, assign, release, contain, reopen, ask for a closure or a
  merge, approve, reject, a group, a check) shows its exact request in `ConfirmDialog` and names
  the version it was looked at (`expected_version`, `seen_version`); a closure or merge also names
  the hash of the preview the person read (`payload_hash`), so a request is never one they did not
  see. Notes are typed in a visible form and sent from it. A disabled action says why, in the
  server's words (`why_not`), next to the button.
- A group of alike closures is kept as it was first shown while a person works through it (its
  sample, one by one, then the rest together): the queue shrinks after each approval, a smaller
  group would have a smaller sample.
- Text from people and from Kibana (titles, notes, comments, approval words) goes through
  `UntrustedText`; a Kibana comment sits in its own labelled frame, never in a notice. In an
  `aria-label` a value goes through `optionText`.
- The Members section of a case is where Q-C2's suggested members and the still-active watch go
  (new fields on `CaseDetail`); `src/argus/web/casepages.py` builds the page, and
  `app.state.quiet_windows_for` (a function of the request's connection) is where Q-C2's finder is handed to `CaseService`.


## Parity and the switch (Q-B4)
- Pages added so that nothing the classic server-rendered app showed is missing: `/app/rules`,
  `/app/hosts` (`pages/Browse.tsx`), `/app/patterns` (with the group review, which shows its exact
  request first), `/app/health`, `/app/glossary`, `/app/metrics` (`pages/System.tsx`),
  `/app/tuning`, `/app/gold`. All read routes that `/api/v1` already had. "Your access" stays a
  server page (`/access`): the session route does not carry what it says.
- The classic pages are gone: a classic address answers 303 to the same page here
  (`src/argus/web/classic.py`), a classic form address answers 410. The menu opens one server page,
  "Your access". Tests: `tests/parity-pages.test.tsx`; the server side
  `tests/integration/web/test_classic_redirects.py`.
- The access banner (`shell/AccessBanner.tsx`, Q-B4 review): `GET /api/v1/session` carries
  `break_glass` and `unverified` ({since, why}); the shell shows what the classic pages showed on
  every page (an emergency session; ELK sign-in ARGUS cannot confirm). `useSessionWatch` reads the
  session again every minute as a background request (it never keeps the session alive), so the
  banner follows the server without a reload. Tests: `tests/access-banner.test.tsx`.

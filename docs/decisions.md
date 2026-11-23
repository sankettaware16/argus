# Design decisions

Comments, tests and documents in this repository cite design decisions by number (`D-123`). This
is the index of every decision cited: its number and what was decided, as it was recorded when
it was taken. A later decision may replace an earlier one; it then says so.

The full entries (the context, the alternatives that were rejected and why) are kept with the
project's working notes, which describe the first installation's network and are not published.
If you want the reasoning behind one, open an issue and name its number.

Other labels in comments (`Q-A5`, `AR8`, `P4-F E3`, `DQ25`, `plan §7.6`) name the work item or
the planning question a piece of code was built under; they have no public counterpart.

| Decision | What was decided |
| --- | --- |
| D-001 | Run ARGUS locally until its value is proven |
| D-004 | ARGUS owns alerts via workflow tags/status, not assignees |
| D-009 | PostgreSQL is the system of record and the job queue |
| D-016 | Audit trail is append-only via database triggers (role separation later) |
| D-022 | (about the first installation or the project's own process; not published) |
| D-023 | Unknown is not negative |
| D-025 | Phase 1 includes the human review loop |
| D-028 | Separate history.window, memory.window and retention (amends D-005) |
| D-029 | Database roles; audit triggers ENABLE ALWAYS (extends D-016) |
| D-030 | Fixture toolkit, one-day corpus capture, cassettes, local-ES tier |
| D-032 | Asset map imported by the operator; ARGUS holds no SSH credential |
| D-033 | (about the first installation or the project's own process; not published) |
| D-037 | Strict configuration sources (refines D-018) |
| D-038 | Redaction design and accepted residual gaps |
| D-040 | Mutation testing with ARGUS's own runner, not mutmut (amends the plan's §10) |
| D-041 | Fixture sanitizer v2: identity rules, fail-closed site space, a paranoid scanner (amends D-030) |
| D-042 | Fixture sanitizer 2.1.0: context kinds, word-indexed dictionary, one-to-one ids (amends D-041) |
| D-048 | R4 Elastic Gateway: design choices (amends D-010 and D-030) |
| D-049 | R4 review round 1: health staleness, DEGRADED budget, bucket counting (amends D-048) |
| D-050 | R5 collector: one id-diff routine for live, backfill and reconciliation; no PIT |
| D-051 | R6 grouper and job queue: pure ids, per-investigation locks, fenced leases |
| D-052 | R7 Inbox v0: server-rendered pages on a thin FastAPI app, loopback only |
| D-053 | Investigations are keyed by the actor, not by every key field (amends plan §7.1, D-051) |
| D-054 | R8 context graph and worker: refs-only LangGraph, evidence keyed in Postgres, local-only stub pack |
| D-055 | R8 review round 1: run gate, poison jobs, storable answers (amends D-054) |
| D-056 | (about the first installation or the project's own process; not published) |
| D-057 | R9 reference data: rules from the alerts themselves, TI mirror + cached lookups |
| D-058 | R10 generic pack: runbooks derived from the rules' own notes, no per-rule config |
| D-059 | R9 review round 1: exact counts, lookups by value with spellings (amends D-057) |
| D-060 | R11–R14 as modules of the one generic pack, chosen by the data, not by rule |
| D-061 | (about the first installation or the project's own process; not published) |
| D-062 | R17 write-back: progress per batch, so no alert is sent twice (refines D-061 §3) |
| D-063 | R11–R14 and R17 review: stricter "unknown", newest decision only, one run at a time |
| D-066 | The device that saw an alert is no host entity (normalizer 1.1, migration 0015) |
| D-067 | (about the first installation or the project's own process; not published) |
| D-068 | (about the first installation or the project's own process; not published) |
| D-069 | (about the first installation or the project's own process; not published) |
| D-070 | Log requests once per investigation; both log checks on |
| D-071 | (about the first installation or the project's own process; not published) |
| D-072 | (about the first installation or the project's own process; not published) |
| D-076 | P1, the privacy layer: what a model may see, and the limits accepted |
| D-077 | P1 after adversarial review 1: what changed (supersedes parts of D-076) |
| D-078 | Measure what the privacy layer costs the model's answers |
| D-080 | P2: how the gold set is chosen and pre-filled |
| D-081 | (about the first installation or the project's own process; not published) |
| D-082 | The gold set v1 is used as answered; it grows through normal reviews |
| D-084 | P3: assessments are their own table, keyed by the privacy view |
| D-085 | P4: the decision engine learns little today, by design |
| D-086 | (about the first installation or the project's own process; not published) |
| D-087 | Fake comparison arms are sent only as a proof against the policy text |
| D-090 | P7 rule tuning, and the agent switched on in the service |
| D-091 | P8: assessments in the Inbox |
| D-092 | P9: the Phase 2 soak, and how each exit criterion is judged |
| D-093 | (about the first installation or the project's own process; not published) |
| D-094 | The AI cost is always in view; the investigator's proposals are grouped by rule |
| D-095 | The AI shows its work in the Inbox; lists sort newest first; pages explain themselves |
| D-096 | A model call that never reached a provider costs nothing; the month is reconciled |
| D-098 | A daily cost cap for the models; the investigator no longer uses the large model |
| D-100 | Gemini's medium tier uses flash-lite |
| D-101 | The free providers first, the paid one last (supersedes D-074's order) |
| D-102 | The Inbox layout: a grouped sidebar, counter cards, an investigation page with tabs |
| D-103 | A SOC dashboard, on ARGUS's own records only |
| D-104 | (about the first installation or the project's own process; not published) |
| D-105 | After Phase 2: a real frontend stack, a small set of agents defined in Markdown, Phase 3 next |
| D-106 | A deferred assessment waits an hour at most, and says why |
| D-108 | (about the first installation or the project's own process; not published) |
| D-109 | (about the first installation or the project's own process; not published) |
| D-110 | Decisions under D-109: the plan's questions, and how Phase 3 is run |
| D-111 | (about the first installation or the project's own process; not published) |
| D-112 | (about the first installation or the project's own process; not published) |
| D-120 | (about the first installation or the project's own process; not published) |
| D-121 | (about the first installation or the project's own process; not published) |
| D-123 | (about the first installation or the project's own process; not published) |
| D-130 | The identity lane gets 300 ms a minute, Kibana reads 150 (plan §7.8 corrected) |
| D-131 | The lane split corrected: Kibana reads keep 200 ms, freshness gives 50 (supersedes D-130's split) |
| D-150 | (about the first installation or the project's own process; not published) |
| D-152 | (about the first installation or the project's own process; not published) |
| D-154 | (about the first installation or the project's own process; not published) |
| D-155 | (about the first installation or the project's own process; not published) |
| D-157 | (about the first installation or the project's own process; not published) |
| D-158 | The case team: each agent comments on the Kibana case under its own user (AR8) |
| D-159 | (about the first installation or the project's own process; not published) |
| D-160 | AR2 and AR2b: one run per pattern, raise by evidence, suggested cases |
| D-162 | Review fixes to AR2 and AR2b: a person's "no" stands, suggestions have their own budget, a verdict is not a Confirm |
| D-164 | (about the first installation or the project's own process; not published) |
| D-165 | AR3: outside threat intel (VirusTotal, Shodan, Censys) and the link to Needs attention |
| D-168 | AR2c's strategy: domain families, one outside lookup per parent, operators and shared servers; Shodan through InternetDB |
| D-169 | (about the first installation or the project's own process; not published) |
| D-170 | AR2c as built: families, flags, campaigns and the suggested cases they make |
| D-171 | What an open case holds is never suggested into a new case |
| D-172 | (about the first installation or the project's own process; not published) |
| D-174 | (about the first installation or the project's own process; not published) |
| D-176 | AR4b as built (1): "owner notified" is a fact on an open case, not a state |
| D-180 | (about the first installation or the project's own process; not published) |
| D-181 | AR4b after the adversarial review: a change that lasts, one device's alerts only, a notice that can be withdrawn |
| D-182 | AR4 as built (1): Home is the case-first queue, from one new read and two existing ones |
| D-184 | AR4 as built (3): Confirm, Change, Next and the keys are one control |
| D-186 | AR4 after the adversarial review (1): what is work, and in what order |
| D-187 | AR4 after the adversarial review (2): Home's patterns are counted in SQL, not sampled |
| D-189 | (about the first installation or the project's own process; not published) |
| D-190 | AR7 as built (1): the incident report is a stored, versioned object written by code from verified facts |
| D-193 | AR7 as built (4): Confirm and Reject are labels through the review path, and close nothing |
| D-195 | When a case is posted to Kibana: off by default, then a person's confirmation or a confident true positive, a daily cap, a canary |
| D-200 | AR8 as built (5): a person's Verdict: comment is read after every Kibana sync cycle and becomes the label through AR7's path |
| D-201 | AR7/AR8 after the adversarial review: what was found and where each point is decided |
| D-203 | A hypothesis is ruled out only by facts that count against it and kept only by facts that support it |
| D-205 | The report is not rewritten for alert counts alone, and actors are compared in one unit |
| D-206 | Nothing is ever sent to a placeholder case; `skip` waits for the case; the path for a hand-made collision |
| D-207 | A person's Confirm opens a Kibana case only for a true positive on the newest report version |
| D-208 | Links by origin, the approver reads every word, the doctor's guards, and a downgrade that loses nothing sent |
| D-209 | A case holds up to 500 alerts, 25 a call, 45 seconds apart: the arithmetic |
| D-210 | Partial tag answers never hold a case, and a sync reads only what changed |
| D-211 | A person splits a case: `argus case split` moves investigations, and the actors only they carried, to another case |
| D-214 | (about the first installation or the project's own process; not published) |
| D-216 | AR6 widened: the SSO sign-ins of every investigation's and case's internal addresses are kept per address and day |
| D-220 | The incident report carries the accounts, and a new account is what makes a new version |
| D-222 | Text from the logs is made storable, a batch the database refuses is stored by address and backed off, a bad answer stops the pass, one pass at a time |
| D-223 | Sign-in events with no account name make the day incomplete, never "no one signed in" |
| D-224 | A finished day is final three hours after its end; a lookup is dated by what it read; a missing index inside the retention is retried |
| D-225 | A person's confirm holds across report versions that differ only in the accounts |
| D-226 | A device is an address that acts, and is read over the alerts of its own investigations |
| D-227 | Smaller fixes of the AR6 review: failed-only accounts, "so far", retention, a scope note on D-219 |
| D-229 | A person's confirm of a true positive holds while the report still says true positive (supersedes D-207's "newest version" and D-225) |
| D-230 | Case titles name the incident; ARGUS keeps its own titles current; a person's title is theirs |
| D-232 | A web attack's title names what its paths looked for, in fixed words |
| D-234 | Every CHECK is written so a restore reads it back the same (migration 0060) |
| D-235 | A person-confirmed case posts in one go: 100 alerts a call and a capped burst (supersedes D-209's pacing for the case team) |
| D-236 | (about the first installation or the project's own process; not published) |
| D-237 | Kibana text: escape only what Kibana's Markdown escapes; indicators plain in code spans, not defanged (supersedes D-196's defanging in Kibana text) |
| D-238 | Two repositories, one ARGUS: the public one is a generic, one-command SOC analyst for any Elastic SIEM |
| D-240 | (about the first installation or the project's own process; not published) |
| D-241 | Edits in place, as built: three step kinds, read-then-set, never over a person (implements D-236) |
| D-242 | Speed, as built: 100 alerts a call, the write lane's 60 s burst at full health, a 3 s courtesy gap (on D-235) |
| D-243 | The write lane's burst after the deploy: a person's top-up, and the throughput said as it is (amends D-242; AR9 review F6) |
| D-244 | Kibana text, after the review: no fence in bold, no raw pipe in a cell, fences that touch are one span, and a guardian that reads as Kibana does (AR9 review F1, F2, F3, F11, F13, F15; on D-237) |
| D-245 | The advice facts from a client's 2xx answers count only for paths the case is about (AR9 review F4; on D-240) |
| D-246 | Wide tables are one unit a row, a cut never lands inside a span, and the words say what is and is not shown (AR9 review F5, F8, F9, F10, F12) |
| D-247 | A refresh is not an update round, even when it adds a comment (AR9 review F7; on D-241) |
| D-248 | Text is tested against Kibana's own reader (AR9 review F14) |
| D-250 | AR10 as built (1): the Visualiser is a seventh case-team user, optional, and its comment follows the evidence |
| D-251 | AR10 as built (2): charts in a comment are self-contained blocks of plain strings over the case's tagged alerts |
| D-252 | AR10 as built (3): the picture dashboard is drawn by code and is the PDF's second part and a file of its own |
| D-270 | The read-back reads the case team's cases: one find names every ARGUS identity (P4-B1) |
| D-271 | (about the first installation or the project's own process; not published) |
| D-272 | Sync alerts switched on by a person does not stop ARGUS's edits and comments; attaches and status changes still refuse |
| D-280 | The `site` section: what differs between organisations is configuration, read from one active profile (P4-D1, on D-238) |
| D-282 | `argus discover`: a short, fixed list of metadata reads through the gateways, a proposal with evidence, never a write (P4-D1) |
| D-283 | P4-D1's review fixes: discovery remembers nothing, evidence reads the family the rule reads, the site names what the checks ask |
| D-284 | P4-D1 part 2: the zone, the incident prefix, the own network, the quiet hours and the mapping facts are the site's |
| D-285 | The privacy layer fails closed: it needs a domain of the organisation, or it builds nothing (P4-D1 part 2 review F4) |
| D-287 | A served secrets file counts on its own; the fuzzier served paths still need the case to be about them (on D-245) |
| D-288 | Sync alerts on: an attach to an open case leaves the closed alerts out; any other status skips it (on D-272) |
| D-289 | The agents' prompt pin covers the template, not the site's words (on D-286 F6) |
| D-291 | (about the first installation or the project's own process; not published) |
| D-292 | (about the first installation or the project's own process; not published) |
| D-293 | Threat-intel sources are site settings: index, schema, mode (P4-D4 part b) |
| D-294 | (about the first installation or the project's own process; not published) |
| D-295 | The systemd units are templates each installation renders; `units` in local.yaml; what an installation runs is configuration (P4-D2) |
| D-296 | How `argus init` trusts the SIEM: a CA file, the presented CA confirmed by fingerprint, or a public root; always one pinned file (P4-D2, on D-033) |
| D-297 | `argus init` creates nothing on the SIEM: it prints the key request with the role inline, starting wide, then the exact role for the site (P4-D2) |
| D-298 | No LLM keys is a supported installation: `keys_file: null`, an overlay beside llm.yaml, and every model feature off cleanly (P4-D2) |
| D-299 | `argus init`: nine idempotent steps, an answers file that never prompts, and doctor's exit code (P4-D2) |
| D-300 | `argus init` never takes over another checkout's database container (P4-D3) |
| D-303 | `argus case team provision`: ARGUS makes its Kibana case team from one admin login |
| D-305 | (about the first installation or the project's own process; not published) |
| D-309 | (about the first installation or the project's own process; not published) |
| D-312 | (about the first installation or the project's own process; not published) |
| D-321 | (about the first installation or the project's own process; not published) |
| D-322 | (about the first installation or the project's own process; not published) |
| D-323 | The incident engine gathers the deciding evidence of its own outbound incidents on the checking lane; a ruling-out moves the certainty word, never the priority (P4-F E3/E5) |
| D-324 | The model money goes to the incidents people read: the agent only on presented P1-P3, ARGUS AI's reading per incident version, a 25-minute presenter window (P4-F Track 4) |
| D-325 | (about the first installation or the project's own process; not published) |
| D-327 | UI-first operations: the app changes settings through argus-admin; the web never writes a file or reads a key |
| D-328 | Everything after the install from the app: AI providers and keys, the agents, the asset map, connection checks |
| D-329 | A complete application for distribution: threat-intel keys, costs and usage, fresh screenshots and docs |
| D-330 | (about the first installation or the project's own process; not published) |
| D-331 | One design language for the whole app: the first-time setup's (supersedes D-330's "the working app keeps its layout" in part) |
| D-332 | The incident report opens with an analyst brief written by a large model and checked by code; many addresses of one account read as one device (supersedes D-216's "no model is ever shown the accounts" in part) |
| D-333 | A person's change in Kibana need not pause ARGUS's writes to that case: `kibana.sync.pause_on_change` |
| D-334 | One account's addresses that were never active together are one device to the engine (identity, counts, campaign lane, priority, title) |
| D-336 | Every decision a person makes in ARGUS reaches Kibana's alerts by itself: dismissals, ARGUS's own accounts, and a timer's run |
| D-337 | (about the first installation or the project's own process; not published) |
| D-338 | No word of the first site in what ARGUS says, sends or names: the site's words everywhere, neutral names in the code, three stored values kept |
| D-340 | Response times on the dashboards: MTTD, MTTA, MTTR and targets by priority; Costs is a board |

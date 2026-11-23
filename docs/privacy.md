# Privacy: what leaves your network, and what never does

ARGUS runs on your own server and keeps its data in its own database there. Most of what it
does needs no outside service at all. Two optional features ask an outside service a question:
the **AI features** (a cloud model) and the **outside reputation lookups** (VirusTotal, Shodan,
Censys). This page says, in plain words, what each of them is sent, what it is never sent, how
ARGUS makes sure of that, and what the limits are.

The short version:

- **No model ever sees one of your internal addresses, host names, account names or your own
  domain names.** They are replaced by tokens such as `I1.IP_1` and `I1.USER_1` before anything
  is sent, and the real names are put back only inside ARGUS, in memory, when the answer returns.
- **Raw log lines are never sent.** A model is given a short description that ARGUS wrote, built
  field by field from a list of what may be sent. A field that is not on the list is withheld.
- **The text is checked again just before it leaves.** If an internal name is still in it, the
  call is not made.
- **You can run ARGUS with no AI at all.** Collection, grouping, the checks, the incident engine,
  the reports and the queue work without a model key. The AI adds explanations; it decides
  nothing.

## 1. Where your data lives

| Data | Where it is | Who can read it |
|---|---|---|
| Alerts and logs | Your Elastic SIEM. ARGUS reads them with a read-only key | Whoever your SIEM allows |
| ARGUS's own records (alert groups, evidence, incidents, reports, sign-in sightings, notes) | ARGUS's PostgreSQL database on your server | ARGUS, and the people you give an ARGUS account |
| Keys (SIEM, AI providers, outside lookups) | Files on your server readable only by ARGUS's account; kept out of ARGUS's logs | The server's administrator |
| The asset map (your networks and their names) | A file on your server, outside the code | The server's administrator |

Nothing is sent to the makers of ARGUS: it has no telemetry.

## 2. What a cloud model is sent

A model is asked only when a feature that uses one is switched on and a provider key is set
(see [AI providers and keys](llm.md)). Each request holds two things: ARGUS's own instructions
(fixed text, the same for every site), and a short description of one alert group or incident.

Here is what happens to that description before it is sent. The left column is what ARGUS
knows; the right column is what the model receives.

| Inside ARGUS | Sent to the model |
|---|---|
| `192.0.2.41 made 1059 requests to 203.0.113.40 between 9:08 AM and 9:08 PM.` | `I1.IP_1 made 1059 requests to 203.0.113.40 between 9:08 AM and 9:08 PM.` |
| `192.0.2.41: Probable user: asha.k (Chrome on Windows).` | `I1.IP_1: Probable user: I1.USER_1 (Chrome on Windows).` |
| `Host lab-pc-07 asked for portal.example.org and files.bad-example.net.` | `Host I1.HOST_1 asked for I1.SITE_1 and files.bad-example.net.` |
| `The most requested address: http://203.0.113.40:8080/api/v1/ext/cookies (170 times)` | the same, unchanged |

(`192.0.2.0/24` and `example.org` stand for your own network and domain here.)

What is replaced, always:

- **Your addresses**: every private address, every address in your own public ranges and every
  address in the asset map becomes `IP_n`.
- **Your host names and asset names** become `HOST_n`.
- **Account names** become `USER_n`, whether written `asha`, `asha.k`, `asha_k` or
  `DOMAIN\asha`; a mail address becomes `EMAIL_n`.
- **Your own domains and everything under them** become `SITE_n`.

What stays readable, on purpose: **outside** addresses and domains, the paths requested there,
ports, counts, times, the rule's name, and general words about the place (`office`, `lab`,
`server`) when your asset map gives them. These are the evidence. A model that cannot see that a
device talked to `203.0.113.40` on a path named `/ext/cookies` cannot say anything useful about
it, and none of it identifies a person or a machine of yours.

The tokens are numbered separately for every item, so `I1.IP_1` in one request and `I2.IP_1` in
the next do not tell a provider that they are the same machine. The list that maps tokens to
real names exists only in memory while one answer is read; it is never stored and never sent.

## 3. How ARGUS makes sure

Four independent steps, each in code, none of them a model:

1. **Default deny.** `config/llm_data_policy.yaml` lists, field by field, what a model may see
   and how: sent as it is, sent as a rounded number, replaced by a token, or dropped. A field that
   is not listed is withheld. The raw log line (`event.original`) is on the list as *dropped*.
2. **Replacement.** Every value that goes out passes through the privacy layer, which finds
   internal identifiers in any spelling it knows (dotted, decimal, hexadecimal and IPv6 forms of
   an address, a name split by dots, dashes or underscores, an address inside a URL) and replaces
   them. Free text from logs (a URL, a user agent) is cleaned, quoted and cut to 300 characters.
3. **The egress check.** The exact bytes of the request are scanned again immediately before
   they are sent. If an internal address, name or domain is found, or anything shaped like a
   password, a token or a key, **the call is refused** and recorded as refused. For the incident
   brief ARGUS also checks that none of the incident's own account and host names is left in the
   text in any form.
4. **The answer is checked too.** A model's answer may name only the tokens it was given. An
   answer that names another item's token, or a real address or account that was not in the
   facts it cites, is dropped. Every sentence ARGUS shows from a model cites the facts it rests
   on, and a number that those facts do not hold removes the sentence.

What is kept of a call is its provider, model, size, cost, time and outcome, and a hash of the
request. **The request's content is not stored.**

## 4. Why the results are still good

Hiding the names costs the model almost nothing, because the question it is asked does not
depend on them. Whether traffic is malicious shows in *what* was requested, *how often*, *at what
rhythm* and *where it went*, and all of that is sent. Who the machine belongs to matters to you,
not to the reading.

Two things keep the quality up:

- **Tokens are consistent inside a request.** The model can still reason that `I1.IP_1` made the
  requests and `I1.USER_1` signed in from it, and that eleven addresses share one account.
- **ARGUS puts the names back.** When the answer says "`I1.USER_1` is most likely the user of
  all eleven addresses", the page you read says the account's real name. You get a report with
  real names; the provider never had them.

And because every sentence must cite ARGUS's own facts, a model cannot add a "fact" of its own.
What it adds is the reading: what the facts amount to, in words a person can act on.

## 5. The outside reputation lookups

VirusTotal, Shodan and Censys are asked about **outside** things only: a public address, a
public domain, a file hash. ARGUS refuses to ask about anything internal: a private or own
address, a name under your own domains, a name holding an asset, host or account name, or
anything it cannot read for certain. The lookup carries the outside value and nothing else: not
which of your machines contacted it, not when, not how often. Answers are cached for 7 days.

A lookup does tell that service that *someone at your address* was interested in that value.
If that matters to you, leave the outside keys unset; ARGUS then uses your own threat lists only.

## 6. What a person in ARGUS can see

- An account without log access in your SIEM does not see what ARGUS read from the logs: those
  facts read "Hidden: needs log access", and the accounts that signed in from a device are left
  out, in the app and in the PDF.
- A reviewer's notes are for people only. They are never sent to a model and never written to
  Kibana.
- Reports hold your addresses and account names. The PDF is marked TLP:AMBER; send it only to
  the people who must act.

## 7. Limits you should know

Honest limits, so you can decide for yourself:

- **Outside values are sent.** A public address, an outside domain and a request path are
  visible to the model provider. If one of your own services is reached by a name that is *not*
  under the domains you listed (`site.own_domains`), ARGUS treats it as outside. List every
  domain that is yours.
- **Text from logs can hold personal data of its own.** A URL path or a user agent is cleaned of
  everything ARGUS recognises (your names, addresses, secrets) and cut short, but a path such as
  `/profile/some-name` on an outside site passes as written.
- **The asset map must be complete.** ARGUS recognises your internal names from it. Private
  address space is always internal, but a public range of yours that is neither in
  `site.own_networks` nor in the asset map would be treated as outside. Without an asset map
  ARGUS refuses to call any model.
- **A provider's own terms apply to what it receives.** Check each provider's data-retention
  and training terms before you enable it; [AI providers and keys](llm.md) notes where a free
  plan may use prompts to improve the provider's products.
- **Tokens hide identity, not behaviour.** A provider sees that *some* machine of yours contacted
  a flagged server. It cannot see which one, or whose.

## 8. Switches

| You want | Do this |
|---|---|
| No cloud model at all | Set no provider key. ARGUS says so and runs without AI |
| Stop all model calls now | **AI and agents → Stop all AI calls** in the app, or `argus llm stop` |
| A model on your own hardware | Enable the local provider ([local model guide](llm.md#12-an-optional-local-model)); the same privacy rules still apply to it |
| No outside lookups | Leave the VirusTotal, Shodan and Censys keys unset |
| Change what a field may show | Edit `config/llm_data_policy.yaml`; an unknown action is an error, and a field you remove is withheld |

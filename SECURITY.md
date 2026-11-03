# Security Policy

ARGUS is security software that holds read keys to your SIEM — vulnerability
reports are taken seriously and handled with priority. This policy follows the
[TLSOC ecosystem policy](https://github.com/sankettaware16/tlsoc).

## Supported versions

Security fixes are applied to the `main` branch and included in the next tagged
release. Older tags do not receive backported fixes.

## Reporting a vulnerability

**Do not open a public issue for security problems.**

Report privately using either channel:

1. **GitHub private vulnerability reporting** (preferred): on this repository,
   go to **Security → Report a vulnerability**.
2. **Email**: sankettaware1612@gmail.com with the subject line
   `[ARGUS SECURITY] <short summary>`.

Please include:

- The affected file/component and the commit or version.
- A description of the vulnerability and its impact.
- Reproduction steps or a proof of concept.
- Any suggested remediation.

## What to expect

- **Acknowledgement** of your report within 7 days.
- An assessment and, for accepted reports, a fix on `main` with a changelog
  entry that credits you (unless you prefer anonymity).
- Coordinated disclosure: please give us reasonable time to release a fix before
  publishing details.

## Scope notes

ARGUS's security model, so reports can target what matters:

- **Read-only towards the SIEM by default.** ARGUS's keys must hold no write
  privilege (`argus init` and `argus siem selftest` refuse a key that does);
  Kibana writes stay off until an operator names a write class and gives the
  writer its own key.
- **A load budget and health states** guard the SIEM: a way to make ARGUS exceed
  its daily budget, skip the quiet hours, or ignore a STOP state is in scope.
- **Secrets** live only in `.env` (mode 600) and key files; logs pass through a
  redaction layer. Any path that prints, logs, stores or sends a secret is in
  scope.
- **The privacy layer** pseudonymises internal names and addresses before any
  cloud LLM call; a leak of an internal identifier to a model provider is in
  scope.
- **The web Inbox** listens on `127.0.0.1` by default; network exposure requires
  TLS plus host and network allowlists. Reports about intentionally documented
  defaults are welcome as hardening suggestions via normal issues.
- Never include real deployment data (IPs, hostnames, credentials, alert
  excerpts) in reports — reproduce with placeholder data.

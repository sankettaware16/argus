# Changelog

All notable changes to ARGUS are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this repository adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] — 2026-11-03

First public release.

### Added

- **Always-on alert intake** from Kibana's Security app (detection alerts of one
  space), stored durably with an idempotent cursor: nothing is lost between
  reviews.
- **Grouping and investigation:** repeated alerts become one investigation;
  evidence packs ask the log indices bounded, read-only questions and write a
  dossier with every source named.
- **Deterministic assessment** of every investigation, with an optional LLM
  agent (Groq, OpenRouter, Gemini, OpenAI; free providers first, daily and
  monthly caps) for what rules cannot decide. Internal names and addresses are
  pseudonymised before any cloud call; without model keys ARGUS runs fully
  deterministically.
- **A web Inbox** for reviewers: cases, investigations, evidence, approvals,
  daily and weekly reports.
- **SIEM protection:** every read goes through a gateway with a daily load
  budget, health states (slow down, then stop, when the cluster is busy),
  quiet hours, kill switches and a circuit breaker. Kibana writes are off until
  an operator switches them on.
- **`argus init`:** a one-command installer (prerequisites, `.env` with
  generated passwords, PostgreSQL in Docker, certificate trust, read-only key
  checks, organisation and discovery, systemd user units, doctor), interactive
  or scripted with `--answers`.
- **`argus discover`:** proposes the site's log families, threat-intel sources
  and Kibana space from read-only metadata requests.
- **`argus doctor`:** a health check of every part, each problem with its fix.
- **Backups:** `argus backup dump|drill|check|list|prune` with restore drills
  that compare every table's fingerprint.

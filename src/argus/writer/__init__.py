"""``argus-writer``: the one process that sends ARGUS's case writes to Kibana.

It drains approved outbox rows class by class through the Kibana lane: W1 creates a case (then its
opening comment and representative alerts), W2 changes tags, severity and status with a comment, W3
closes with reason tags and then the comment. Every request is rendered from deterministic text
(:mod:`argus.writer.render`), re-checked against what Kibana holds now (:mod:`argus.writer.plan`),
preceded by a committed ``sending``, never retried, and followed by a read-back; a write whose
outcome is unknown is looked for (:mod:`argus.writer.lookup`) and never resent without a person's
approval."""

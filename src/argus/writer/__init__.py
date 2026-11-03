"""``argus-writer`` (Q-D4, plan §7.1): the one process that sends ARGUS's case writes to Kibana.

It drains approved outbox rows class by class through the Kibana lane (Q-D2): W1 creates a case
(then its opening comment and representative alerts), W2 changes tags, severity and status with
a comment, W3 closes with reason tags and then the comment. Every request is rendered from
deterministic text only (:mod:`argus.writer.render`), re-checked against what Kibana holds
now (:mod:`argus.writer.plan`), preceded by a committed ``sending``, never retried, and followed
by a read-back (:mod:`argus.writer.sender`); a write whose outcome is unknown is looked for at
2, 5, 15 and 30 minutes and never resent without a person's approval
(:mod:`argus.writer.lookup`).
"""

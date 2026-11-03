"""Cases (Phase 3, Q-C1; plan §7.1): ARGUS's record of one real-world problem across days,
hosts and rules, its lifecycle, the Kibana outbox it plans, approvals and the audit hash chain.

ARGUS's database is the system of record; Kibana is a verified mirror (plan §3 rule 1). Nothing
here sends anything to Kibana: the outbox rows wait for the writer (Q-D4).
"""

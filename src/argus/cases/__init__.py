"""Cases: ARGUS's record of one real-world problem across days, hosts and rules, its lifecycle,
the Kibana outbox it plans, approvals and the audit hash chain.

ARGUS's database is the system of record; Kibana is a verified mirror. Nothing here sends
anything to Kibana: the outbox rows wait for the writer.
"""

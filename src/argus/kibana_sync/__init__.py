"""The Kibana read-back and reconciliation (Q-D3, plan §5 and §7.1): read-only.

``argus-kibana-sync`` (``argus kibana sync run``) polls Kibana through the Kibana lane (Q-D2)
every 10 minutes in NORMAL health, 20 in CAUTION, hourly in DEGRADED and never in STOP. Each
cycle:

- reads ``kibana.status`` once an hour (Kibana's clock from its Date header: an alarm above
  30 s);
- polls changes with ``cases.find`` (``reporters`` = the service user and the case team's
  users, newest ``updatedAt`` first, P4-B1) and lists every case ARGUS made (the same
  reporters, oldest first): the **id-set diff** against the mirror finds deletions (each
  confirmed by ``cases.get``) and new cases, and each case's version finds changes the poll
  missed;
- reads the user actions of every changed case from where it stopped, and classifies them
  (``classify``: §7.1's reconciliation table and alarms);
- once an hour, finds people's cases that hold alerts ARGUS knows and alert status changes
  ARGUS cannot explain (``alerts.case_links``, Elasticsearch, in the Kibana read lane).

Pure parts: ``model`` (Kibana's answers as records), ``classify`` (the classifier, the poll
interval, the clock offset, staleness), ``readmodel`` (§7.1's read load at projected case
counts). ``cycle`` runs one cycle and the loop; ``store`` keeps the state (Postgres, or memory
for tests and the simulation). Nothing here writes to Kibana or Elasticsearch: every request
is a read template of the Kibana lane.
"""

"""The Kibana read-back and reconciliation: read-only.

``argus-kibana-sync`` polls Kibana through the Kibana lane every 10 minutes in NORMAL health, 20 in
CAUTION, hourly in DEGRADED and never in STOP. Each cycle reads ``kibana.status`` hourly (an alarm
if Kibana's clock is off by more than 30 s), polls changes with ``cases.find`` and lists every case
ARGUS made (the id-set diff against the mirror finds deletions, each confirmed by ``cases.get``,
and new cases), reads and classifies the user actions of every changed case, and hourly finds
people's cases holding alerts ARGUS knows and alert status changes ARGUS cannot explain. ``model``,
``classify`` and ``readmodel`` are pure; ``cycle`` runs the cycle and the loop; ``store`` keeps the
state. Nothing here writes to Kibana or Elasticsearch: every request is a read template."""

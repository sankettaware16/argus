"""The incident engine v2 (P4-F, docs/p4f-plan.md §5): the risk graph's foundations.

E0 gives entities a role (actor, target, threat) and rules a lineage, tactics and a log family;
E1 turns every alert group and every evidence fact on an internal object into a scored observation,
accumulates them per object and window (each source once), and decides the lanes (decisive,
burst, slow); E2 links the objects in a lane into incidents and runs their lifecycle (``link``,
``lifecycle``, ``incidents``), and E4 says which device an address is (``identity``). It runs
in **shadow**: its own tables only; today's queue, suggester and raises are unchanged. Postgres
only: no SIEM request and no model."""

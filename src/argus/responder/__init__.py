"""The responder: advice about a case, never an action. For each confirmed case it recommends the
catalogue's actions for the incident kinds the case shows (:mod:`argus.responder.catalogue`,
:mod:`argus.responder.facts`), keeps what people did (:mod:`argus.responder.store`) and says
whether the case then went quiet (:mod:`argus.responder.machine`). Deterministic, database only:
nothing is sent to the SIEM, Kibana or a model, and nothing is executed. The responder agent may
only rank and phrase catalogue actions once switched on (:mod:`argus.responder.ranking`)."""

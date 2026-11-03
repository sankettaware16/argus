"""The responder (Q-H2, plan §5 and §7.7): advice about a case, never an action.

For each confirmed case ARGUS recommends the catalogue's actions for the kinds of incident the
case shows (:mod:`argus.responder.catalogue`, :mod:`argus.responder.facts`), keeps what people
did about them (:mod:`argus.responder.store`: recommended, requested, reported done), and says
whether the case then went quiet (:mod:`argus.responder.machine`: verified, or not verified
with the last sign of activity). Everything here is deterministic and reads the database only;
nothing is sent to the SIEM, to Kibana or to a model, and nothing is executed (Phase 6 is the
first that may act). The responder agent (``config/agents/responder.md``) may only rank and
phrase catalogue actions once it is switched on; it is built off (:mod:`argus.responder.ranking`).
"""

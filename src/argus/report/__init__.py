"""report@2 (Q-F2, plan §7.3): what ARGUS found, where each fact came from, and what is new.

- ``model``: the contract (pydantic), the shape ``/api`` and the Inbox serve;
- ``facts``: provenance lines, facts from signals, steps and alerts, observations read from
  stored evidence (for people only: no model sees them, so agent@1's inputs are unchanged);
- ``diff``: "what's new", a pure diff of two views of a dossier;
- ``build``: the report of one assessment (or of a dossier alone), pure;
- ``render``: plain text, and hiding log-derived facts from people without log access;
- ``store``: reading the inputs from Postgres.

Every number is computed by code; the model's words appear only in the summary of an
assessment an agent made.
"""

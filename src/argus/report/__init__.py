"""report@2: what ARGUS found, where each fact came from, and what is new.

``model`` is the contract (the shape the API and the Inbox serve), ``facts`` the provenance lines,
facts and observations (for people only), ``diff`` "what's new", ``build`` the report of one
assessment (or of a dossier alone), ``render`` plain text and the view that hides log-derived
facts, ``store`` the reads from Postgres. Every number is computed by code; the model's words
appear only in the summary of an assessment."""

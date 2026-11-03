"""The context graph: for each job, a deterministic LangGraph run that
gathers what ARGUS knows about an investigation (stored alerts first, then evidence from the SIEM
through the gateway) and writes one dossier per investigation version."""

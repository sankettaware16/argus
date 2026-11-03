"""The Reporter: a daily and a weekly report of how ARGUS and its cases are doing, made from the
local database alone (so on time whatever the SIEM and the model providers are doing). ``model`` is
the contract (each figure a ``Metric`` with its definition), ``sections`` the SQL builders,
``build`` the period and the text, ``render`` the deterministic text, ``figures`` the check that
rejects prose with a number not in the input, ``prose`` the optional prose agent (off), ``store``
the history, ``cli`` the ``argus report daily|weekly`` commands."""

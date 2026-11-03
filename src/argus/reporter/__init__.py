"""The Reporter (Q-H3, plan §5 and §7.7): a daily and a weekly report of how ARGUS and its
cases are doing, for the people who look once a day or a few times a week.

* ``model``: the contract (pydantic): every figure is a :class:`~argus.reporter.model.Metric`
  with its definition;
* ``sections``: one SQL builder for each section, returning figures with their definitions
  (nothing is estimated, nothing is read from the SIEM or a model);
* ``build``: the period, the sections together, the text;
* ``render``: the deterministic text, written from the figures only;
* ``figures``: the number extractor and the check that rejects prose with a number that is not
  in the input;
* ``prose``: the optional prose agent's door (built off: nothing calls a model while
  ``ENABLED["reporter"]`` is None, ``argus.agent.registry``);
* ``store``: the history (``reports``, migration 0046);
* ``cli``: ``argus report daily|weekly``.

A report is made from the local database alone, so it is made on time whatever the SIEM and the
model providers are doing.
"""

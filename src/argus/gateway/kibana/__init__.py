"""The Kibana lane (Q-D2, plan §5 and §7.1): the only path from ARGUS to Kibana.

- ``paths``: the one path builder (every path in ``/s/<space>/api/``; no DELETE, ``/internal/``,
  configuration write or push can be built);
- ``templates``: the reads and the class-gated writes, ``models``: their strict bodies and the
  checks of Kibana's answers, ``validator``: the final request held to both;
- ``writes``: the write classes, caps, window and the lane's shared state;
- ``gateway``: ``KibanaGateway`` (read, start_run, write, key_privileges), ``transport``: HTTPS
  with the pinned CA, ``selftest``: the keys' canaries, ``service`` and ``cli``.
Settings: ``kibana.*`` (off by default).
"""

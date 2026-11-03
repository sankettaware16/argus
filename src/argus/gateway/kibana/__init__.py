"""The Kibana lane: the only path from ARGUS to Kibana.

``paths`` builds every path; ``templates`` and ``models`` define the reads and class-gated writes
with their strict bodies and answer checks; ``validator`` holds the final request to both;
``writes`` has the write classes, caps and shared state; ``gateway`` is ``KibanaGateway``;
``transport`` is the HTTPS client; ``selftest`` has the keys' canaries. Settings: ``kibana.*``
(off by default).
"""

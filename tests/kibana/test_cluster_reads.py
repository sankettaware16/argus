"""§12 #17 and the readable half of #16: the Elasticsearch reads ARGUS's own keys make.

* ``GET /_license`` needs only the ``monitor`` cluster privilege: the runbook's reader key
  (argus_reader) reads it; Kibana's reader key (application privileges only) cannot.
* The security index's health (``GET /_cluster/health/.security``, the check that must come
  before a 401 counts as a denial, plan §7.2) is readable with ``monitor`` too. That the index
  being down turns every native user's answer into a 401 needs a tier of its own and is left
  to Q-E2 (docs/runbooks/kibana-tier.md, "What cassettes cannot do").
"""

from __future__ import annotations

from tests.kibana import kit
from tests.kibana.tier import Tier

LICENSE_KEEP = {"license": ["type", "status"]}


def _license(kt: Tier, principal: str) -> tuple[int, object]:
    reply = kt.es(principal).get(
        "/_license",
        keep=lambda b: {"type": b["license"]["type"], "status": b["license"]["status"]},
    )
    if reply.status == 200:
        return 200, reply.body
    return reply.status, reply.body["error"]["type"]


def _security_health(kt: Tier, principal: str) -> tuple[int, object]:
    reply = kt.es(principal).get(
        "/_cluster/health/.security",
        keep=lambda b: {
            k: b[k] for k in ("status", "active_primary_shards", "unassigned_primary_shards")
        },
    )
    if reply.status == 200:
        return 200, reply.body
    return reply.status, reply.body["error"]["type"]


def test_the_licence_needs_only_monitor(kt: Tier) -> None:
    monitor = kit.make_es_role(kt, "mon-r", {"cluster": ["monitor"]})
    with_monitor = kit.make_user(kt, "mon", [monitor])
    without = kit.make_user(kt, "nomon", [])
    basic = (200, {"type": "basic", "status": "active"})
    assert _license(kt, with_monitor) == basic
    assert _license(kt, "key:argus-reader") == basic
    assert _license(kt, without) == (403, "security_exception")
    assert _license(kt, "key:argus-kibana-reader") == (403, "security_exception")


def test_the_security_index_health_is_readable_with_monitor(kt: Tier) -> None:
    without = kit.make_user(kt, "nohealth", [])
    assert _security_health(kt, "key:argus-reader") == (
        200,
        {"status": "green", "active_primary_shards": 1, "unassigned_primary_shards": 0},
    )
    assert _security_health(kt, without) == (403, "security_exception")

"""The read-only keys ARGUS needs, as Kibana Dev Tools requests a person pastes. Init never creates
a user, a role or a key on the SIEM; it prints the request that makes the key, with the role
inline, and asks for the key.

The Elasticsearch key reads what the gateway reads: ``monitor``, and ``read`` and
``view_index_metadata`` on the alerts index and its backing indices, the log families and the
threat-intel sources. Kibana's key holds Cases Read in the space. Before discovery the starting key
reads every space's alerts; afterwards init prints the exact role for the site, to narrow it to.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

from argus.site import SiteSettings

ES_KEY = "argus-reader"
KIBANA_KEY = "argus-kibana-reader"
STARTING_LOGS = ("logs-*",)
STARTING_ALERTS = (".alerts-security.alerts-*", ".internal.alerts-security.alerts-*")
PURPOSE = "read-only first-line analyst: alerts, logs, threat intel, node health"


def es_names(site: SiteSettings) -> list[str]:
    """The indices the gateway reads for ``site``, in the order a person reads them."""
    names = [site.alerts_index_name, f"{site.alerts_backing_prefix}*"]
    names += [*site.checked_log_patterns, *site.ti_indices]
    return list(dict.fromkeys(names))


def starting_names(log_patterns: Sequence[str]) -> list[str]:
    """The starting key's indices: every space's alerts and the given log patterns."""
    return list(dict.fromkeys([*STARTING_ALERTS, *(log_patterns or STARTING_LOGS)]))


def es_role(names: Sequence[str]) -> dict[str, Any]:
    return {
        "cluster": ["monitor"],
        "indices": [
            {
                "names": list(names),
                "privileges": ["read", "view_index_metadata"],
                "allow_restricted_indices": False,
            }
        ],
    }


def kibana_role(site: SiteSettings, *, every_space: bool = False) -> dict[str, Any]:
    resource = "*" if every_space else f"space:{site.space}"
    return {
        "cluster": [],
        "indices": [],
        "applications": [
            {
                "application": "kibana-.kibana",
                "privileges": [f"feature_{site.kibana_features.cases}.read"],
                "resources": [resource],
            }
        ],
    }


def key_request(name: str, role_name: str, role: dict[str, Any], purpose: str) -> str:
    """A Dev Tools request that creates an API key limited to ``role`` (the key never holds more
    than its creator either). Its answer's ``encoded`` is the key."""
    body = {
        "name": name,
        "expiration": "90d",
        "role_descriptors": {role_name: role},
        "metadata": {"application": "argus", "purpose": purpose},
    }
    return "POST /_security/api_key\n" + json.dumps(body, indent=2) + "\n"


def es_request(names: Sequence[str]) -> str:
    return key_request(ES_KEY, "argus_reader", es_role(names), PURPOSE)


def kibana_request(site: SiteSettings, *, every_space: bool = False) -> str:
    where = "every space" if every_space else f"space {site.space}"
    return key_request(
        KIBANA_KEY,
        "argus_kibana_reader",
        kibana_role(site, every_space=every_space),
        f"Kibana Cases read in {where} (read-back)",
    )


HOW = (
    "In Kibana: Dev Tools (Console), paste the request, run it as an administrator, and copy\n"
    '"encoded" from the answer: that is the key. It expires in 90 days (note the date).'
)

"""Which indicators may be asked of an outside source: external ones only. An address is eligible
when the classifier calls it public and the privacy layer's internal view does not hold it; a name
when it is a public domain holding no internal domain, asset, host or user name; a URL needs an
eligible host and no internal identifier; a file hash always passes. Anything the check cannot
read is refused. The internal view is per item (:meth:`Eligibility.for_item`): the host and user
names a dossier mentions count as internal names for it."""

from __future__ import annotations

import ipaddress
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from typing import Any

from argus import site
from argus.assets.classify import IpClass, IpClassifier
from argus.llm.detect import OwnSpace, find
from argus.outside import facts

# special-use and non-public suffixes: a name under one is not a public name
_PRIVATE_SUFFIXES = (
    "local", "localhost", "localdomain", "internal", "intranet", "private", "lan", "corp",
    "home", "home.arpa", "in-addr.arpa", "ip6.arpa", "invalid", "test", "example", "onion",
)  # fmt: skip


# addresses the classifier calls public that no public name is behind: site-local (fec0::/10,
# deprecated but still routed inside some networks)
_NOT_PUBLIC = (ipaddress.ip_network("fec0::/10"),)


@dataclass(frozen=True)
class Eligibility:
    classifier: IpClassifier
    ours: OwnSpace
    # the privacy layer's ``ours_for``: the base own space plus the names a dossier mentions
    ours_for: Callable[[Sequence[Any]], OwnSpace] | None = field(
        default=None, compare=False, repr=False
    )

    def for_item(self, body: Mapping[str, Any]) -> Eligibility:
        """This check with the organisation's own names as one investigation's dossier ``body``
        gives them (its host and user names added), as the model's view of it is scrubbed."""
        if self.ours_for is None:
            return self
        return replace(self, ours=self.ours_for([body]))

    def with_ours(self, ours: OwnSpace) -> Eligibility:
        return replace(self, ours=ours)

    def check(self, kind: str, value: str) -> str | None:
        """Why ``value`` (an indicator of ``kind``, in its canonical spelling) may not be looked
        up, or None when it may."""
        if kind == "hash":
            return None if facts.canonical("hash", value) == value else "not a file hash"
        if kind == "ip":
            return self._address(value)
        if kind == "domain":
            return self._name(value)
        if kind == "url":
            return self._url(value)
        return f"no lookups of {kind}"

    def _address(self, value: str) -> str | None:
        got = self.classifier.classify(value)
        if got.address is None:
            return "not an address"
        if got.ip_class is not IpClass.PUBLIC:
            return site.a_own_or("address", "private", "special-use")
        address = ipaddress.ip_address(got.address)
        if any(address.version == n.version and address in n for n in _NOT_PUBLIC):
            return site.a_own_or("address", "private", "special-use")
        if self.ours.internal(address):
            return site.a_own("address")
        return None

    def _name(self, value: str) -> str | None:
        name = facts.canonical("domain", value)
        if name is None or name != value:
            return "not a public domain name"
        if any(name == s or name.endswith("." + s) for s in _PRIVATE_SUFFIXES):
            return "not a public domain name"
        if self.ours.own_domain(name):
            return site.a_own("name")
        if find(name, self.ours):
            return site.a_own("name")
        return None

    def _url(self, value: str) -> str | None:
        url = facts.canonical("url", value)
        if url is None or url != value:
            return "not a URL"
        host = facts.host_of(url)
        why = self._address(host) if _is_address(host) else self._name(host)
        if why is not None:
            return why
        return f"{site.a_own('identifier')} in the URL" if find(url, self.ours) else None


def _is_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True

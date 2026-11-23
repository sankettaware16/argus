"""A small campus for the privacy layer's tests: private space, a campus prefix, an asset map
with a public network and names of every shape (short, with digits, several words)."""

from __future__ import annotations

import ipaddress

import pytest

from argus.assets import parse_asset_map
from argus.llm.detect import OwnSpace
from argus.llm.privacy import Privacy, load_policy

ASSETS = parse_asset_map(
    b"""
defaults: {site.organization: Example}
networks:
  - name: Geology Lab Block
    range: 10.20.0.0/16
    fields: {site.type: lab, site.zone: north, site.building: Geology, site.floor: "2"}
  - name: tp8
    range: 10.30.1.8
    fields: {site.type: server, site.zone: south}
  - name: Mailgate
    range: 203.0.113.0/24
    fields: {site.type: server, site.zone: dmz}
  - name: H12 Wing-C
    range: 192.168.12.0/24
    fields: {site.type: hostel}
"""
)
CAMPUS_PREFIX = ipaddress.ip_network("198.51.100.0/24")


@pytest.fixture(scope="session")
def privacy() -> Privacy:
    return Privacy.build(load_policy(), ASSETS, (CAMPUS_PREFIX,))


@pytest.fixture(scope="session")
def ours(privacy: Privacy) -> OwnSpace:
    return privacy.ours

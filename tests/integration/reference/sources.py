"""The threat-intel sources the integration tests run on: the active site's (the suite runs on the
shipped site, tests/conftest.py), by their index names."""

from __future__ import annotations

from argus import site

ABUSE = "abuse-ioc"
ACME = "acme-threat-intel"


def mirror_source() -> site.TiSource:
    found = site.active().ti_source(ABUSE)
    assert found is not None
    return found


def lookup_source() -> site.TiSource:
    found = site.active().ti_source(ACME)
    assert found is not None
    return found

"""The Kibana lane's version and licence gates over the site profile (P4-D1, D-238): a range of
Kibana versions, writes on every active licence level, nothing on an expired one, and the
Spaces and Features reads `argus discover` makes."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest

from argus import site
from argus.gateway.kibana import models
from argus.gateway.kibana.errors import AnswerMismatchError, WriteRefusedError
from argus.gateway.kibana.gateway import KibanaTargets
from argus.gateway.kibana.paths import KEndpoint, built, wire_path
from argus.gateway.kibana.templates import KibanaFeatures, KibanaSpaces, NoParams
from argus.gateway.kibana.writes import WriteClass
from argus.site import KibanaFeatures as FeatureIds
from argus.site import SiteSettings, VersionRange, feature_ids
from tests.unit.gateway.fakes import FakeTransport, ok
from tests.unit.gateway.kibana.fakes import (
    FakeKibana,
    make,
    ready_kibana,
    reply,
    start,
    status_answer,
)

pytestmark = pytest.mark.unit

W1 = frozenset({WriteClass.W1})


def es_with(level: str, status: str = "active") -> FakeTransport:
    return FakeTransport().on("/_license", ok({"license": {"type": level, "status": status}}))


@pytest.mark.parametrize(
    ("level", "paid"),
    [("basic", False), ("gold", False), ("platinum", True), ("enterprise", True), ("trial", True)],
)
async def test_every_active_licence_level_may_write(level: str, paid: bool) -> None:
    gateway, *_, clock, _ = make(ready_kibana(), classes=W1, es=es_with(level))
    run = await start(gateway, clock)
    assert run.licence == (level, "active")
    assert run.facts.writes_allowed
    assert (run.facts.sub_feature_privileges, run.facts.case_assignment) == (paid, paid)


@pytest.mark.parametrize("level", ["basic", "platinum", "trial", "enterprise"])
async def test_an_expired_licence_refuses_writes_of_any_level(level: str) -> None:
    gateway, *_, clock, _ = make(ready_kibana(), classes=W1, es=es_with(level, "expired"))
    with pytest.raises(WriteRefusedError) as caught:
        await start(gateway, clock)
    assert caught.value.reason == "licence"


async def test_a_licence_answer_that_says_nothing_refuses_writes() -> None:
    es = FakeTransport().on("/_license", ok({"license": {}}))
    gateway, *_, clock, _ = make(ready_kibana(), classes=W1, es=es)
    with pytest.raises(WriteRefusedError) as caught:
        await start(gateway, clock)
    assert caught.value.reason == "licence"


@pytest.mark.parametrize(
    ("versions", "kibana", "allowed"),
    [
        (">=8.0,<10", "8.19.13", True),
        (">=8.0,<10", "9.0.1", True),
        (">=8.0,<10", "7.17.9", False),
        (">=8.0,<10", "10.0.0", False),
        ("==8.19.12", "8.19.12", True),
        ("==8.19.12", "8.19.13", False),
    ],
)
async def test_a_write_run_follows_the_sites_kibana_range(
    versions: str, kibana: str, allowed: bool
) -> None:
    server = ready_kibana()
    server.routes[0] = ("GET", "/api/status", [reply(status_answer(kibana))])
    gateway, *_, clock, _ = make(server, classes=W1)
    gateway.targets = KibanaTargets(versions=VersionRange.parse(versions))
    if allowed:
        assert (await start(gateway, clock)).version == kibana
    else:
        with pytest.raises(WriteRefusedError) as caught:
            await start(gateway, clock)
        assert caught.value.reason == "version_not_pinned"
        assert "writes need" in str(caught.value)


def test_the_default_targets_are_the_active_sites() -> None:
    acme = KibanaTargets()
    assert acme.space == "acme-soc"
    assert acme.versions.describe() == "the pinned 8.19.12"
    with site.using(SiteSettings()):
        neutral = KibanaTargets()
        assert neutral.space == "default"
        assert neutral.versions.allows("9.2.0")
        assert not neutral.versions.allows("7.0.0")


# --------------------------------------------------------------------------- the reads of discovery


def test_the_discovery_reads_have_paths_in_the_space_and_are_allowlisted() -> None:
    for endpoint, path in ((KEndpoint.SPACES, "spaces/space"), (KEndpoint.FEATURES, "features")):
        assert wire_path(endpoint, "default") == ("GET", f"/s/default/api/{path}")
        assert built("GET", f"/s/default/api/{path}", "default")
        assert not built("POST", f"/s/default/api/{path}", "default")  # reads only
    assert not built("GET", "/s/default/api/spaces/space/default", "default")


async def test_the_spaces_and_features_reads_keep_ids_and_names_only() -> None:
    server = (
        FakeKibana()
        .on("GET", "/api/spaces/space", reply([{"id": "default", "name": "Default", "color": "x"}]))
        .on("GET", "/api/features", reply([{"id": "siemV2", "name": "Security", "app": ["x"]}]))
    )
    gateway, *_, clock, _ = make(server)
    deadline = clock.now + timedelta(seconds=30)
    spaces = await gateway.read(KibanaSpaces(), NoParams(), component="t", deadline=deadline)
    features = await gateway.read(KibanaFeatures(), NoParams(), component="t", deadline=deadline)
    assert spaces.body == [{"id": "default", "name": "Default"}]
    assert features.body == [{"id": "siemV2", "name": "Security"}]
    assert feature_ids(features.body) == FeatureIds()
    assert [c.method for c in server.calls] == ["GET", "GET"]


@pytest.mark.parametrize("answer", [{"id": "x"}, [{"name": "x"}], [3], "text", None])
def test_a_spaces_or_features_answer_must_be_a_list_of_things_with_ids(answer: Any) -> None:
    with pytest.raises(AnswerMismatchError):
        models.check_named(answer, "space")

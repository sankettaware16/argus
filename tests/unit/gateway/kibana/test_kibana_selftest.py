"""``argus kibana selftest`` (Q-D2): the keys' must-hold and must-not-hold canaries, judged on
answers shaped as Elasticsearch gives them, and the self-check's path through the lane."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from argus.gateway.kibana import selftest
from argus.gateway.kibana.errors import KibanaAuthError
from argus.gateway.kibana.templates import KeyRole
from tests.unit.gateway.kibana.fakes import FakeKibana, make, reply, status_answer

pytestmark = pytest.mark.unit
SPACE = "acme-soc"
ALIAS = f".alerts-security.alerts-{SPACE}"


def held(role: KeyRole, *, holds: tuple[str, ...] = (), lacks: tuple[str, ...] = ()) -> Any:
    """An answer for ``role``'s request in which the key is exactly as its profile wants,
    then holds ``holds`` and lacks ``lacks``."""
    profile = selftest.PROFILES[role]
    body = selftest.request_body(role, SPACE)
    app = dict.fromkeys(body["application"][0]["privileges"], False)
    app.update(dict.fromkeys(profile.must_app, True))
    index = dict.fromkeys(body.get("index", [{"privileges": []}])[0]["privileges"], False)
    index.update(dict.fromkeys(profile.must_index, True))
    for name in holds:
        (app if name in app else index)[name] = True
    for name in lacks:
        (app if name in app else index)[name] = False
    return {
        "has_all_requested": False,
        "cluster": dict.fromkeys(selftest.CLUSTER_CANARIES, False),
        "index": {ALIAS: index} if index else {},
        "application": {selftest.APP: {f"space:{SPACE}": app}},
    }


@pytest.mark.parametrize("role", list(KeyRole))
def test_a_key_as_its_profile_wants_has_no_problem(role: KeyRole) -> None:
    assert selftest.judge(role, SPACE, held(role)) == selftest.Verdict((), ())


@pytest.mark.parametrize(
    ("role", "privilege"),
    [
        (KeyRole.READER, "api:rac"),
        (KeyRole.READER, "cases:securitySolution/createCase"),
        (KeyRole.CASES, "api:rac"),
        (KeyRole.CASES, "alerting:siem.queryRule/siem/alert/update"),
        (KeyRole.CASES, "cases:securitySolution/deleteCase"),
        (KeyRole.CASES, "cases:securitySolution/createConfiguration"),
        (KeyRole.CASES, "cases:securitySolution/pushCase"),
        (KeyRole.CASES, "cases:securitySolution/assignCase"),
        (KeyRole.CASES, "index"),
        (KeyRole.ALERTS, "cases:securitySolution/updateCase"),
        (KeyRole.ALERTS, "delete"),
    ],
)
def test_every_must_not_hold_canary_is_a_problem(role: KeyRole, privilege: str) -> None:
    verdict = selftest.judge(role, SPACE, held(role, holds=(privilege,)))
    assert verdict.problems == (f"holds {privilege}" + (" on the alerts" if privilege in
                                ("index", "delete") else ""),)  # fmt: skip


@pytest.mark.parametrize(
    ("role", "privilege"),
    [
        (KeyRole.READER, "cases:securitySolution/getCase"),
        (KeyRole.READER, "login:"),
        (KeyRole.CASES, "cases:securitySolution/createComment"),
        (KeyRole.CASES, "alerting:siem.queryRule/siem/alert/get"),
        (KeyRole.ALERTS, "maintenance"),
    ],
)
def test_every_must_hold_privilege_missing_is_a_problem(role: KeyRole, privilege: str) -> None:
    verdict = selftest.judge(role, SPACE, held(role, lacks=(privilege,)))
    assert len(verdict.problems) == 1
    assert privilege in verdict.problems[0]
    assert verdict.problems[0].startswith("lacks")


def test_an_accepted_residual_is_listed_not_failed() -> None:
    fallback = held(KeyRole.CASES, holds=("api:rac", "cases:securitySolution/deleteCase"))
    verdict = selftest.judge(KeyRole.CASES, SPACE, fallback, ["api:rac"])
    assert verdict.residual == ("api:rac",)
    assert verdict.problems == ("holds cases:securitySolution/deleteCase",)


def test_an_answer_that_does_not_say_is_a_problem() -> None:
    assert selftest.judge(KeyRole.READER, SPACE, None).problems
    silent = held(KeyRole.READER)
    silent["cluster"] = {}
    del silent["application"][selftest.APP][f"space:{SPACE}"]["api:rac"]
    problems = selftest.judge(KeyRole.READER, SPACE, silent, ["api:rac"]).problems
    assert "holds api:rac" in problems  # unknown is never "not held", nor an accepted residual
    assert "holds cluster privilege manage_security" in problems


def test_the_request_asks_every_canary_in_one_body() -> None:
    body = selftest.request_body(KeyRole.CASES, SPACE)
    asked = set(body["application"][0]["privileges"])
    assert {"api:rac", "api:securitySolution", "cases:securitySolution/deleteCase",
            "cases:securitySolution/createConfiguration", "cases:securitySolution/pushCase",
            "cases:securitySolution/assignCase"} <= asked  # fmt: skip
    assert len([p for p in asked if p.endswith("/siem/alert/update")]) == 9
    assert body["application"][0]["resources"] == [f"space:{SPACE}"]
    assert body["index"] == [{"names": [ALIAS], "privileges": sorted(
        ["index", "write", "delete", "maintenance",
         "all", "manage", "delete_index", "create_index"])}]  # fmt: skip


async def test_the_self_check_sends_the_keys_own_request_and_a_401_stops_kibana() -> None:
    kibana = FakeKibana().on("GET", "/api/status", reply(status_answer()))
    kibana.on("POST", "/_security/user/_has_privileges", reply(held(KeyRole.CASES)))
    gateway, kibana, store, clock, _ = make(kibana)
    version, verdict = await selftest.run_selftest(
        gateway, KeyRole.CASES, deadline=clock.now + timedelta(seconds=30)
    )
    assert (version, verdict.problems) == ("8.19.12", ())
    check = kibana.calls[-1]
    assert (check.target, check.key, check.method) == ("es", KeyRole.CASES, "POST")
    assert store.ledger[-1].target == "elasticsearch"
    assert store.ledger[-1].lane == "kibana_read"
    assert store.memory.state.value == "normal"
    kibana.routes[1] = ("POST", "/_security/user/_has_privileges", [reply({}, 401)])
    with pytest.raises(KibanaAuthError):
        await selftest.run_selftest(
            gateway, KeyRole.CASES, deadline=clock.now + timedelta(seconds=30)
        )
    assert store.kibana.stopped == "401"
    assert store.memory.state.value == "normal"  # the SIEM is not stopped by a Kibana key


async def test_an_unpinned_version_is_a_problem() -> None:
    kibana = FakeKibana().on("GET", "/api/status", reply(status_answer("8.18.0")))
    kibana.on("POST", "/_security/user/_has_privileges", reply(held(KeyRole.READER)))
    gateway, *_, clock, _ = make(kibana)
    _, verdict = await selftest.run_selftest(
        gateway, KeyRole.READER, deadline=clock.now + timedelta(seconds=30)
    )
    assert verdict.problems == ("Kibana is 8.18.0, not the pinned 8.19.12",)


def test_the_dry_run_sends_nothing_and_needs_no_kibana(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from argus.cli import app
    from tests.conftest import suite_checkout

    monkeypatch.chdir(suite_checkout(tmp_path))

    result = CliRunner().invoke(app, ["kibana", "selftest", "--key", "reader", "--dry-run"])
    assert result.exit_code == 0, result.output
    assert "dry run: nothing was sent" in result.output
    assert "/s/acme-soc/api/status" in result.output
    assert '"api:rac"' in result.output
    bad = CliRunner().invoke(app, ["kibana", "selftest", "--key", "elastic", "--dry-run"])
    assert bad.exit_code == 2

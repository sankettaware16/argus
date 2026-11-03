"""``argus case team provision`` (D-303): the plan, and the run against a fake SIEM — users made,
kept or re-keyed, keys written mode 600, a login without manage_security refused, the
administrator's password never shown."""

from __future__ import annotations

import stat
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import pytest

from argus.caseteam import provision
from argus.caseteam.model import Author
from tests.conftest import example_site

pytestmark = pytest.mark.unit
NOW = datetime(2026, 11, 3, 12, 0, tzinfo=UTC)


class FakeSiem:
    def __init__(self, *, users: set[str] | None = None, manage: bool = True) -> None:
        self.users = set(users or ())
        self.manage = manage
        self.calls: list[tuple[str, str, Any, str | None]] = []
        self.passwords: dict[str, str] = {}
        self.keys: dict[str, str] = {}
        self.roles: dict[str, Any] = {}
        self.wrong_key_owner = False

    def call(
        self, method: str, path: str, body: Any = None, *, api_key: str | None = None
    ) -> provision.Answer:
        self.calls.append((method, path, body, api_key))
        if path == "/_security/_authenticate":
            if api_key is None:
                return provision.Answer(200, {"username": "elastic"})
            owner = self.keys[api_key]
            return provision.Answer(200, {"username": "someone" if self.wrong_key_owner else owner})
        if path == "/_security/user/_has_privileges":
            return provision.Answer(200, {"cluster": {"manage_security": self.manage}})
        if path.startswith("/_security/role/"):
            self.roles[path.rsplit("/", 1)[1]] = body
            return provision.Answer(200, {"role": {"created": True}})
        if path == "/_security/api_key/grant":
            assert self.passwords[body["username"]] == body["password"]
            encoded = f"key-of-{body['username']}"
            self.keys[encoded] = body["username"]
            return provision.Answer(200, {"id": "x", "name": body["api_key"]["name"],
                                          "encoded": encoded})  # fmt: skip
        if path.endswith("/_password"):
            self.passwords[path.split("/")[3]] = body["password"]
            return provision.Answer(200, {})
        if path.startswith("/_security/user/"):
            user = path.rsplit("/", 1)[1]
            if method == "GET":
                return provision.Answer(200 if user in self.users else 404, {})
            if method == "POST":
                self.users.add(user)
                self.passwords[user] = body["password"]
            return provision.Answer(200, {"created": method == "POST"})
        raise AssertionError(path)


def _plan(tmp_path: Path, **kw: Any) -> provision.Plan:
    return provision.plan_for(example_site(), tmp_path / "creds", **kw)


def _run(plan: provision.Plan, siem: FakeSiem) -> tuple[provision.Outcome, list[str]]:
    said: list[str] = []
    out = provision.apply(plan, siem, say=said.append, now=lambda: NOW)
    return out, said


def test_the_plan_names_two_roles_in_the_space_and_seven_users(tmp_path: Path) -> None:
    site = example_site()
    plan = _plan(tmp_path)
    assert [m.user for m in plan.team] == [a.value for a in Author]
    assert [m.role for m in plan.team].count(provision.LEAD_ROLE) == 1
    lead = plan.roles[provision.LEAD_ROLE]
    assert lead["applications"][0]["resources"] == [f"space:{site.space}"]
    assert "write" in lead["indices"][0]["privileges"]
    assert "write" not in plan.roles[provision.COMMENTER_ROLE]["indices"][0]["privileges"]
    assert lead["indices"][0]["names"][0] == site.alerts_index_name
    text = "\n".join(provision.describe(plan))
    assert "nothing is sent without --apply" in text
    assert "argus-visualiser (ARGUS · Visualiser)" in text
    without = _plan(tmp_path, visualiser=False)
    assert Author.VISUALISER.value not in [m.user for m in without.team]
    with pytest.raises(provision.ProvisionError, match="1 to 3650"):
        _plan(tmp_path, expiration_days=0)


def test_a_fresh_siem_gets_roles_users_and_keys_written_private(tmp_path: Path) -> None:
    plan = _plan(tmp_path)
    siem = FakeSiem()
    out, said = _run(plan, siem)
    assert out.made == [a.value for a in Author]
    assert out.expires == date(2027, 11, 3)
    assert set(siem.roles) == {provision.LEAD_ROLE, provision.COMMENTER_ROLE}
    for mate in plan.team:
        path = plan.credentials / mate.key_file
        assert path.read_text() == f"key-of-{mate.user}"
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(plan.credentials.stat().st_mode) == 0o700
    for password in siem.passwords.values():
        assert all(password not in line for line in said)  # nobody sees a teammate's password
    keyed = [c for c in siem.calls if c[3] is not None]
    assert len(keyed) == 7  # each key checked as its own user


def test_a_rerun_keeps_everyone_and_makes_nothing(tmp_path: Path) -> None:
    plan = _plan(tmp_path)
    siem = FakeSiem()
    _run(plan, siem)
    out, _ = _run(plan, siem)
    assert out.made == out.rekeyed == []
    assert len(out.kept) == 7
    assert out.expires is None


def test_a_user_without_its_key_file_gets_a_new_password_and_key(tmp_path: Path) -> None:
    plan = _plan(tmp_path)
    siem = FakeSiem()
    _run(plan, siem)
    (plan.credentials / "case_team.intel_api_key").unlink()
    out, _ = _run(plan, siem)
    assert out.rekeyed == ["argus-intel"]
    assert any(c[1] == "/_security/user/argus-intel/_password" for c in siem.calls)


def test_a_login_without_manage_security_changes_nothing(tmp_path: Path) -> None:
    siem = FakeSiem(manage=False)
    with pytest.raises(provision.ProvisionError, match="manage_security"):
        _run(_plan(tmp_path), siem)
    assert siem.roles == {}
    assert siem.users == set()


def test_a_key_that_is_someone_elses_stops_the_run(tmp_path: Path) -> None:
    siem = FakeSiem()
    siem.wrong_key_owner = True
    with pytest.raises(provision.ProvisionError, match="does not authenticate as argus-lead"):
        _run(_plan(tmp_path), siem)


def test_an_http_error_names_the_step(tmp_path: Path) -> None:
    class Refusing(FakeSiem):
        def call(self, method: str, path: str, body: Any = None, *, api_key: str | None = None
                 ) -> provision.Answer:  # fmt: skip
            if path.startswith("/_security/role/"):
                return provision.Answer(403, {})
            return super().call(method, path, body, api_key=api_key)

    with pytest.raises(provision.ProvisionError, match="role argus_case_lead: HTTP 403"):
        _run(_plan(tmp_path), Refusing())

"""P4-D2: the prerequisites with their one-line fixes, and the read keys' roles (D-297)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from argus.install import prereq, roles
from argus.site import SiteSettings
from tests.conftest import example_site
from tests.unit.install.fakes import DOCKER_OK, Commands

pytestmark = pytest.mark.unit
GIB = prereq.GIB


def _checkout(tmp_path: Path) -> Path:
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "argus.yaml").write_text("")
    (tmp_path / "docker-compose.yml").write_text("")
    return tmp_path


def _check(root: Path, commands: Commands, *, free: bool = True, disk: int = 50 * GIB,
           which: str | None = "/usr/bin/docker", uv: str | None = "/usr/bin/uv",
           compose: bool = True) -> list[prereq.Finding]:  # fmt: skip
    return prereq.check(
        root, compose=compose, port=55432, uv=uv, which=lambda _: which, run=commands,
        free=lambda _h, _p: free, disk_free=lambda _p: disk,
    )  # fmt: skip


def _missing(found: list[prereq.Finding]) -> list[str]:
    return [f.text for f in found if not f.ok]


def test_a_ready_machine_has_everything(tmp_path: Path) -> None:
    found = _check(_checkout(tmp_path), Commands(dict(DOCKER_OK)))
    assert _missing(found) == []
    assert "docker compose 2.29.1" in [f.text for f in found]
    assert "port 55432 is free for PostgreSQL" in [f.text for f in found]


@pytest.mark.parametrize(
    ("table", "which", "fix"),
    [
        ({}, None, "docker is not installed: https://docs.docker.com/engine/install/"),
        ({("docker", "compose"): (1, "")}, "/usr/bin/docker", "install the compose plugin"),
        ({("docker", "compose"): (0, "1.29.2\n")}, "/usr/bin/docker", "compose v2 is missing"),
        ({**DOCKER_OK, ("docker", "info"): (1, "")}, "/usr/bin/docker", "cannot be reached"),
    ],
)
def test_each_missing_docker_piece_says_how_to_fix_it(
    tmp_path: Path, table: dict[tuple[str, ...], tuple[int, str]], which: str | None, fix: str
) -> None:
    missing = _missing(_check(_checkout(tmp_path), Commands(table), which=which))
    assert len(missing) == 1
    assert fix in missing[0]


def test_a_busy_port_is_fine_only_when_argus_db_holds_it(tmp_path: Path) -> None:
    root = _checkout(tmp_path)
    ours = Commands({
        **DOCKER_OK,
        ("docker", "ps", "-a"): (0, f"argus-db|{root}\n"),
        ("docker", "ps"): (0, "127.0.0.1:55432->5432/tcp\n"),
    })  # fmt: skip
    assert _missing(_check(root, ours, free=False)) == []
    theirs = Commands({**DOCKER_OK, ("docker", "ps"): (0, "")})
    assert "set ARGUS_DATABASE__PORT in .env" in _missing(_check(root, theirs, free=False))[0]


def test_another_checkouts_database_container_is_never_taken_over(tmp_path: Path) -> None:
    """The same container name or the same compose project's db, made in another checkout
    (production's, say): compose would recreate it with this checkout's settings."""
    root = _checkout(tmp_path)
    for listed in ("argus-db|/srv/argus\n", "argus-db|\n"):
        other = Commands({**DOCKER_OK, ("docker", "ps", "-a"): (0, listed)})
        missing = _missing(_check(root, other))
        assert len(missing) == 1
        assert "argus-db belongs to another ARGUS checkout" in missing[0]
        assert "COMPOSE_PROJECT_NAME, COMPOSE_DB_CONTAINER and ARGUS_DATABASE__PORT" in missing[0]
    asked = [a for a in other.ran if a[:3] == ["docker", "ps", "-a"]]
    assert asked[0][3:5] == ["--filter", "name=^argus-db$"]
    own = Commands({**DOCKER_OK, ("docker", "ps", "-a"): (0, f"argus-db|{root}/\n")})
    assert _missing(_check(root, own)) == []


def test_the_container_and_project_names_follow_compose() -> None:
    assert prereq.compose_names({}, {}) == ("argus-db", "argus")
    env = {"COMPOSE_DB_CONTAINER": "argus2-db", "COMPOSE_PROJECT_NAME": "argus2"}
    assert prereq.compose_names(env, {}) == ("argus2-db", "argus2")
    assert prereq.compose_names(env, {"COMPOSE_PROJECT_NAME": "x"}) == ("argus2-db", "x")


def test_disk_space_uv_and_the_checkout(tmp_path: Path) -> None:
    root = _checkout(tmp_path)
    assert "at least 2 GiB" in _missing(_check(root, Commands(dict(DOCKER_OK)), disk=GIB))[0]
    low = _check(root, Commands(dict(DOCKER_OK)), disk=5 * GIB)
    assert [f.text for f in low if f.warn] == [f"5.0 GiB free in {root}: 10 GiB or more is better"]
    assert "uv is not on PATH" in _missing(_check(root, Commands(dict(DOCKER_OK)), uv=None))[0]
    elsewhere = _check(tmp_path / "nowhere", Commands(), compose=False)
    assert sorted(_missing(elsewhere)) == [
        "config/argus.yaml is not here: run argus init in the checkout",
        "docker-compose.yml is not here: run argus init in the checkout",
    ]


def test_no_docker_is_asked_without_compose(tmp_path: Path) -> None:
    commands = Commands()
    assert _missing(_check(_checkout(tmp_path), commands, which=None, compose=False)) == []
    assert commands.ran == []


def test_the_port_probe_sees_a_listener() -> None:
    import socket

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        sock.listen()
        assert not prereq.port_free("127.0.0.1", sock.getsockname()[1])


# --------------------------------------------------------------------------- the roles


def test_the_role_reads_what_the_gateway_reads_for_the_site() -> None:
    site = example_site()
    names = roles.es_names(site)
    assert names == [
        ".alerts-security.alerts-acme-soc", ".internal.alerts-security.alerts-acme-soc-*",
        "acme-logs-*", "abuse-ioc", "acme-threat-intel",
    ]  # fmt: skip
    role = roles.es_role(names)
    assert role["cluster"] == ["monitor"]
    assert role["indices"][0]["privileges"] == ["read", "view_index_metadata"]
    assert role["indices"][0]["allow_restricted_indices"] is False


def test_without_log_patterns_the_families_are_named() -> None:
    site = SiteSettings.model_validate(
        {"space": "soc", "families": [{"role": "dns", "pattern": "dns-*"},
                                      {"role": "web", "pattern": "logs-nginx.access-default"}]}
    )  # fmt: skip
    assert roles.es_names(site)[2:] == ["dns-*", "logs-nginx.access-default"]


def test_the_starting_role_reads_every_spaces_alerts_and_the_given_logs() -> None:
    assert roles.starting_names([]) == [*roles.STARTING_ALERTS, "logs-*"]
    assert roles.starting_names(["corp-*", "corp-*"]) == [*roles.STARTING_ALERTS, "corp-*"]


def test_the_requests_are_dev_tools_requests_that_make_a_limited_key() -> None:
    site = example_site()
    text = roles.es_request(roles.es_names(site))
    method, _, body = text.partition("\n")
    assert method == "POST /_security/api_key"
    parsed = json.loads(body)
    assert parsed["name"] == "argus-reader"
    assert parsed["expiration"] == "90d"
    assert parsed["role_descriptors"] == {"argus_reader": roles.es_role(roles.es_names(site))}
    kibana = json.loads(roles.kibana_request(site).partition("\n")[2])
    application = kibana["role_descriptors"]["argus_kibana_reader"]["applications"][0]
    assert application == {
        "application": "kibana-.kibana",
        "privileges": ["feature_securitySolutionCasesV3.read"],
        "resources": ["space:acme-soc"],
    }
    every = json.loads(roles.kibana_request(site, every_space=True).partition("\n")[2])
    assert every["role_descriptors"]["argus_kibana_reader"]["applications"][0]["resources"] == ["*"]
    for request in (text, roles.kibana_request(site)):
        for word in ("manage", "write", "delete", "all"):
            assert f'"{word}"' not in request  # nothing but reads


def test_nothing_proposed_names_the_quiet_hours_when_they_are_the_cause() -> None:
    from datetime import UTC, datetime

    from argus.discover.run import nothing_proposed

    plain = nothing_proposed(datetime(2026, 11, 3, 12, 0, tzinfo=UTC))
    assert plain == "the list of indices could not be read: nothing is proposed"
    quiet = nothing_proposed(datetime(2026, 11, 3, 0, 20, tzinfo=UTC))
    assert "quiet hours, 00:00-01:30 UTC" in quiet
    assert "run this again after 01:30 UTC" in quiet

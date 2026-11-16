"""Q-A2, D-295: the systemd units in the repository are templates each installation renders. The
gate: installed units are byte-identical to the rendering (doctor checks it), new units stay
disabled, and the installer never enables, starts or restarts anything. These tests read fixture
folders (and the repository); none touches the real user unit directory or systemd. A site's own
rendering is pinned in its private tests."""

from __future__ import annotations

import re
import shutil
import stat
import subprocess
from pathlib import Path

import pytest
from typer.main import get_command

from argus.cli import app
from argus.ops import units
from argus.ops.units import MANIFEST, UNITS_DIR, Role, UnitState
from tests.conftest import REPO_ROOT
from tests.unit.ops.unit_files import render_into

pytestmark = pytest.mark.unit

INSTALL = REPO_ROOT / "deploy" / "systemd" / "install.sh"
# A made-up installation: another user's checkout and uv, a web on the campus network.
PARAMS = units.UnitParams(Path("/home/alice/argus"), "/home/alice/.local/bin/uv", {
    "WEB_HOST": "0.0.0.0", "WEB_TLS_CERT": "data/tls/web.crt", "WEB_TLS_KEY": "data/tls/web.key",  # noqa: S104 - a unit's text
    "WEB_ALLOWED_HOSTS": "argus.example.org", "WEB_ALLOWED_NETWORKS": "192.0.2.0/24",
})  # fmt: skip
RENDERED = units.rendered_units(PARAMS)


def test_the_manifest_lists_exactly_the_files_in_deploy_systemd() -> None:
    files = {p.name for p in UNITS_DIR.iterdir() if p.suffix in (".service", ".timer")}
    assert files == set(MANIFEST)
    # whole units only: doctor fails on every drop-in, and install.sh copies none (QA2-R3)
    assert not [p for p in UNITS_DIR.iterdir() if p.is_dir()]


def test_every_timer_has_its_service_and_triggered_services_have_their_timer() -> None:
    for name, (role, _) in MANIFEST.items():
        if name.endswith(".timer"):
            assert name.removesuffix(".timer") + ".service" in MANIFEST
        if role is Role.TRIGGERED:
            assert name.removesuffix(".service") + ".timer" in MANIFEST
            assert "[Install]" not in (UNITS_DIR / name).read_text()


def _commands() -> set[tuple[str, ...]]:
    """Every `argus` command path the CLI has, as word tuples."""
    found: set[tuple[str, ...]] = set()

    def walk(command: object, path: tuple[str, ...]) -> None:
        found.add(path)
        for name, sub in getattr(command, "commands", {}).items():
            walk(sub, (*path, name))

    walk(get_command(app), ())
    return found


def _exec_start(unit: Path) -> list[str]:
    for line in RENDERED[unit.name].splitlines():
        if line.startswith("ExecStart="):
            return line.removeprefix("ExecStart=").split()
    raise AssertionError(f"{unit.name} has no ExecStart")


@pytest.mark.parametrize("name", sorted(n for n in MANIFEST if n.endswith(".service")))
def test_each_service_runs_an_argus_command_that_exists_or_waits_for_it(name: str) -> None:
    """A running or triggered unit's command exists; an OFF unit's planned command may not
    yet, and then its ExecCondition skips a start instead of failing it again and again."""
    words = _exec_start(UNITS_DIR / name)
    start = words.index("argus") + 1
    command = tuple(w for w in words[start:] if not w.startswith("-"))
    known = _commands()
    path = next((command[:n] for n in range(len(command), 0, -1) if command[:n] in known), None)
    role = MANIFEST[name][0]
    if role is Role.OFF:
        text = (UNITS_DIR / name).read_text()
        assert "ExecCondition=" in text
        assert "--help" in text
    else:
        assert path is not None, (name, command)
        assert path, (name, command)


def test_the_new_units_are_disabled_and_scheduled_at_quiet_hours() -> None:
    assert {n for n, (r, _) in MANIFEST.items() if r in (Role.OFF, Role.SOON)} == {
        "argus-writer.service", "argus-backup.timer",
        "argus-backup-drill.timer", "argus-purge.timer", "argus-notices.timer",
        "argus-report-daily.timer", "argus-report-weekly.timer",
        "argus-soak-phase3.timer"}  # fmt: skip
    purge_timer = (UNITS_DIR / "argus-purge.timer").read_text()
    # 04:30 IST: after the nightly dump (21:30 UTC) and Sunday's drill (22:00 UTC)
    assert "OnCalendar=*-*-* 23:00:00 UTC" in purge_timer
    assert "Persistent=true" in purge_timer
    purge = (UNITS_DIR / "argus-purge.service").read_text()
    assert "argus purge run --apply --scheduled" in purge  # deletes only once approved
    backup_timer = (UNITS_DIR / "argus-backup.timer").read_text()
    drill_timer = (UNITS_DIR / "argus-backup-drill.timer").read_text()
    assert "OnCalendar=*-*-* 21:30:00 UTC" in backup_timer  # 03:00 IST, nightly
    assert "OnCalendar=Sun *-*-* 22:00:00 UTC" in drill_timer  # Monday 03:30 IST, weekly
    for timer in (backup_timer, drill_timer):
        assert "Persistent=true" in timer  # a night the machine was off runs at boot
    drill = (UNITS_DIR / "argus-backup-drill.service").read_text()
    assert "scripts/heavy.sh --mem 2G" in drill  # the heavy-task lock
    writer = (UNITS_DIR / "argus-writer.service").read_text()
    assert "LoadCredential" in writer  # the comment pointing at Q-A5's custody


@pytest.mark.skipif(shutil.which("systemd-analyze") is None, reason="needs systemd-analyze")
def test_systemd_reads_every_unit_and_timer_without_a_complaint(tmp_path: Path) -> None:
    files = [str(p) for p in render_into(tmp_path / "units")]
    done = subprocess.run(  # noqa: S603 - fixed program, repository files
        ["systemd-analyze", "--user", "verify", *files],  # noqa: S607
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert (done.returncode, done.stderr.strip()) == (0, "")
    for spec in ("*-*-* 21:30:00 UTC", "Sun *-*-* 22:00:00 UTC"):
        calendar = subprocess.run(  # noqa: S603
            ["systemd-analyze", "calendar", spec],  # noqa: S607
            capture_output=True, text=True, timeout=30, check=False,
        )  # fmt: skip
        assert calendar.returncode == 0, calendar.stderr


# --------------------------------------------------------------------------- states


def _state(**kw: object) -> UnitState:
    base: dict[str, object] = {
        "name": "argus-x.service", "role": Role.RUN, "why": "x", "in_repository": True,
        "installed": True, "identical": True, "enabled": True,
    }  # fmt: skip
    base.update(kw)
    return UnitState(**base)  # type: ignore[arg-type]


DIFFERS = "the installed copy differs from its rendered template (argus units install)"
NOT_INSTALLED = "not installed: run argus units install --apply"


@pytest.mark.parametrize(
    ("kw", "expected"),
    [
        ({}, None),
        ({"in_repository": False}, ("missing from deploy/systemd", False)),
        ({"identical": False}, (DIFFERS, False)),
        ({"installed": False, "identical": False}, (NOT_INSTALLED, False)),
        ({"enabled": False}, ("installed but not enabled", False)),
        ({"role": Role.TRIGGERED, "enabled": False}, None),
        ({"role": Role.TRIGGERED, "installed": False, "identical": False, "enabled": False},
         (NOT_INSTALLED, True)),
        ({"role": Role.SOON, "enabled": False}, ("not enabled yet (x): a production step", True)),
        ({"role": Role.SOON}, None),
        ({"role": Role.SOON, "installed": False, "identical": False, "enabled": False},
         ("not enabled yet (x): a production step", True)),
        ({"role": Role.OFF, "enabled": False}, None),
        ({"role": Role.OFF, "installed": False, "identical": False, "enabled": False}, None),
        ({"role": Role.OFF}, ("enabled before its production step (x)", False)),
        ({"role": Role.CHOICE, "enabled": False}, None),
        ({"role": Role.CHOICE, "installed": False, "identical": False, "enabled": False}, None),
        ({"role": Role.CHOICE}, ("enabled, but units.run does not list it (x): add it there"
                                 " (config/local.yaml) so doctor watches it", True)),
        ({"role": Role.CHOICE, "identical": False}, (DIFFERS, False)),
    ],
)  # fmt: skip
def test_what_doctor_says_about_a_unit(kw: dict[str, object], expected: object) -> None:
    assert units.problems(_state(**kw)) == expected


def test_a_triggered_service_of_a_running_timer_must_be_installed() -> None:
    state = _state(
        name="argus-soak-sample.service", role=Role.TRIGGERED, installed=False, identical=False,
        enabled=False, timer_runs=True,
    )  # fmt: skip
    assert units.problems(state) == (NOT_INSTALLED, False)


def test_the_roles_follow_what_the_installation_runs() -> None:
    default = units.roles_for(None)
    assert {n for n, (r, _) in default.items() if r is Role.RUN} == set(units.CORE)
    assert units.CORE == ("argus-collector.service", "argus-worker.service",
                          "argus-web.service", "argus-assess.service",
                          "argus-admin.service")  # fmt: skip
    assert default["argus-case-team.timer"][0] is Role.CHOICE
    assert default["argus-purge.timer"][0] is Role.OFF
    nothing = units.roles_for(())
    assert not [n for n, (r, _) in nothing.items() if r is Role.RUN]
    assert nothing["argus-web.service"][0] is Role.CHOICE
    more = units.roles_for(("argus-purge.timer", "argus-case-team.timer"))
    assert more["argus-purge.timer"][0] is Role.RUN  # a production step lists it
    assert more["argus-collector.service"][0] is Role.CHOICE
    states, _, _ = units.unit_states(UNITS_DIR, Path("/nowhere"), params=PARAMS,
                                     run=("argus-case-team.timer",))  # fmt: skip
    service = next(s for s in states if s.name == "argus-case-team.service")
    assert (service.role, service.timer_runs) == (Role.TRIGGERED, True)


def _installed(tmp_path: Path, *names: str) -> Path:
    folder = tmp_path / "systemd" / "user"
    folder.mkdir(parents=True)
    for name in names:
        (folder / name).write_text(RENDERED[name])
    return folder


def _enable(folder: Path, name: str, target: str = "default.target") -> None:
    wants = folder / f"{target}.wants"
    wants.mkdir(exist_ok=True)
    (wants / name).symlink_to(folder / name)


def test_unit_states_compare_the_rendering_and_read_the_wants_links(tmp_path: Path) -> None:
    folder = _installed(tmp_path, "argus-web.service", "argus-collector.service",
                        "argus-writer.service")  # fmt: skip
    _enable(folder, "argus-web.service")
    _enable(folder, "argus-writer.service")
    (folder / "argus-collector.service").write_text(
        RENDERED["argus-collector.service"] + "\n"  # one byte more
    )
    (folder / "argus-stray.service").write_text("[Service]\nExecStart=/bin/true\n")
    states, unlisted, stray = units.unit_states(UNITS_DIR, folder, params=PARAMS)
    by_name = {s.name: s for s in states}
    assert (by_name["argus-web.service"].identical, by_name["argus-web.service"].enabled) == (
        True, True)  # fmt: skip
    assert (by_name["argus-collector.service"].installed,
            by_name["argus-collector.service"].identical) == (True, False)  # fmt: skip
    assert by_name["argus-worker.service"].installed is False
    assert units.problems(by_name["argus-writer.service"]) == (
        "enabled before its production step (Kibana writes (Q-D4, Q-D5): each class's canary)",
        False,
    )
    assert (unlisted, stray) == ([], ["argus-stray.service"])
    other = units.UnitParams(Path("/home/bob/argus"), PARAMS.uv, PARAMS.values)
    states, _, _ = units.unit_states(UNITS_DIR, folder, params=other)
    assert not next(s for s in states if s.name == "argus-web.service").identical
    assert units.installed_root(folder) == Path("/home/alice/argus")


def test_a_missing_unit_directory_has_nothing_enabled(tmp_path: Path) -> None:
    assert units.enabled_units(tmp_path / "nowhere") == set()
    states, _, stray = units.unit_states(UNITS_DIR, tmp_path / "nowhere", params=PARAMS)
    assert not any(s.installed for s in states)
    assert stray == []
    assert units.installed_root(tmp_path / "nowhere") is None


def test_the_user_unit_directory_follows_xdg(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    assert units.user_unit_dir() == tmp_path / "systemd" / "user"
    monkeypatch.delenv("XDG_CONFIG_HOME")
    assert units.user_unit_dir() == Path.home() / ".config" / "systemd" / "user"


def test_a_units_environment_and_working_directory(tmp_path: Path) -> None:
    web = tmp_path / "argus-web.service"
    web.write_text(RENDERED["argus-web.service"])
    env = units.unit_environment(web)
    assert env["ARGUS_WEB__TLS_CERT"] == "data/tls/web.crt"
    assert env["ARGUS_WEB__ALLOWED_NETWORKS"] == "192.0.2.0/24"
    assert units.working_directory(web) == Path("/home/alice/argus")
    unit = tmp_path / "argus-q.service"
    unit.write_text(
        "[Unit]\nEnvironment=NOT_THIS=1\n[Service]\n# Environment=COMMENTED=1\n"
        'Environment="A=one two" B=3 \'C=x y\'\nEnvironment=BROKEN="unclosed\n'
        "Environment=NOEQUALS\nEnvironmentFile=/x\n"
    )
    assert units.unit_environment(unit) == {"A": "one two", "B": "3", "C": "x y"}
    assert units.working_directory(unit) is None


# --------------------------------------------------------------------------- rendering


def test_a_made_up_installation_gets_its_own_paths_and_no_one_elses() -> None:
    for name, text in RENDERED.items():
        assert units.PLACEHOLDER.search(text) is None, name  # every placeholder filled
        assert "/home/" not in text.replace("/home/alice/", ""), name
        if name.endswith(".service"):
            assert "WorkingDirectory=/home/alice/argus\n" in text, name
            assert "/home/alice/.local/bin/uv run argus " in text, name
    web = RENDERED["argus-web.service"]
    assert "Environment=ARGUS_WEB__ALLOWED_HOSTS=argus.example.org\n" in web
    assert "ARGUS_WEB__PUBLIC_URL" not in web  # not given: the line is left out ...
    assert "AR8's canary" not in web  # ... and its group's comment with it
    assert "# D-104" in web  # a group with a line given keeps its comment
    drill = RENDERED["argus-backup-drill.service"]
    assert "ExecStart=/home/alice/argus/scripts/heavy.sh --mem 2G" in drill


def test_a_loopback_web_has_no_network_lines() -> None:
    params = units.UnitParams(
        Path("/srv/argus"), "/usr/bin/uv", {"WEB_PUBLIC_URL": "http://127.0.0.1:8765"}
    )
    web = units.rendered_units(params)["argus-web.service"]
    assert [line for line in web.splitlines() if line.startswith("Environment=")] == [
        "Environment=ARGUS_WEB__PUBLIC_URL=http://127.0.0.1:8765"
    ]
    assert "D-104" not in web
    bare = units.UnitParams(Path("/srv/argus"), "/usr/bin/uv")
    assert "Environment=" not in units.rendered_units(bare)["argus-web.service"]


def test_render_drops_only_the_comments_of_a_group_that_went() -> None:
    template = (
        "[Service]\n# kept: above a plain line\nA=1\n# the group's comment\nB=@WEB_X@\n"
        "C=@WEB_Y@\n# second group\nD=@WEB_Z@\nE=@ROOT@\n# trailing comment\n"
    )
    params = units.UnitParams(Path("/r"), "/uv", {"WEB_Y": "y"})
    assert units.render(template, params) == (
        "[Service]\n# kept: above a plain line\nA=1\n# the group's comment\nC=y\nE=/r\n"
        "# trailing comment\n"
    )
    with pytest.raises(units.UnitsError, match=r"unknown placeholder @NOPE@"):
        units.render("A=@NOPE@ @ROOT@\n", units.UnitParams(Path("/r"), "/uv"))


def test_the_settings_give_the_parameters(monkeypatch: pytest.MonkeyPatch) -> None:
    from argus.config.settings import UnitsSettings

    given = UnitsSettings.model_validate(
        {"root": "/srv/argus", "uv": "/usr/bin/uv", "web": {"public_url": "http://127.0.0.1:8765"}}
    )
    params = units.params_of(given)
    assert (params.root, params.uv) == (Path("/srv/argus"), "/usr/bin/uv")
    assert params.values == {"WEB_PUBLIC_URL": "http://127.0.0.1:8765"}
    monkeypatch.setenv("UV", "/nonexistent/uv")
    monkeypatch.setattr(units.shutil, "which", lambda _name: None)
    with pytest.raises(units.UnitsError, match=r"set units\.uv"):
        units.params_of(UnitsSettings())
    assert units.params_of(UnitsSettings(), uv="uv").root == units.REPO


@pytest.mark.parametrize(
    ("given", "error"),
    [
        ({"run": ["argus-nothing.service"]}, "is not one of ARGUS's units"),
        ({"run": ["argus-backup.service"]}, "started by its timer"),
        ({"run": ["argus-web.service", "argus-web.service"]}, "listed twice"),
        ({"root": "relative/path"}, "absolute path"),
        ({"web": {"host": "0.0.0.0"}}, "listens on the loopback only"),  # noqa: S104 - a unit's text
        ({"web": {"tls_cert": "a.crt"}}, "tls_cert and tls_key go together"),
        ({"web": {"public_url": "https://elsewhere.example"}}, "public_url's host"),
        ({"web": {"allowed_hosts": ["has space"]}}, "allowed_hosts"),
        ({"web": {"credentials": "a$b"}}, "pattern"),
    ],
)
def test_the_units_settings_refuse_what_cannot_run(given: dict[str, object], error: str) -> None:
    from pydantic import ValidationError

    from argus.config.settings import UnitsSettings

    with pytest.raises(ValidationError, match=re.escape(error)):
        UnitsSettings.model_validate(given)


# --------------------------------------------------------------------------- the installer

CONFIG = (
    "units:\n  root: /home/alice/argus\n  uv: /home/alice/.local/bin/uv\n  web:\n"
    "    host: 0.0.0.0\n    tls_cert: data/tls/web.crt\n    tls_key: data/tls/web.key\n"
    "    allowed_hosts: [argus.example.org]\n    allowed_networks: [192.0.2.0/24]\n"
)


def _install(tmp_path: Path, *args: str) -> tuple[int, str]:
    from typer.testing import CliRunner

    config = tmp_path / "config" / "argus.yaml"
    config.parent.mkdir(exist_ok=True)
    config.write_text(CONFIG)
    done = CliRunner().invoke(app, ["units", "install", "-c", str(config), *args])
    return done.exit_code, done.output


def test_the_installer_is_a_dry_run_by_default(tmp_path: Path) -> None:
    dest = tmp_path / "dest"
    code, out = _install(tmp_path, "--dest", str(dest))
    assert code == 0, out
    assert f"0 changed, {len(MANIFEST)} new, 0 unchanged" in out
    assert "dry run: nothing written" in out
    assert not dest.exists()


def test_the_installer_writes_the_rendering_and_enables_nothing(tmp_path: Path) -> None:
    dest = _installed(tmp_path, "argus-web.service", "argus-worker.service")
    (dest / "argus-worker.service").write_text("[Service]\nExecStart=/bin/old\n")
    (dest / "argus-gone.service").write_text("[Service]\n")
    calls: list[list[str]] = []
    code, out = _install(tmp_path, "--apply", "--dest", str(dest))
    assert code == 0, out
    assert "== changed: argus-worker.service" in out
    assert "+ExecStart=/home/alice/.local/bin/uv run argus worker run" in out  # the diff
    assert "installed but not in the repository (left alone): argus-gone.service" in out
    assert "next: systemctl --user daemon-reload" in out
    assert "systemctl --user restart argus-worker.service" in out
    for name in MANIFEST:
        assert (dest / name).read_text() == RENDERED[name], name
        if name != "argus-web.service":  # identical already: left as it was
            assert stat.S_IMODE((dest / name).stat().st_mode) == 0o644
    assert (dest / "argus-gone.service").exists()
    assert not list(dest.glob("*.wants"))  # nothing enabled
    assert not list(dest.glob(".*"))  # no temporary file left
    assert calls == []
    code, again = _install(tmp_path, "--apply", "--dest", str(dest))
    assert f"0 changed, 0 new, {len(MANIFEST)} unchanged" in again


def test_the_installers_diff_never_shows_a_secret(tmp_path: Path) -> None:
    dest = _installed(tmp_path, "argus-web.service")
    body = (dest / "argus-web.service").read_text()
    (dest / "argus-web.service").write_text(
        body.replace(
            "[Service]\n",
            "[Service]\nEnvironment=ARGUS_SIEM__WRITER_API_KEY=Synthetic-Leak-1 X_TOKEN=t0k\n"
            'Environment="ARGUS_DATABASE__PASSWORD=Synthetic-Leak-2"\n',
        )
    )
    code, out = _install(tmp_path, "--dest", str(dest))
    assert code == 0, out
    assert "== changed: argus-web.service" in out
    assert "ARGUS_SIEM__WRITER_API_KEY=***" in out
    for leak in ("Synthetic-Leak-1", "Synthetic-Leak-2", "t0k"):
        assert leak not in out


def test_the_installers_dry_run_names_every_drop_in(tmp_path: Path) -> None:
    """QA2-R3: a drop-in changes a unit whose file is unchanged; the dry run says so."""
    dest = _installed(tmp_path, *MANIFEST)
    for folder, name in (("argus-web.service.d", "override.conf"), ("service.d", "all.conf"),
                         ("argus-.timer.d", "t.conf")):  # fmt: skip
        (dest / folder).mkdir()
        (dest / folder / name).write_text("[Service]\nExecStart=\n")
    (dest / "other.service.d").mkdir()
    (dest / "other.service.d" / "x.conf").write_text("[Service]\n")  # not ARGUS's
    code, out = _install(tmp_path, "--dest", str(dest))
    assert code == 0, out
    shown = [line for line in out.splitlines() if line.startswith("== drop-in")]
    found = [("argus-.timer.d", "t.conf"), ("argus-web.service.d", "override.conf"),
             ("service.d", "all.conf")]  # fmt: skip
    assert sorted(shown) == sorted(
        f"== drop-in (changes units; not from the repository): {dest / folder / name}"
        for folder, name in found
    )


def test_the_installer_reloads_only_when_asked_and_never_restarts(tmp_path: Path) -> None:
    from argus.ops import units_cli

    calls: list[list[str]] = []

    def run(argv: list[str], **_kw: object) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, "", "")

    plan = units.plan_install(PARAMS, tmp_path / "dest")
    assert units_cli.report(plan, apply=True, reload=True, run=run) == 0
    assert calls == [["systemctl", "--user", "daemon-reload"]]
    code, out = _install(tmp_path, "--reload", "--dest", str(tmp_path / "x"))
    assert code == 2
    assert "--reload goes with --apply" in out


def test_the_installer_refuses_unknown_options_and_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert _install(tmp_path, "--enable")[0] == 2
    assert _install(tmp_path, "--dest")[0] == 2
    monkeypatch.setattr(units.os, "geteuid", lambda: 0)
    plan = units.plan_install(PARAMS, tmp_path / "dest")
    with pytest.raises(units.UnitsError, match="not root"):
        units.apply_install(plan)


def test_the_installer_never_names_enable_start_or_stop() -> None:
    source = (REPO_ROOT / "src" / "argus" / "ops" / "units_cli.py").read_text()
    body = "\n".join(line for line in source.splitlines() if not line.lstrip().startswith("#"))
    for verb in ('"enable"', '"start"', '"stop"', '"disable"', '"--now"', '"restart"]'):
        assert verb not in body
    assert '"daemon-reload"' in body


def test_install_sh_runs_argus_units_install_from_its_checkout() -> None:
    script = INSTALL.read_text()
    assert 'root=$(cd "$(dirname "$0")/../.." && pwd)' in script
    assert script.rstrip().endswith('exec uv run --quiet argus units install "$@"')


def test_argus_units_show_prints_one_rendered_unit(tmp_path: Path) -> None:
    from typer.testing import CliRunner

    config = tmp_path / "config" / "argus.yaml"
    config.parent.mkdir()
    config.write_text(CONFIG)
    done = CliRunner().invoke(app, ["units", "show", "argus-web.service", "-c", str(config)])
    assert done.exit_code == 0, done.output
    assert done.output == RENDERED["argus-web.service"]
    missing = CliRunner().invoke(app, ["units", "show", "argus-nope.service", "-c", str(config)])
    assert missing.exit_code == 2

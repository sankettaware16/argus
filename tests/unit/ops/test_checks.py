"""Q-A2: ``argus doctor``'s platform checks on fixtures (the gate: every doctor check on
fixtures). Each check is called with explicit paths and clocks; nothing here reads the real
unit directory, backups, .env or /proc."""

from __future__ import annotations

import asyncio
import contextlib
import json
import re
import shutil
import ssl
from collections.abc import AsyncIterator
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import SecretStr

from argus.config.settings import Settings, SiemSettings, WebSettings
from argus.doctor import CheckResult
from argus.ops import backup, certs, checks, frontend, units
from argus.ops.units import UNITS_DIR
from tests.conftest import REPO_ROOT, private_text
from tests.unit.ops.test_certs import make_cert

pytestmark = pytest.mark.unit

NOW = datetime(2026, 10, 23, 12, 0, tzinfo=UTC)


@pytest.fixture(scope="module")
def pem(tmp_path_factory: pytest.TempPathFactory) -> Path:
    if shutil.which("openssl") is None:
        pytest.skip("needs openssl")
    folder = tmp_path_factory.mktemp("pem")
    make_cert(folder, "web", "argus-web")
    make_cert(folder, "other", "argus-other")
    return folder


def labels(results: list[CheckResult]) -> list[tuple[str, str]]:
    return [(r.name, r.label) for r in results]


# --------------------------------------------------------------------------- certificates


def test_a_certificate_is_fine_warned_or_failed_by_its_expiry(pem: Path) -> None:
    info = certs.read_cert(pem / "web.crt")
    fine = checks.certificate_result("c", pem / "web.crt", info.not_after - timedelta(days=31), "r")
    assert (fine.label, fine.detail) == (
        "PASS",
        f"argus-web, valid until {info.not_after:%Y-%m-%d} (31 days)",
    )
    soon = checks.certificate_result(
        "c", pem / "web.crt", info.not_after - timedelta(days=3), "renew"
    )
    assert (soon.label, soon.detail) == (
        "WARN", f"argus-web expires {info.not_after:%Y-%m-%d} (in 3 days): renew")  # fmt: skip
    gone = checks.certificate_result("c", pem / "web.crt", info.not_after, "renew")
    assert (gone.label, gone.detail) == (
        "FAIL", f"argus-web expired on {info.not_after:%Y-%m-%d}: renew")  # fmt: skip
    missing = checks.certificate_result("c", pem / "none.crt", NOW, "r")
    assert (missing.label, missing.detail.endswith("does not exist")) == ("FAIL", True)


def _fake_repo(tmp_path: Path, working_directory: Path, cert: str) -> Path:
    repo = tmp_path / "repo"
    unit = repo / "deploy" / "systemd" / "argus-web.service"
    unit.parent.mkdir(parents=True)
    unit.write_text(
        f"[Service]\nWorkingDirectory={working_directory}\n"
        f"Environment=ARGUS_WEB__TLS_CERT={cert}\nExecStart=/bin/true\n"
    )
    return repo


def test_the_web_certificate_comes_from_settings_or_from_the_web_unit_of_this_checkout(
    tmp_path: Path,
) -> None:
    configured = Settings(web=WebSettings(tls_cert=Path("/x/web.crt"), tls_key=Path("/x/web.key")))
    assert checks.web_certificate(configured, tmp_path) == (
        Path("/x/web.crt"), "web.tls_cert", 8765)  # fmt: skip
    repo = _fake_repo(tmp_path, tmp_path / "repo", "data/tls/argus.crt")
    assert checks.web_certificate(Settings(), repo) == (
        tmp_path / "repo" / "data/tls/argus.crt", "argus-web.service", 8765)  # fmt: skip
    absolute = _fake_repo(tmp_path / "abs", tmp_path / "abs" / "repo", "/etc/argus/web.crt")
    assert checks.web_certificate(Settings(), absolute)[0] == Path("/etc/argus/web.crt")
    unit = absolute / "deploy" / "systemd" / "argus-web.service"
    unit.write_text(unit.read_text() + "Environment=ARGUS_WEB__PORT=9443\n")
    assert checks.web_certificate(Settings(), absolute)[2] == 9443
    # another checkout (a stream's worktree): the production web is not its business
    elsewhere = _fake_repo(tmp_path / "w", Path("/home/dev/code/argus"), "data/tls/argus.crt")
    assert checks.web_certificate(Settings(), elsewhere) == (None, "", 8765)
    assert checks.web_certificate(Settings(), tmp_path / "empty") == (None, "", 8765)


def _closed_port() -> int:
    import socket

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


async def test_the_web_certificate_alarm(pem: Path, tmp_path: Path) -> None:
    info = certs.read_cert(pem / "web.crt")
    now = info.not_after - timedelta(days=100)
    tls = {"tls_cert": pem / "web.crt", "tls_key": pem / "web.key", "port": _closed_port()}
    unpinned = await checks.web_certificate_checks(Settings(web=WebSettings(**tls)), now, tmp_path)
    assert labels(unpinned) == [("web certificate", "PASS"), ("web certificate pin", "WARN")]
    assert f"set web.tls_pin_sha256: {info.sha256}" in unpinned[1].detail
    pinned = Settings(web=WebSettings(tls_pin_sha256=info.sha256, **tls))
    assert labels(await checks.web_certificate_checks(pinned, now, tmp_path))[1] == (
        "web certificate pin", "PASS")  # fmt: skip
    other = certs.read_cert(pem / "other.crt").sha256
    changed = Settings(web=WebSettings(tls_pin_sha256=other, **tls))
    result = (await checks.web_certificate_checks(changed, now, tmp_path))[1]
    assert (result.label, result.detail.startswith("the certificate CHANGED")) == ("FAIL", True)
    assert other[:16] in result.detail
    assert info.sha256[:16] in result.detail
    none = await checks.web_certificate_checks(Settings(), now, tmp_path)
    assert labels(none) == [("web certificate", "PASS")]
    junk = tmp_path / "junk.crt"
    junk.write_text("junk")
    broken = Settings(web=WebSettings(tls_cert=junk, tls_key=junk))
    assert labels(await checks.web_certificate_checks(broken, now, tmp_path)) == [
        ("web certificate", "FAIL")]  # fmt: skip


@pytest.fixture
async def serving_other(pem: Path) -> AsyncIterator[int]:
    """A web on the loopback that serves other.crt."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(pem / "other.crt", pem / "other.key")

    async def answer(_r: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.close()
        with contextlib.suppress(OSError, ssl.SSLError):
            await writer.wait_closed()

    server = await asyncio.start_server(answer, "127.0.0.1", 0, ssl=context)
    try:
        yield server.sockets[0].getsockname()[1]
    finally:
        server.close()
        await server.wait_closed()


async def test_a_web_that_serves_another_certificate_than_its_file_fails(
    serving_other: int, pem: Path, tmp_path: Path
) -> None:
    info = certs.read_cert(pem / "web.crt")
    web = WebSettings(
        tls_cert=pem / "web.crt",
        tls_key=pem / "web.key",
        port=serving_other,
        tls_pin_sha256=info.sha256,
    )
    now = info.not_after - timedelta(days=99)
    got = await checks.web_certificate_checks(Settings(web=web), now, tmp_path)
    assert labels(got) == [
        ("web certificate", "PASS"),
        ("web certificate served", "FAIL"),
        ("web certificate pin", "PASS"),
    ]
    assert f"the web on port {serving_other} serves" in got[1].detail
    assert "restart argus-web, or find out why" in got[1].detail
    same = WebSettings(tls_cert=pem / "other.crt", tls_key=pem / "other.key", port=serving_other)
    found = await checks.web_certificate_checks(Settings(web=same), info.not_before, tmp_path)
    assert "web certificate served" not in [r.name for r in found]


# --------------------------------------------------------------------------- keys


def _keys(**siem: object) -> Settings:
    return Settings(siem=SiemSettings.model_validate(siem))


def test_key_expiries() -> None:
    assert checks.key_expiry_results(Settings(), NOW) == []
    unrecorded = checks.key_expiry_results(_keys(api_key=SecretStr("k" * 10)), NOW)
    assert labels(unrecorded) == [("SIEM key expiry", "WARN")]
    assert "set siem.api_key_expires" in unrecorded[0].detail
    day = NOW.date()
    cases = [
        (day + timedelta(days=31), "PASS", "valid until"),
        (day + timedelta(days=30), "WARN", "in 29 days"),  # its midnight is 29.5 days away
        (day + timedelta(days=29), "WARN", "rotate it"),
        (day + timedelta(days=1), "WARN", "in 0 days"),
        (day, "FAIL", "expired on"),
        (day - timedelta(days=9), "FAIL", "mint a new one"),
    ]
    for expires, label, words in cases:
        (got,) = checks.key_expiry_results(
            _keys(api_key=SecretStr("k" * 10), api_key_expires=expires), NOW
        )
        assert (got.label, words in got.detail) == (label, True), (expires, got.detail)
    writer = _keys(writer_api_key=SecretStr("w" * 10), writer_api_key_expires=date(2026, 11, 1))
    assert labels(checks.key_expiry_results(writer, NOW)) == [("writer key expiry", "WARN")]


def _proc(tmp_path: Path, processes: dict[int, tuple[str, bytes]]) -> Path:
    proc = tmp_path / "proc"
    for pid, (comm, environ) in processes.items():
        entry = proc / str(pid)
        entry.mkdir(parents=True)
        (entry / "comm").write_text(comm + "\n")
        (entry / "environ").write_bytes(environ)
    (proc / "self").mkdir(parents=True)  # not a pid: ignored
    return proc


def _write_keys(settings: Settings, tmp_path: Path, **kw: object) -> list[str]:
    defaults: dict[str, object] = {
        "env_file": tmp_path / ".env", "config_file": None, "unit_dirs": (), "me": 1,
        "proc": tmp_path / "noproc", "environ_now": {},
    }  # fmt: skip
    defaults.update(kw)
    return checks.write_key_problems(settings, **defaults)  # type: ignore[arg-type]


def test_no_write_key_anywhere_is_clean(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("ARGUS_DATABASE__PASSWORD=x\nARGUS_SIEM__WRITER_API_KEY=\n")
    proc = _proc(tmp_path, {10: ("argus", b"PATH=/bin\0HOME=/h\0")})
    assert _write_keys(Settings(), tmp_path, proc=proc) == []
    result = checks.write_key_result([], configured=False)
    assert (result.label, result.detail) == ("PASS", "none anywhere (writes are off, D-109)")


def test_a_write_key_in_any_shared_place_is_named_never_shown(tmp_path: Path) -> None:
    secret = "Synthetic-Writer-Key-91"
    settings = _keys(writer_api_key=SecretStr(secret))
    (tmp_path / ".env").write_text(f"export ARGUS_SIEM__WRITER_API_KEY='{secret}'\n")
    config = tmp_path / "argus.yaml"
    config.write_text(f"siem:\n  writer_api_key: {secret}\n")
    units_dir = tmp_path / "units"
    units_dir.mkdir()
    (units_dir / "argus-web.service").write_text(
        "[Service]\nEnvironment=ARGUS_SIEM__WRITER_API_KEY=x\n"
    )
    (units_dir / "other.service").write_text("ARGUS_SIEM__WRITER_API_KEY")  # not an ARGUS unit
    proc = _proc(
        tmp_path,
        {
            7: ("bash", b"A=1\0ARGUS_SIEM__WRITER_API_KEY=" + secret.encode() + b"\0"),
            8: ("python", b"STOLEN=" + secret.encode() + b"\0"),  # the value, under another name
            9: ("argus", b"ARGUS_DATABASE__PASSWORD=x\0"),
            42: ("argus", b"ARGUS_SIEM__WRITER_API_KEY=" + secret.encode()),
        },
    )
    (proc / "9" / "environ").chmod(0o000)  # another user's process: unreadable, skipped
    problems = _write_keys(
        settings, tmp_path, config_file=config, unit_dirs=(units_dir, tmp_path / "none"),
        proc=proc, me=42, environ_now={"ARGUS_SIEM__WRITER_API_KEY": secret},
    )  # fmt: skip
    assert problems == [
        f"siem.writer_api_key is in {tmp_path / '.env'}, which every ARGUS process loads",
        f"siem.writer_api_key is in {config} (secrets never go in YAML)",
        f"siem.writer_api_key is in the unit file {units_dir / 'argus-web.service'}",
        "siem.writer_api_key is in the environment of bash (pid 7), python (pid 8), this doctor",
    ]
    result = checks.write_key_result(problems, configured=True)
    assert result.label == "FAIL"
    assert secret not in result.detail
    assert result.detail.endswith("belongs only to the writer's own credential (Q-A5); remove it")


def test_a_write_key_in_a_drop_in_or_an_environment_file_is_found(tmp_path: Path) -> None:
    """A unit's drop-in (argus-web.service.d/*.conf) and the files units load with
    EnvironmentFile= are shared places too."""
    secret = "Synthetic-Writer-Key-92"
    units_dir = tmp_path / "units"
    drop_in = units_dir / "argus-web.service.d"
    drop_in.mkdir(parents=True)
    (drop_in / "override.conf").write_text("[Service]\nEnvironment=ARGUS_SIEM__WRITER_API_KEY=x\n")
    loaded = tmp_path / "web.env"
    loaded.write_text(f"ARGUS_SIEM__WRITER_API_KEY={secret}\n")
    (units_dir / "argus-worker.service").write_text(
        f"[Service]\nEnvironmentFile=-{loaded}\nEnvironmentFile={tmp_path / '.env'}\n"
    )
    (tmp_path / ".env").write_text("ARGUS_DATABASE__PASSWORD=x\n")
    problems = _write_keys(
        _keys(writer_api_key=SecretStr(secret)), tmp_path, unit_dirs=(units_dir,)
    )
    assert problems == [
        f"siem.writer_api_key is in the unit file {drop_in / 'override.conf'}",
        f"siem.writer_api_key is in {loaded}, which argus-worker.service loads",
    ]


def test_a_yaml_that_names_the_key_without_setting_it_is_clean(tmp_path: Path) -> None:
    config = tmp_path / "argus.yaml"
    config.write_text("# siem.writer_api_key lives in .env until Q-A5\nsiem:\n  writer_api_key:\n")
    assert _write_keys(Settings(), tmp_path, config_file=config) == []
    config.write_text(": not yaml : [")
    assert _write_keys(Settings(), tmp_path, config_file=config) == []
    assert checks.write_key_result([], configured=True).detail == (
        "configured, and in no shared place")  # fmt: skip


WRITER = "Synthetic-Writer-Key-93"


@pytest.mark.parametrize(
    "line",
    [
        f"argus_siem__writer_api_key={WRITER}",  # ARGUS reads ARGUS_ names in any case
        f"Argus_Siem__Writer_Api_Key={WRITER}",
        f"'ARGUS_SIEM__WRITER_API_KEY'={WRITER}",  # python-dotenv takes a quoted name
    ],
)
def test_a_writer_key_in_dotenv_is_found_however_its_name_is_written(
    tmp_path: Path, line: str
) -> None:
    """QA2-R2 (a): .env is read as ARGUS reads it, so every spelling ARGUS loads is found."""
    from argus.config.settings import load_settings

    env = tmp_path / ".env"
    env.write_text(line + "\n")
    yaml_file = tmp_path / "argus.yaml"
    yaml_file.write_text("logging:\n  level: WARNING\n")
    settings = load_settings(yaml_file, env_file=env)
    assert settings.siem.writer_api_key is not None  # ARGUS loads it ...
    # ... and doctor finds it, by its name alone and by its value alone
    expected = [f"siem.writer_api_key is in {env}, which every ARGUS process loads"]
    assert _write_keys(settings, tmp_path, env_file=env) == expected
    assert _write_keys(Settings(), tmp_path, env_file=env) == expected
    env.write_text(f"SOMETHING_ELSE={WRITER}\n")  # the value under another name
    assert _write_keys(settings, tmp_path, env_file=env) == expected


def test_a_writer_key_in_a_unit_lowercase_or_through_a_specifier_is_found(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """QA2-R2 (b): unit names in any case; EnvironmentFile= paths with systemd's specifiers
    (%h, %E, %t, %S, %C, %u, %n, %%) and wildcards are expanded as systemd does; one that
    cannot be resolved is a problem, never a pass."""
    home = tmp_path / "home"
    (home / ".config").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "run"))
    (tmp_path / "run").mkdir()
    (home / "writer.env").write_text(f"ARGUS_SIEM__WRITER_API_KEY={WRITER}\n")
    (home / ".config" / "argus-kibana-sync.service.env").write_text(
        f"argus_siem__writer_api_key={WRITER}\n"
    )
    (tmp_path / "run" / "a.env").write_text(f"ARGUS_SIEM__WRITER_API_KEY={WRITER}\n")
    units_dir = tmp_path / "user"
    units_dir.mkdir()
    (units_dir / "argus-writer.service").write_text(
        f"[Service]\nEnvironment=argus_siem__writer_api_key={WRITER}\n"
    )
    (units_dir / "argus-kibana-sync.service").write_text(
        "[Service]\nEnvironmentFile=%h/writer.env\nEnvironmentFile=-%E/%n.env\n"
        "EnvironmentFile=%t/*.env\nEnvironmentFile=%h/100%%.env\n"
    )
    (units_dir / "argus-web.service").write_text(
        "[Service]\nEnvironmentFile=%Z/odd.env\nEnvironmentFile=relative.env\n"
    )
    problems = _write_keys(Settings(), tmp_path, unit_dirs=(units_dir,))
    sync = "argus-kibana-sync.service"
    assert problems == [
        f"siem.writer_api_key is in {home / 'writer.env'}, which {sync} loads",
        f"siem.writer_api_key is in {home / '.config' / (sync + '.env')}, which {sync} loads",
        f"siem.writer_api_key is in {tmp_path / 'run' / 'a.env'}, which {sync} loads",
        "cannot tell whether argus-web.service loads siem.writer_api_key: doctor cannot"
        " resolve EnvironmentFile=%Z/odd.env",
        f"siem.writer_api_key is in the unit file {units_dir / 'argus-writer.service'}",
        # Q-D2's Kibana writer keys: the unresolvable file could hold them as well
        "cannot tell whether argus-web.service loads kibana.cases_writer_api_key: doctor"
        " cannot resolve EnvironmentFile=%Z/odd.env",
        "cannot tell whether argus-web.service loads kibana.alert_writer_api_key: doctor"
        " cannot resolve EnvironmentFile=%Z/odd.env",
        # AR8's six case team keys, the same
        *[
            f"cannot tell whether argus-web.service loads case_team.{user}_api_key: doctor"
            " cannot resolve EnvironmentFile=%Z/odd.env"
            for user in (
                "lead",
                "evidence",
                "intel",
                "responder",
                "hunter",
                "reporter",
                "visualiser",
            )
        ],
    ]


def test_a_writer_key_in_a_process_environment_in_another_case_is_found(tmp_path: Path) -> None:
    proc = _proc(tmp_path, {7: ("bash", b"argus_siem__writer_api_key=x\0")})
    now = {"Argus_Siem__Writer_Api_Key": "y"}
    assert _write_keys(Settings(), tmp_path, proc=proc, environ_now=now) == [
        "siem.writer_api_key is in the environment of bash (pid 7), this doctor"
    ]
    empty = _proc(tmp_path / "e", {8: ("bash", b"argus_siem__writer_api_key=\0")})
    assert _write_keys(Settings(), tmp_path, proc=empty) == []  # set to nothing: no key


def test_the_write_key_check_reads_the_config_file_that_was_loaded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """QA2-R2 (c): ``argus doctor --config other.yaml`` scans other.yaml, not the default."""
    from argus.config.settings import load_settings

    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ARGUS_CONFIG", raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))  # no real unit directory
    other = tmp_path / "prod.yaml"
    other.write_text(f"siem:\n  writer_api_key: {WRITER}\n")
    settings = load_settings(other, env_file=None)
    assert (settings.config_file, settings.env_file) == (other, None)
    monkeypatch.setattr(checks, "PROC", tmp_path / "noproc")  # never the real /proc
    (result,) = asyncio.run(checks.write_key_check(settings))
    assert result.label == "FAIL", (result.label, result.detail)
    assert f"is in {other} (secrets never go in YAML)" in result.detail
    assert WRITER not in result.detail


# --------------------------------------------------------------------------- the tunnel


@pytest.fixture
async def serving(pem: Path) -> AsyncIterator[int]:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(pem / "web.crt", pem / "web.key")

    async def answer(_r: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.close()
        with contextlib.suppress(OSError, ssl.SSLError):
            await writer.wait_closed()

    server = await asyncio.start_server(answer, "127.0.0.1", 0, ssl=context)
    try:
        yield server.sockets[0].getsockname()[1]
    finally:
        server.close()
        await server.wait_closed()


async def test_the_tunnel(serving: int, pem: Path, tmp_path: Path) -> None:
    up = await checks.tunnel_result(pem / "web.crt", serving)
    assert (up.label, up.detail) == ("PASS", f"up on 127.0.0.1:{serving}, the stored certificate")
    other = await checks.tunnel_result(pem / "other.crt", serving)
    assert (other.label, "serves another certificate" in other.detail) == ("FAIL", True)
    unset = await checks.tunnel_result(tmp_path / "local-llm.crt", serving)
    assert (unset.label, unset.detail) == ("PASS", "the local model is not set up (D-108)")
    junk = tmp_path / "junk.crt"
    junk.write_text("junk")
    assert (await checks.tunnel_result(junk, serving)).label == "FAIL"


async def test_a_tunnel_that_is_down_is_a_warning(pem: Path) -> None:
    import socket

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    down = await checks.tunnel_result(pem / "web.crt", port, wait_s=1.0)
    assert (down.label, down.detail.startswith(f"down: nothing answers on 127.0.0.1:{port}")) == (
        "WARN", True)  # fmt: skip


def test_the_tunnel_is_where_the_setup_script_puts_it() -> None:
    script = private_text(REPO_ROOT / "deploy" / "local-llm" / "setup-argus-side.sh")
    assert f"TUNNEL_PORT={checks.LOCAL_LLM_PORT}\n" in script
    assert f'CERT_FILE="$ARGUS_DIR/{checks.LOCAL_LLM_CERT}"' in script


# --------------------------------------------------------------------------- units


# A made-up installation (D-295): its checkout, its uv, the units it runs.
PARAMS = units.UnitParams(
    Path("/srv/argus"), "/usr/local/bin/uv", {"WEB_PUBLIC_URL": "http://127.0.0.1:8765"}
)
RUN = (*units.CORE, "argus-soak-sample.timer", "argus-kibana-sync.service",
       "argus-case-team.timer")  # fmt: skip
RENDERED = units.rendered_units(PARAMS)


def _results(installed: Path, *other: Path) -> list[CheckResult]:
    return checks.unit_results(UNITS_DIR, installed, other, params=PARAMS, run=RUN)


def test_unit_results_summarise_and_flag(tmp_path: Path) -> None:
    folder = tmp_path / "user"
    folder.mkdir()
    roles = units.roles_for(RUN)
    for name, (role, _) in roles.items():
        if role.value in ("run", "triggered") and not name.startswith("argus-backup"):
            (folder / name).write_text(RENDERED[name])
    wants = folder / "default.target.wants"
    wants.mkdir()
    for name in RUN:
        (wants / name).symlink_to(folder / name)
    results = _results(folder)
    assert results[0].name == "service units"
    assert results[0].label == "PASS"
    assert "8 of the 8 this installation runs running as installed" in results[0].detail
    assert {r.name: r.label for r in results[1:]} == {
        "unit argus-backup.timer": "WARN",
        "unit argus-backup.service": "WARN",
        "unit argus-backup-drill.timer": "WARN",
        "unit argus-backup-drill.service": "WARN",
    }
    (folder / "argus-web.service").write_text("[Service]\nWorkingDirectory=/srv/argus\n")
    failed = _results(folder)
    assert failed[0].label == "FAIL"
    assert ("unit argus-web.service", "FAIL") in labels(failed)


def test_the_templates_themselves_installed_differ_from_their_rendering(tmp_path: Path) -> None:
    folder = tmp_path / "user"
    folder.mkdir()
    shutil.copyfile(UNITS_DIR / "argus-collector.service", folder / "argus-collector.service")
    found = checks.unit_results(UNITS_DIR, folder, (), params=PARAMS, run=RUN)
    assert ("unit argus-collector.service", "FAIL") in labels(found)


def test_units_installed_for_another_checkout_are_named_not_compared(tmp_path: Path) -> None:
    folder = tmp_path / "user"
    folder.mkdir()
    other = units.UnitParams(Path("/home/someone/argus"), "/usr/bin/uv")
    for name, text in units.rendered_units(other).items():
        (folder / name).write_text(text)
    found = _results(folder)
    assert labels(found) == [("service units", "WARN")]
    assert "installed for another checkout (/home/someone/argus)" in found[0].detail
    (folder / "argus-web.service.d").mkdir()
    (folder / "argus-web.service.d" / "x.conf").write_text("[Service]\n")
    assert labels(_results(folder))[0] == ("service units", "FAIL")  # a drop-in still fails


def test_a_fresh_install_that_runs_nothing_yet_has_no_failure(tmp_path: Path) -> None:
    folder = tmp_path / "user"
    folder.mkdir()
    for name, text in RENDERED.items():
        (folder / name).write_text(text)
    found = checks.unit_results(UNITS_DIR, folder, (), params=PARAMS, run=())
    assert found[0].label == "PASS"
    assert "none runs yet" in found[0].detail
    assert all(r.ok for r in found)
    wants = folder / "default.target.wants"
    wants.mkdir()
    (wants / "argus-collector.service").symlink_to(folder / "argus-collector.service")
    chosen = checks.unit_results(UNITS_DIR, folder, (), params=PARAMS, run=())
    assert ("unit argus-collector.service", "WARN") in labels(chosen)  # not listed in units.run


def test_units_installed_but_not_started_yet_wait_for_a_person(tmp_path: Path) -> None:
    """`argus init` answered no to starting: nothing runs yet, which is a warning; once one
    runs, every other that units.run lists must run too."""
    folder = tmp_path / "user"
    folder.mkdir()
    for name, text in RENDERED.items():
        (folder / name).write_text(text)
    waiting = _results(folder)
    assert waiting[0].label == "WARN"
    assert "none started yet: `argus init --start` starts them" in waiting[0].detail
    assert all(r.ok for r in waiting)
    assert ("unit argus-collector.service", "WARN") in labels(waiting)
    assert any("not started yet" in r.detail for r in waiting[1:])
    wants = folder / "default.target.wants"
    wants.mkdir()
    (wants / "argus-collector.service").symlink_to(folder / "argus-collector.service")
    partly = _results(folder)
    assert partly[0].label == "FAIL"
    assert ("unit argus-worker.service", "FAIL") in labels(partly)


def _installed_and_enabled(tmp_path: Path) -> Path:
    folder = tmp_path / "user"
    folder.mkdir()
    wants = folder / "default.target.wants"
    wants.mkdir()
    for name, (role, _) in units.roles_for(RUN).items():
        (folder / name).write_text(RENDERED[name])
        if role.value in ("run", "soon"):
            (wants / name).symlink_to(folder / name)
    return folder


@pytest.mark.parametrize(
    ("where", "folder", "name"),
    [
        ("user", "argus-web.service.d", "override.conf"),  # systemctl --user edit
        ("user", "argus-.service.d", "all.conf"),  # every argus-*.service
        ("user", "service.d", "all.conf"),  # every service
        ("control", "argus-web.service.d", "50-MemoryMax.conf"),  # systemctl set-property
        ("runtime-control", "argus-web.service.d", "50-MemoryMax.conf"),  # ... --runtime
        ("runtime", "argus-web.service.d", "override.conf"),  # systemctl --user edit --runtime
    ],
)
def test_a_drop_in_that_changes_a_unit_fails_the_units_check(
    tmp_path: Path, where: str, folder: str, name: str
) -> None:
    """QA2-R3: a drop-in changes what runs while the unit file stays byte-identical."""
    installed = _installed_and_enabled(tmp_path)
    places = {
        "user": installed,
        "control": tmp_path / "user.control",
        "runtime-control": tmp_path / "run" / "user.control",
        "runtime": tmp_path / "run" / "user",
    }
    extra = tuple(v for k, v in places.items() if k != "user")
    before = _results(installed, *extra)
    assert labels(before) == [("service units", "PASS")]
    assert "8 of the 8 this installation runs running as installed" in before[0].detail
    drop = places[where] / folder
    drop.mkdir(parents=True)
    (drop / name).write_text("[Service]\nExecStart=\nExecStart=/bin/other\n")
    after = _results(installed, *extra)
    assert after[0].label == "FAIL"
    flagged = [r for r in after[1:] if str(drop / name) in r.detail]
    assert [r.label for r in flagged] == ["FAIL"], after
    running = re.search(r"; (\d+) of the 8 this installation runs", after[0].detail)
    assert running is not None, after[0].detail
    assert int(running.group(1)) < 8, after[0].detail  # the changed unit is not counted


# --------------------------------------------------------------------------- backups


def _manifest(base: Path, kind: backup.Kind, at: datetime, **kw: object) -> backup.Manifest:
    folder = base / kind
    folder.mkdir(parents=True, exist_ok=True)
    name = f"argus-{at:%Y%m%dT%H%M%S}.dump"
    (folder / name).write_bytes(b"dump")
    made = backup.Manifest(
        kind=kind, database="argus", created_at=at, file=name, bytes=4, sha256="0" * 64,
        revision="0022", server_version="17.11", took_s=1.0,
        fingerprints=backup.Fingerprints({"public.t": (1, "x")}, {}, {}),
        path=folder / name.replace(".dump", ".json"), **kw,  # type: ignore[arg-type]
    )  # fmt: skip
    made.path.write_text(json.dumps(made.as_json()))
    return made


def _drill(base: Path, at: datetime, passed: bool) -> None:
    with (base / backup.DRILLS).open("a") as handle:
        handle.write(json.dumps({"at": at.isoformat(), "dump": "nightly/x", "passed": passed}))
        handle.write("\n")


def test_backup_results(tmp_path: Path) -> None:
    base = tmp_path / "backups"
    assert labels(checks.backup_results(base, NOW)) == [("backups", "WARN")]
    _manifest(base, "manual", NOW - timedelta(hours=2))
    only_manual = checks.backup_results(base, NOW)
    assert labels(only_manual) == [("backups", "WARN"), ("restore drill", "WARN")]
    assert "no nightly dump yet (newest: manual" in only_manual[0].detail
    _manifest(base, "nightly", NOW - timedelta(hours=25))
    assert labels(checks.backup_results(base, NOW))[0] == ("backups", "PASS")
    stale = checks.backup_results(base, NOW + timedelta(hours=1, minutes=1))
    assert labels(stale)[0] == ("backups", "FAIL")
    assert "26 h old" in stale[0].detail
    _drill(base, NOW - timedelta(days=9), True)
    assert labels(checks.backup_results(base, NOW))[1] == ("restore drill", "WARN")
    _drill(base, NOW - timedelta(days=1), True)
    assert labels(checks.backup_results(base, NOW))[1] == ("restore drill", "PASS")
    _drill(base, NOW - timedelta(hours=1), False)
    failed = checks.backup_results(base, NOW)
    assert labels(failed)[1] == ("restore drill", "FAIL")
    assert "DIFFERENT" in failed[1].detail
    (base / backup.DRILLS).write_text('{"at": "not a time", "passed": true}\nnot json\n')
    assert labels(checks.backup_results(base, NOW))[1] == ("restore drill", "WARN")


# --------------------------------------------------------------------------- the frontend


def _node(tmp_path: Path, node: str, npm: str | None) -> Path:
    folder = tmp_path / "node24"
    (folder / "bin").mkdir(parents=True)
    for name, version in (("node", node), ("npm", npm)):
        if version is None:
            continue
        tool = folder / "bin" / name
        tool.write_text(f"#!/bin/sh\necho {version}\n")
        tool.chmod(0o755)
    return folder


def test_the_node_toolchain(tmp_path: Path) -> None:
    good = checks.toolchain_result(_node(tmp_path / "a", "v24.21.0", "11.19.0"))
    assert (good.label, good.detail.startswith("Node v24.21.0, npm 11.19.0")) == ("PASS", True)
    assert checks.toolchain_result(tmp_path / "missing").label == "WARN"
    old = checks.toolchain_result(_node(tmp_path / "b", "v20.20.2", "10.8.0"))
    assert (old.label, "not Node 24" in old.detail) == ("FAIL", True)
    no_npm = checks.toolchain_result(_node(tmp_path / "c", "v24.1.0", None))
    assert (no_npm.label, no_npm.detail) == ("FAIL", "npm is missing, not npm 11")
    npm10 = checks.toolchain_result(_node(tmp_path / "d", "v24.1.0", "10.9.2"))
    assert (npm10.label, npm10.detail) == ("FAIL", "npm is 10.9.2, not npm 11")


def test_the_frontend_build_is_the_build_of_its_sources(tmp_path: Path) -> None:
    source, build = tmp_path / "frontend", tmp_path / "spa"
    assert checks.build_result(source, build).detail == "no frontend yet (Q-B1)"
    source.mkdir()
    (source / "package.json").write_text("{}")
    assert checks.build_result(source, build).label == "FAIL"
    frontend.write_manifest(build, source, "v24.21.0", "11.19.0", NOW)
    fresh = checks.build_result(source, build)
    assert (fresh.label, fresh.detail) == (
        "PASS", "built 2026-10-23T12:00 with Node v24.21.0 from the current sources")  # fmt: skip
    (source / "src").mkdir()
    (source / "src" / "main.ts").write_text("export {}\n")
    stale = checks.build_result(source, build)
    assert (stale.label, re.search(r"^stale: built from sources \w{12}", stale.detail) is not None
            ) == ("FAIL", True)  # fmt: skip


def test_the_served_build_is_checked_where_app_serves_it(tmp_path: Path) -> None:
    """Review F9: doctor checks the folder /app is served from (web.spa_dir), not only the
    package's: a missing page, a page without a build id, a copy of another build."""
    package = tmp_path / "spa"
    package.mkdir()
    page = '<meta name="argus-build" content="0123456789abcdef">'
    (package / "index.html").write_text(page)
    source = tmp_path / "frontend"
    source.mkdir()
    frontend.write_manifest(package, source, "v24.21.0", "11.19.0", NOW)
    same = checks.served_result(package, package)
    serves = "/app serves build 0123456789abcdef from"
    assert (same.name, same.label, same.detail) == (
        "frontend served",
        "PASS",
        f"{serves} {package}",
    )
    copy = tmp_path / "deploy"
    assert checks.served_result(copy, package).label == "FAIL"  # no folder
    copy.mkdir()
    empty = checks.served_result(copy, package)
    assert (empty.label, empty.detail) == (
        "FAIL", f"no index.html in {copy}: /app answers 503 (web.spa_dir)")  # fmt: skip
    (copy / "index.html").write_text("<p>no id</p>")
    no_id = checks.served_result(copy, package)
    assert (no_id.label, no_id.detail) == ("FAIL", f"index.html in {copy} names no build")
    (copy / "index.html").write_text(page)
    unlabelled = checks.served_result(copy, package)
    again = "is not a copy of the package's build: copy it again (web.spa_dir)"
    assert (unlabelled.label, unlabelled.detail) == ("FAIL", f"{copy} {again}")
    frontend.write_manifest(copy, source, "v24.21.0", "11.19.0", NOW.replace(hour=1))
    assert checks.served_result(copy, package).label == "FAIL"  # another build's manifest
    (copy / frontend.MANIFEST).write_text((package / frontend.MANIFEST).read_text())
    good = checks.served_result(copy, package)
    assert (good.label, good.detail) == ("PASS", f"{serves} {copy}")


async def test_doctor_checks_the_folder_app_is_served_from(tmp_path: Path) -> None:
    empty = tmp_path / "deploy-copy"
    empty.mkdir()
    results = await checks.frontend_check(Settings(web=WebSettings(spa_dir=empty)))
    served = next(r for r in results if r.name == "frontend served")
    assert (served.ok, str(empty) in served.detail) == (False, True)
    default = await checks.frontend_check(Settings())
    assert next(r for r in default if r.name == "frontend served").ok


async def test_a_platform_check_that_breaks_hides_no_other(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from argus.doctor import run_checks

    def broken(*_: object, **__: object) -> list[CheckResult]:
        raise PermissionError("unit directory unreadable")

    monkeypatch.setattr(checks, "unit_results", broken)
    settings = Settings.model_validate(
        {"database": {"name": "argus_unit_never_created", "port": 1, "connect_timeout": "1s"}}
    )
    got = {r.name: r for r in await run_checks(settings)}
    assert (got["unit_check"].label, "check crashed: unit directory unreadable" in
            got["unit_check"].detail) == ("FAIL", True)  # fmt: skip
    for still in ("web certificate", "local model tunnel", "write keys", "backups",
                  "node toolchain", "frontend build", "threat intel"):  # fmt: skip
        assert still in got, still


# --------------------------------------------------------------------------- deployed code


def test_the_code_tree_is_dated_by_its_newest_file(tmp_path: Path) -> None:
    import os

    (tmp_path / "src" / "argus" / "pkg" / "__pycache__").mkdir(parents=True)
    (tmp_path / "config").mkdir()
    old = tmp_path / "src" / "argus" / "a.py"
    new = tmp_path / "config" / "argus.yaml"
    cache = tmp_path / "src" / "argus" / "pkg" / "__pycache__" / "x.pyc"
    for path, when in ((old, 1_000), (new, 5_000), (cache, 9_000)):
        path.write_text("x")
        os.utime(path, (when, when))
    assert checks.code_changed_at(tmp_path) == datetime.fromtimestamp(5_000, UTC)
    assert checks.code_changed_at(tmp_path / "nowhere") is None


class _Done:
    def __init__(self, out: str, code: int = 0) -> None:
        self.stdout, self.returncode = out, code


def test_service_start_times_are_read_from_the_user_manager() -> None:
    answer = (
        "Id=argus-web.service\nActiveState=active\nActiveEnterTimestamp=@1793411806\n\n"
        "Id=argus-worker.service\nActiveState=inactive\nActiveEnterTimestamp=\n\n"
        "Id=argus-assess.service\nActiveState=active\nActiveEnterTimestamp=@1793415000\n"
    )
    seen: list[list[str]] = []

    def run(argv: list[str], **_: object) -> _Done:
        seen.append(argv)
        return _Done(answer)

    got = checks.service_start_times(["argus-web.service"], run)  # type: ignore[arg-type]
    assert got == {
        "argus-web.service": datetime.fromtimestamp(1793411806, UTC),
        "argus-assess.service": datetime.fromtimestamp(1793415000, UTC),
    }
    assert seen[0][:3] == ["systemctl", "--user", "show"]  # read-only: nothing started or stopped

    def broken(argv: list[str], **_: object) -> _Done:
        raise FileNotFoundError("systemctl")

    assert "could not be run" in str(checks.service_start_times(["a"], broken))  # type: ignore[arg-type]
    down = checks.service_start_times(["a"], lambda *_a, **_k: _Done("", 1))  # type: ignore[arg-type]
    assert "did not answer" in str(down)


def test_a_service_that_started_before_the_code_changed_is_warned() -> None:
    changed = datetime(2026, 10, 31, 1, 32, tzinfo=UTC)
    before = datetime(2026, 10, 30, 21, 13, tzinfo=UTC)
    after = datetime(2026, 10, 31, 2, 0, tzinfo=UTC)
    stale = checks.deployed_code_result(
        {"argus-web.service": before, "argus-worker.service": after}, changed
    )
    assert (stale.label, "argus-web (since" in stale.detail, "argus-worker" in stale.detail) == (
        "WARN", True, False)  # fmt: skip
    assert "restart" in stale.detail
    assert "argus db upgrade" in stale.detail
    fresh = checks.deployed_code_result({"argus-web.service": after}, changed)
    assert (fresh.label, fresh.detail) == (
        "PASS", "1 running services started after the code last changed")  # fmt: skip
    # nothing is claimed when it cannot be told
    unknown = checks.deployed_code_result("the user service manager did not answer", changed)
    assert unknown.label == "PASS"
    assert checks.deployed_code_result({"a.service": before}, None).label == "PASS"
    assert checks.deployed_code_result({}, changed).label == "PASS"


async def test_the_registered_check_never_starts_or_stops_a_service(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[list[str]] = []

    def run(argv: list[str], **_: object) -> _Done:
        seen.append(argv)
        return _Done("Id=argus-web.service\nActiveState=active\nActiveEnterTimestamp=@1\n")

    monkeypatch.setattr(checks.subprocess, "run", run)
    [result] = await checks.deployed_code_check(Settings())
    assert result.label == "WARN"
    assert "argus-web" in result.detail  # started in 1970
    assert seen[0][:3] == ["systemctl", "--user", "show"]
    assert "argus-web.service" in seen[0]
    assert "argus-writer.service" not in seen[0]

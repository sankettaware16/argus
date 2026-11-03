"""Q-A5: the import install.sh runs (the shared .env split into credentials and argus.env,
read exactly as ARGUS reads it) and argus doctor's custody checks, on a fake /etc/argus."""

# ruff: noqa: S103 - the tests set modes on purpose, permissive ones included

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.config import Settings
from argus.ops import custody
from argus.ops.custody import (
    ACCOUNTS,
    UNITS,
    account_results,
    credential_results,
    custody_results,
    env_file_text,
    import_checkout,
    main,
    release_results,
    unit_results,
)
from tests.conftest import REPO_ROOT

pytestmark = pytest.mark.unit

SECRET_VALUES = {
    "ARGUS_DATABASE__PASSWORD": "Synthetic-Runtime-11",
    "ARGUS_DATABASE__OWNER_PASSWORD": "Synthetic-Owner-22",
    "ARGUS_DATABASE__API_PASSWORD": "Synthetic-Web-33",
    "ARGUS_SIEM__API_KEY": "Synthetic-Reader-44",
}
ME = os.getuid()


def checkout(tmp_path: Path, extra: str = "") -> Path:
    root = tmp_path / "checkout"
    (root / "data" / "tls").mkdir(parents=True)
    (root / "data" / "certs").mkdir(parents=True)
    (root / "data" / "assets").mkdir(parents=True)
    (root / "reference").mkdir(parents=True)
    lines = [f"{k}={v}" for k, v in SECRET_VALUES.items()]
    lines += [
        "ARGUS_DATABASE__HOST=127.0.0.1",
        "ARGUS_DATABASE__PORT=55432",
        "ARGUS_DATABASE__NAME=argus",
        "ARGUS_BACKUP__BEFORE_MIGRATION=true",
        "ARGUS_BACKUP__DIR=data/backups",  # replaced by the custody path
        "ARGUS_WEB__HOST=0.0.0.0",  # the unit sets it
        "POSTGRES_EXTRA=not-argus",  # another tool's: never copied
        "REPLICA_ELASTIC_PASSWORD=Synthetic-Replica-66",
    ]
    (root / ".env").write_text("\n".join(lines) + "\n" + extra)
    (root / "data" / "tls" / "argus.key").write_text("Synthetic-TLS-Key\n")
    (root / "data" / "tls" / "argus.crt").write_text("certificate\n")
    (root / "data" / "certs" / "siem-ca.crt").write_text("ca\n")
    (root / "data" / "assets" / "asset_map.yaml").write_text("assets: []\n")
    (root / "reference" / "llm_api_keys.env").write_text("GROQ_API_KEY=Synthetic-Groq-77\n")
    return root


def everything_printed(report: custody.Report) -> str:
    return "\n".join(report.lines)


def test_the_import_makes_each_credential_and_argus_env(tmp_path: Path) -> None:
    source, etc = checkout(tmp_path), tmp_path / "etc"
    report = import_checkout(source, etc, check=False)
    assert report.missing == []
    folder = etc / "credentials"
    expected = {
        "database.password": "Synthetic-Runtime-11",
        "database.owner_password": "Synthetic-Owner-22",
        "database.api_password": "Synthetic-Web-33",
        "siem.api_key": "Synthetic-Reader-44",
        "web-tls.key": "Synthetic-TLS-Key\n",
        "llm-api-keys.env": "GROQ_API_KEY=Synthetic-Groq-77\n",
    }
    assert sorted(p.name for p in folder.iterdir()) == sorted(expected)
    for name, value in expected.items():
        assert (folder / name).read_text() == value
        assert stat.S_IMODE((folder / name).stat().st_mode) == 0o600
    env = (etc / "argus.env").read_text()
    assert stat.S_IMODE((etc / "argus.env").stat().st_mode) == 0o640
    assert "ARGUS_DATABASE__HOST='127.0.0.1'" in env
    assert "ARGUS_BACKUP__BEFORE_MIGRATION='true'" in env
    assert "ARGUS_BACKUP__DIR='/var/lib/argus-backups'" in env
    assert "ARGUS_SIEM__CA_FILE='/etc/argus/certs/siem-ca.crt'" in env
    assert "ARGUS_WEB__HOST" not in env
    assert "POSTGRES_EXTRA" not in env
    assert "REPLICA" not in env
    for value in [*SECRET_VALUES.values(), "Synthetic-Replica-66"]:
        assert value not in env
        assert value not in everything_printed(report)
    assert "argus.env: ARGUS_WEB__HOST left out (the units set it)" in report.lines
    assert any(".env still holds database.api_password" in line for line in report.lines)
    assert (etc / "data" / "asset_map.yaml").read_text() == "assets: []\n"
    assert stat.S_IMODE((etc / "data" / "asset_map.yaml").stat().st_mode) == 0o640
    assert stat.S_IMODE((etc / "certs" / "siem-ca.crt").stat().st_mode) == 0o644


def test_the_import_is_idempotent_and_never_replaces_a_credential(tmp_path: Path) -> None:
    source, etc = checkout(tmp_path), tmp_path / "etc"
    import_checkout(source, etc, check=False)
    again = import_checkout(source, etc, check=True)
    assert again.pending == 0
    # the .env changes after the move: the credential counts now, so it is kept
    text = (source / ".env").read_text().replace("Synthetic-Reader-44", "Synthetic-Reader-99")
    (source / ".env").write_text(text)
    report = import_checkout(source, etc, check=False)
    assert (etc / "credentials" / "siem.api_key").read_text() == "Synthetic-Reader-44"
    assert any(line.startswith("credential siem.api_key: kept") for line in report.lines)
    assert "Synthetic-Reader-99" not in everything_printed(report)
    assert report.pending == 0


def test_check_changes_nothing(tmp_path: Path) -> None:
    source, etc = checkout(tmp_path), tmp_path / "etc"
    report = import_checkout(source, etc, check=True)
    assert report.pending > 0
    assert not etc.exists()
    assert "credential database.password: to create" in report.lines


def test_a_missing_required_credential_is_reported(tmp_path: Path) -> None:
    source, etc = checkout(tmp_path), tmp_path / "etc"
    (source / ".env").write_text("ARGUS_DATABASE__PASSWORD=x\n")
    (source / "reference" / "llm_api_keys.env").unlink()
    report = import_checkout(source, etc, check=False)
    assert sorted(report.missing) == [
        "database.api_password",
        "database.owner_password",
        "siem.api_key",
    ]
    assert (etc / "credentials" / "llm-api-keys.env").read_bytes() == b""  # no provider keys
    assert not (etc / "credentials" / "siem.writer_api_key").exists()
    assert "credential siem.writer_api_key: none yet (added at its own production step)" in (
        report.lines
    )
    assert main(["import", "--checkout", str(source), "--etc", str(etc)]) == 3


def test_a_dotenv_argus_refuses_stops_the_import(tmp_path: Path) -> None:
    source, etc = checkout(tmp_path), tmp_path / "etc"
    (source / ".env").write_text("ARGUS_DATABASE__PASSWORD='unterminated\n")
    report = import_checkout(source, etc, check=False)
    assert report.missing == [".env"]
    assert not (etc / "credentials").exists()


def test_a_value_systemd_could_not_carry_is_left_out(tmp_path: Path) -> None:
    report = custody.Report()
    text = env_file_text({"ARGUS_WEB__TLS_PIN_SHA256": "it's", "ARGUS_ENVIRONMENT": "prod"}, report)
    assert b"ARGUS_ENVIRONMENT='prod'" in text
    assert b"TLS_PIN" not in text
    assert (
        "argus.env: ARGUS_WEB__TLS_PIN_SHA256 left out (a quote or a line break)"
        in (report.lines[0])
    )


@given(
    value=st.text(
        st.characters(blacklist_categories=("Cs",), blacklist_characters="\x00"), max_size=40
    )
)
def test_argus_env_holds_a_value_literally_or_not_at_all(value: str) -> None:
    """systemd reads a single-quoted value literally: so every value written is exactly the
    setting's, and one it could not hold so is left out (never changed)."""
    report = custody.Report()
    text = env_file_text({"ARGUS_DATABASE__NAME": value}, report).decode()
    # systemd ends a line at \n or \r only (U+0085 or U+2028 are part of a value)
    lines = [line for line in text.split("\n") if line.startswith("ARGUS_DATABASE__NAME=")]
    if lines:
        assert lines == [f"ARGUS_DATABASE__NAME='{value}'"]
        assert "'" not in value
        assert all(ord(c) >= 0x20 and c != "\x7f" for c in value)
    else:
        assert any("ARGUS_DATABASE__NAME left out" in line for line in report.lines)


# --------------------------------------------------------------------------- doctor


def installed(tmp_path: Path) -> tuple[Path, Path, Path]:
    """A fake custody install: /etc/argus, /opt/argus and the system unit folder."""
    etc, opt, systemd = tmp_path / "etc", tmp_path / "opt", tmp_path / "system"
    import_checkout(checkout(tmp_path), etc, check=False)
    release = opt / "releases" / "q-a5-approved-0123456789ab"
    (release / "deploy" / "custody").mkdir(parents=True)
    source_units = release / "deploy" / "custody" / "units"
    source_units.mkdir()
    systemd.mkdir()
    wants = {"multi-user.target.wants": systemd / "multi-user.target.wants",
             "timers.target.wants": systemd / "timers.target.wants"}  # fmt: skip
    for folder in wants.values():
        folder.mkdir()
    for name, (_account, role) in UNITS.items():
        data = (REPO_ROOT / "deploy" / "custody" / "units" / name).read_bytes()
        (source_units / name).write_bytes(data)
        (systemd / name).write_bytes(data)
        if role is custody.Role.RUN:
            target = "timers.target.wants" if name.endswith(".timer") else "multi-user.target.wants"
            (wants[target] / name).symlink_to(systemd / name)
    for top, dirs, files in os.walk(release, topdown=False):
        for entry in [*files, *dirs]:
            os.chmod(os.path.join(top, entry), 0o555 if entry in dirs else 0o444)
    os.chmod(release, 0o555)
    (opt / "current").symlink_to("releases/q-a5-approved-0123456789ab")
    (etc / "custody.json").write_text(
        json.dumps(
            {
                "tag": "q-a5-approved",
                "commit": "0123456789ab" + "0" * 28,
                "release": "q-a5-approved-0123456789ab",
            }
        )
    )
    return etc, opt, systemd


@pytest.fixture
def layout(tmp_path: Path):  # type: ignore[no-untyped-def]
    etc, opt, systemd = installed(tmp_path)
    yield etc, opt, systemd
    for top, dirs, _files in os.walk(opt):
        os.chmod(top, 0o755)
        for d in dirs:
            os.chmod(os.path.join(top, d), 0o755)


def test_a_complete_install_passes(layout: tuple[Path, Path, Path]) -> None:
    etc, opt, systemd = layout
    results = custody_results(Settings(), etc=etc, opt=opt, units_dir=systemd, want_uid=ME)
    failed = [r for r in results if not r.ok]
    assert failed == [], failed
    assert results[0].name == "custody"
    assert "argus-svc, argus-web, argus-writer" in results[0].detail
    assert any("SOON" not in r.detail and r.warn for r in results)  # the backup timers


def test_not_installed_is_a_warning(tmp_path: Path) -> None:
    (result,) = custody_results(Settings(), etc=tmp_path / "none")
    assert result.ok
    assert result.warn
    assert "not installed" in result.detail


def test_a_marker_doctor_cannot_read_fails(tmp_path: Path) -> None:
    (tmp_path / "custody.json").write_text("{not json")
    (result,) = custody_results(Settings(), etc=tmp_path)
    assert not result.ok


@pytest.mark.parametrize(
    ("damage", "expected"),
    [
        (lambda f: os.chmod(f / "database.password", 0o644), "has mode 0644 (wanted 0600 at most)"),
        (lambda f: (f / "siem.api_key").write_text(""), "is empty"),
        (lambda f: (f / "siem.api_key").unlink(), "missing"),
        (lambda f: (f / "copy-of-writer-key").write_text("x"), "not a credential of the layout"),
        (
            lambda f: ((f / "web-tls.key").unlink(), (f / "web-tls.key").symlink_to("/etc/hosts")),
            "is a symbolic link",
        ),
        (lambda f: os.chmod(f, 0o777), "must be root's folder, writable by root only"),
    ],
)
def test_each_credential_problem_is_found(tmp_path: Path, damage, expected: str) -> None:  # type: ignore[no-untyped-def]
    etc = tmp_path / "etc"
    import_checkout(checkout(tmp_path), etc, check=False)
    assert all(r.ok for r in credential_results(etc, want_uid=ME))
    damage(etc / "credentials")
    results = credential_results(etc, want_uid=ME)
    assert not results[0].ok
    assert any(expected in r.detail for r in results), [r.detail for r in results]


def test_an_empty_llm_keys_credential_and_no_writer_key_are_fine(tmp_path: Path) -> None:
    etc = tmp_path / "etc"
    import_checkout(checkout(tmp_path), etc, check=False)
    (etc / "credentials" / "llm-api-keys.env").write_bytes(b"")
    assert all(r.ok for r in credential_results(etc, want_uid=ME))


def test_credentials_owned_by_anyone_but_root_fail(tmp_path: Path) -> None:
    if ME == 0:
        pytest.skip("runs as root")
    etc = tmp_path / "etc"
    import_checkout(checkout(tmp_path), etc, check=False)
    results = credential_results(etc)  # want root's
    assert any("must be root's folder" in r.detail for r in results)
    assert any(r.detail == "is not owned by root" for r in results)


def test_a_writable_or_foreign_deploy_copy_fails(layout: tuple[Path, Path, Path]) -> None:
    etc, opt, _systemd = layout
    assert release_results(etc, opt, want_uid=ME)[0].ok
    release = opt / "releases" / "q-a5-approved-0123456789ab"
    os.chmod(release / "deploy", 0o755)
    (result,) = release_results(etc, opt, want_uid=ME)
    assert not result.ok
    assert "1 writable" in result.detail
    if ME != 0:
        assert "not root's" in release_results(etc, opt)[0].detail
    (opt / "current").unlink()
    (opt / "current").symlink_to("releases")
    assert "not" in release_results(etc, opt, want_uid=ME)[0].detail


def test_unit_problems_are_found(layout: tuple[Path, Path, Path]) -> None:
    _etc, opt, systemd = layout
    source = opt / "releases" / "q-a5-approved-0123456789ab" / "deploy" / "custody" / "units"
    assert [r for r in unit_results(source, systemd) if not r.ok] == []
    collector = systemd / "argus-collector.service"
    collector.write_text(
        collector.read_text().replace(
            "LoadCredential=database.password:",
            "LoadCredential=database.owner_password:/x\nLoadCredential=database.password:",
        )
    )
    (systemd / "multi-user.target.wants" / "argus-web.service").unlink()
    (systemd / "multi-user.target.wants" / "argus-writer.service").symlink_to(
        systemd / "argus-writer.service"
    )
    web = systemd / "argus-web.service"
    web.write_text(
        web.read_text().replace(
            "LoadCredential=database.api_password:/etc/argus/credentials/database.api_password",
            "LoadCredential=database.api_password:/etc/argus/credentials/database.owner_password"
            "\nSetCredential=siem.api_key:Synthetic-Inline-99",
        )
    )
    (systemd / "argus-worker.service.d").mkdir()
    (systemd / "argus-worker.service.d" / "override.conf").write_text("[Service]\nUser=root\n")
    results = unit_results(source, systemd, user_units={"argus-assess.service"})
    found = {(r.name, r.detail) for r in results if not r.ok}
    assert ("system unit argus-collector.service", "differs from the release's copy") in found
    assert (
        "system unit argus-collector.service",
        "loads database.owner_password, which its account (svc) must not hold",
    ) in found
    assert ("system unit argus-web.service", "installed but not enabled") in found
    assert (
        "system unit argus-web.service",
        "loads database.api_password from /etc/argus/credentials/database.owner_password, not"
        " /etc/argus/credentials/database.api_password",
    ) in found
    assert (
        "system unit argus-web.service",
        "gets siem.api_key by SetCredential= (the layout uses LoadCredential=)",
    ) in found
    assert not any("Synthetic-Inline-99" in d for _, d in found)
    elsewhere = _etc.parent / "run-system"
    (elsewhere / "argus-collector.service.d").mkdir(parents=True)
    (elsewhere / "argus-collector.service.d" / "50-x.conf").write_text("[Service]\n")
    more = unit_results(source, systemd, other_dirs=[elsewhere])
    assert any("drop-in" in r.detail and "50-x.conf" in r.detail for r in more)
    assert ("system unit argus-writer.service", "enabled before its production step") in found
    assert any(n == "system unit argus-worker.service" and "drop-in" in d for n, d in found)
    assert any(n == "system unit argus-assess.service" and "run twice" in d for n, d in found)


def test_the_operators_risky_groups_home_and_leftover_secrets_are_warnings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import grp
    import pwd

    me = pwd.getpwuid(ME)
    monkeypatch.setattr(
        grp, "getgrall", lambda: [grp.struct_group(("docker", "x", 999, [me.pw_name]))]
    )
    home = tmp_path / "home"
    home.mkdir(mode=0o751)
    os.chmod(home, 0o751)
    source = checkout(tmp_path)
    results = account_results(uid=ME, home=home, env_file=source / ".env")
    details = [r.detail for r in results]
    assert all(r.ok and r.warn for r in results)
    if ME != 0:
        assert any("this account is in docker" in d for d in details)
    assert any("may be entered by every account" in d for d in details)
    assert any("still holds database.api_password, database.owner_password" in d for d in details)
    assert not any(v in " ".join(details) for v in SECRET_VALUES.values())


def test_names_lists_every_credential(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["names"]) == 0
    assert capsys.readouterr().out.split() == custody.all_credentials()


def test_import_main_check_exit_codes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    source, etc = checkout(tmp_path), tmp_path / "etc"
    assert main(["import", "--checkout", str(source), "--etc", str(etc), "--check"]) == 1
    assert main(["import", "--checkout", str(source), "--etc", str(etc)]) == 0
    assert main(["import", "--checkout", str(source), "--etc", str(etc), "--check"]) == 0
    out = capsys.readouterr().out
    assert not any(v in out for v in SECRET_VALUES.values())


def test_every_account_is_known_to_the_units() -> None:
    used = {account for account, _ in UNITS.values() if account is not None}
    assert used == set(ACCOUNTS)


def test_the_import_never_follows_a_link_out_of_the_checkout(tmp_path: Path) -> None:
    """It runs as root: a link planted in the checkout must not copy a root-only file into a
    credential (or argus.env) that a service account is then given."""
    source, etc = checkout(tmp_path), tmp_path / "etc"
    outside = tmp_path / "root-only"
    outside.mkdir()
    (outside / "shadow").write_text("Synthetic-Root-Only-88\n")
    (source / "data" / "tls" / "argus.key").unlink()
    (source / "data" / "tls" / "argus.key").symlink_to(outside / "shadow")
    shutil.rmtree(source / "data" / "certs")
    (source / "data" / "certs").symlink_to(outside)  # a folder on the way
    (outside / "siem-ca.crt").write_text("Synthetic-Root-Only-88\n")
    report = import_checkout(source, etc, check=False)
    assert not (etc / "credentials" / "web-tls.key").exists()
    assert not (etc / "certs" / "siem-ca.crt").exists()
    assert "web-tls.key" in report.missing
    text = everything_printed(report)
    assert "leads out of the checkout: not read" in text
    assert "Synthetic-Root-Only-88" not in text
    # a link inside the checkout is refused as well: a credential is a file of its own
    (source / "data" / "tls" / "argus.key").unlink()
    (source / "data" / "tls" / "real.key").write_text("Synthetic-TLS-Key\n")
    (source / "data" / "tls" / "argus.key").symlink_to("real.key")
    report = import_checkout(source, etc, check=False)
    assert "credential web-tls.key: data/tls/argus.key is a symbolic link: not read" in report.lines


def test_a_linked_dotenv_is_not_read(tmp_path: Path) -> None:
    source, etc = checkout(tmp_path), tmp_path / "etc"
    (tmp_path / "elsewhere.env").write_text((source / ".env").read_text())
    (source / ".env").unlink()
    (source / ".env").symlink_to(tmp_path / "elsewhere.env")
    report = import_checkout(source, etc, check=False)
    assert report.missing == [".env"]
    assert not (etc / "credentials").exists()


def test_an_import_that_crashes_is_never_read_as_pending(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def boom(*args: object, **kwargs: object) -> None:
        raise PermissionError("denied")

    monkeypatch.setattr(custody, "import_checkout", boom)
    assert main(["import", "--checkout", str(tmp_path), "--check"]) == 4
    assert "import failed: PermissionError: denied" in capsys.readouterr().err


TRUSTED = ("argus.env", "certs/siem-ca.crt", "tls/argus.crt", "data/asset_map.yaml")


def _snapshot(etc: Path) -> dict[str, bytes]:
    return {name: (etc / name).read_bytes() for name in TRUSTED}


def test_a_changed_setting_or_trust_file_is_kept_until_reviewed_and_accepted(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Review F2: argus.env (where each service connects) and the trust files (the CA it
    trusts, the web's certificate, the asset map) are never replaced silently from the
    operator's checkout, which any process of that account can change. A later difference is
    shown (settings by name and value, files by sha256) and kept; only the digest printed with
    it takes exactly what was shown."""
    source, etc = checkout(tmp_path), tmp_path / "etc"
    first = import_checkout(source, etc, check=False)
    assert "argus.env: ARGUS_DATABASE__HOST = '127.0.0.1'" in first.lines  # shown when written
    before = _snapshot(etc)
    env = (source / ".env").read_text()
    env = env.replace("ARGUS_DATABASE__HOST=127.0.0.1", "ARGUS_DATABASE__HOST=203.0.113.9")
    env = env.replace("ARGUS_BACKUP__BEFORE_MIGRATION=true\n", "")
    (source / ".env").write_text(env + "ARGUS_SIEM__URL=https://198.51.100.7:9200\n")
    (source / "data" / "certs" / "siem-ca.crt").write_text("planted ca\n")
    (source / "data" / "assets" / "asset_map.yaml").write_text("assets: [planted]\n")

    for check in (True, False):
        report = import_checkout(source, etc, check=check)
        assert _snapshot(etc) == before
        text = everything_printed(report)
        assert "argus.env: ARGUS_DATABASE__HOST '127.0.0.1' -> '203.0.113.9'" in text
        assert "argus.env: ARGUS_SIEM__URL added 'https://198.51.100.7:9200'" in text
        assert "argus.env: ARGUS_BACKUP__BEFORE_MIGRATION removed (was 'true')" in text
        for data in (b"ca\n", b"planted ca\n"):
            assert hashlib.sha256(data).hexdigest() in text
        assert report.kept == ["argus.env", "certs/siem-ca.crt", "data/asset_map.yaml"]
        assert report.digest() is not None
        assert f"--accept-settings {report.digest()}" in text
        assert report.pending >= 3
        for value in SECRET_VALUES.values():
            assert value not in text
    digest = report.digest()
    assert digest is not None
    args = ["import", "--checkout", str(source), "--etc", str(etc)]
    assert main(args) == 1  # a run that kept a difference is not finished
    assert main([*args, "--check"]) == 1
    capsys.readouterr()

    wrong = import_checkout(source, etc, check=False, accept="0" * 16)
    assert _snapshot(etc) == before
    assert any("nothing taken" in line for line in wrong.lines)

    # the checkout changes after the review: the reviewed digest no longer takes anything
    (source / "data" / "certs" / "siem-ca.crt").write_text("planted again\n")
    late = import_checkout(source, etc, check=False, accept=digest)
    assert _snapshot(etc) == before
    assert any("nothing taken" in line for line in late.lines)
    (source / "data" / "certs" / "siem-ca.crt").write_text("planted ca\n")

    assert main([*args, "--accept-settings", digest]) == 0
    assert "ARGUS_DATABASE__HOST='203.0.113.9'" in (etc / "argus.env").read_text()
    assert "ARGUS_BACKUP__BEFORE_MIGRATION" not in (etc / "argus.env").read_text()
    assert (etc / "certs" / "siem-ca.crt").read_text() == "planted ca\n"
    assert stat.S_IMODE((etc / "certs" / "siem-ca.crt").stat().st_mode) == 0o644
    assert stat.S_IMODE((etc / "argus.env").stat().st_mode) == 0o640
    assert import_checkout(source, etc, check=True).pending == 0


def test_a_loosened_trust_file_is_put_back_without_a_review(tmp_path: Path) -> None:
    source, etc = checkout(tmp_path), tmp_path / "etc"
    import_checkout(source, etc, check=False)
    (etc / "argus.env").chmod(0o666)
    report = import_checkout(source, etc, check=False)
    assert report.kept == []
    assert stat.S_IMODE((etc / "argus.env").stat().st_mode) == 0o640


def test_a_secret_setting_in_an_installed_argus_env_is_never_shown(tmp_path: Path) -> None:
    source, etc = checkout(tmp_path), tmp_path / "etc"
    import_checkout(source, etc, check=False)
    with (etc / "argus.env").open("a") as env:  # put there by hand: shown by name only
        env.write("ARGUS_SIEM__API_KEY='Synthetic-Hand-55'\n")
    report = import_checkout(source, etc, check=True)
    text = everything_printed(report)
    assert "ARGUS_SIEM__API_KEY" in text
    assert "Synthetic-Hand-55" not in text


def test_the_review_lines_for_edge_cases(tmp_path: Path) -> None:
    source, etc = checkout(tmp_path), tmp_path / "etc"
    import_checkout(source, etc, check=False)
    nothing = import_checkout(source, etc, check=False, accept="0123456789abcdef")
    assert "--accept-settings: no difference to take" in nothing.lines
    assert nothing.digest() is None
    env = etc / "argus.env"
    env.write_bytes(env.read_bytes() + b"# a comment by hand\n")
    comments = import_checkout(source, etc, check=True)
    assert "argus.env: only its comments or layout differ" in comments.lines
    env.write_bytes(env.read_bytes() + b"ARGUS_DATABASE__NAME='a\x1b[2Jb'\n")
    shown = everything_printed(import_checkout(source, etc, check=True))
    assert "\x1b" not in shown
    assert "ARGUS_DATABASE__NAME 'a\\x1b[2Jb' -> 'argus'" in shown
    # accepted in a check run: shown as to replace, nothing written
    digest = import_checkout(source, etc, check=True).digest()
    before = env.read_bytes()
    report = import_checkout(source, etc, check=True, accept=digest)
    assert "argus.env: to replace (accepted)" in report.lines
    assert report.kept == []
    assert env.read_bytes() == before
    assert "argus.env: replaced (accepted)" in import_checkout(source, etc, check=False,
                                                              accept=digest).lines  # fmt: skip
    (etc / "certs" / "siem-ca.crt").chmod(0o600)
    check = import_checkout(source, etc, check=True)
    assert "certs/siem-ca.crt: mode 0644 to put back" in check.lines
    assert stat.S_IMODE((etc / "certs" / "siem-ca.crt").stat().st_mode) == 0o600

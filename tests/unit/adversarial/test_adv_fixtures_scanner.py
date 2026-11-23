"""Adversarial attack on R2's leak scanner and the verify/denylist pipeline (lens FXB).

Targets: ``argus.fixtures.leakscan.LeakScanner``, the last line of defence (whatever the sanitizer
misses, it must catch); ``build``, ``asset_identifiers``, ``iter_corpus``, ``cmd_verify`` and
``cmd_samples`` in scripts/sanitize_fixtures.py; and the fixture step of scripts/hooks/pre-commit.

Conventions, as in the sibling adversarial files: a docstring starting with **DEFECT** marks a test
that fails on the current code on purpose and passes once the hole is closed; **LOCK-IN** tests
pass today and pin behaviour that held up under attack. All data is synthetic (documentation and
private address ranges, example domains, the key ``b"k" * 32``). The script and the hook are loaded
with their module-level paths pointed at ``tmp_path``: nothing under reference/ or data/ is read,
the committed fixtures are never rewritten, and nothing here touches the network.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import gzip
import importlib.machinery
import importlib.util
import io
import ipaddress
import json
import random
import string
import subprocess
import time
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml
from hypothesis import example, given
from hypothesis import strategies as st

from argus.fixtures import Leak, LeakScanner, Sanitizer
from argus.fixtures.ipmap import IPMapper
from tests.conftest import REPO_ROOT

KEY = b"k" * 32
SCRIPT = REPO_ROOT / "scripts" / "sanitize_fixtures.py"
HOOK = REPO_ROOT / "scripts" / "hooks" / "pre-commit"
IP = "10.1.2.3"
HOST = "secret-hostname-x9"
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
        self.mod = _load(SCRIPT, f"adv_fxb_sanitize_fixtures_{Env._count}")
        key = root / "data" / "keys" / "fixtures.key"
        key.parent.mkdir(parents=True)
        key.write_text(base64.b64encode(KEY).decode() + "\n")
        self.mod.ROOT = root
        self.mod.KEY_PATH = key
        self.mod.POLICY_PATH = root / "config" / "fixtures.yaml"
        self.mod.ASSETS_PATH = root / "data" / "assets" / "asset_map.yaml"
        self.mod.SAMPLES = []
        self.mod.OUT_DIR = root / "tests" / "fixtures" / "alerts"
        self.policy()

    def policy(self, **override: Any) -> None:
        data: dict[str, Any] = {
            "site_prefixes": [SITE],
            "own_domains": ["campus.example.edu"],
            "keep_domains": ["example.org", "github.com"],
            "literals": {"Campus University": "Example University"},
            "fields": {
                "host": ["host.name"],
                "user": ["user.name"],
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

    def sample(self, source: dict[str, Any], name: str | None = None) -> Path:
        index = len(self.mod.SAMPLES)
        path = self.root / "reference" / (name or f"alert{index}.json")
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

    def raw(self) -> list[dict[str, Any]]:
        return [self.mod.wire(json.loads(p.read_text())) for p in self.mod.SAMPLES]

    def build(self) -> tuple[Sanitizer, LeakScanner, int]:
        result: tuple[Sanitizer, LeakScanner, int] = self.mod.build(self.raw())
        return result

    def write(self, rel: str, text: str) -> Path:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path

    def fixture_of_last_sample(self, rel: str = "tests/fixtures/alerts/f.json") -> Path:
        """What ``samples`` writes for the newest sample (same build, same serialization)."""
        raw = self.raw()
        sanitizer, _, _ = self.mod.build(raw)
        clean = sanitizer.sanitize(raw[-1])
        return self.write(rel, json.dumps(clean, indent=2, sort_keys=True, ensure_ascii=False))

    def verify(self, *files: Path) -> int:
        return int(self.mod.cmd_verify(argparse.Namespace(files=[str(f) for f in files])))

    def samples(self, out: Path | str | None = None) -> int:
        target = str(out if out is not None else self.mod.OUT_DIR)
        return int(self.mod.cmd_samples(argparse.Namespace(out=target)))


@pytest.fixture
def env(tmp_path: Path) -> Env:
    return Env(tmp_path / "repo")


def _scan_json(tmp_path: Path, scanner: LeakScanner, value: Any) -> list[Leak]:
    path = tmp_path / "f.json"
    path.write_text(json.dumps(value, ensure_ascii=False))
    return scanner.scan_file(path)


def _preimage_in_10_8(target: str) -> str:
    """The 10/8 address that the fixture IP map (key ``KEY``) sends to ``target``.

    Inverts the Crypto-PAn style permutation bit by bit: output bit i = input bit i XOR a PRF of
    the input's first i bits, and the first 8 bits (the class region) are kept.
    """
    mapper = IPMapper(KEY, [SITE])
    # Revised with FXC-01..07: each class region has its own (re-keyed) PRF domain.
    mapper.map_text("10.0.0.1")
    domain = next(d for base, d in mapper._domains.items() if base.startswith(b"class|\x0a"))
    out, bits, keep = int(ipaddress.IPv4Address(target)), 32, 8
    value = (out >> (bits - keep)) << (bits - keep)
    for i in range(keep, bits):
        prf = mapper._prf_bit(domain, i, value >> (bits - i), bits)
        value |= (((out >> (bits - 1 - i)) & 1) ^ prf) << (bits - 1 - i)
    source = str(ipaddress.IPv4Address(value))
    assert source != target
    assert mapper.map_text(source) == target
    return source


def _verify_planted(env: Env, fixture: Path, form: str) -> int:
    """Revised with the fixes: the sanitizer now maps ``form`` itself, so the end-to-end
    precondition ("the sanitizer missed it") no longer holds. The miss is planted by hand to prove
    that verify still catches it; the sanitizer side is pinned by the FXA tests."""
    text = fixture.read_text()
    assert form not in text, "the sanitizer still misses this form"
    fixture.write_text(text.replace('"_index"', f'"planted": "{form}", "_index"', 1))
    return env.verify(fixture)


# ====================================================================== FXB-01 (HIGH)
# IPv4 identifiers use the IPv6 boundaries: a ':' or hex letter before, or ':<digit>' after, hides
# them. "10.1.2.3:443" is the commonest way an address appears in proxy and firewall logs.


@pytest.mark.parametrize(
    "text",
    [
        "conn 10.1.2.3:443 established",
        "next=http://10.1.2.3:8080/admin",
        "client:10.1.2.3 refused",
        "from ::ffff:10.1.2.3 (mapped)",
        "next=http%3A%2F%2F10.1.2.3%3A8080%2Fadmin",  # raw: glued to 'F'; decoded: ':8080' after
        "q=host%3A10.1.2.3",  # raw: glued to 'A'; decoded: ':' before
    ],
)
def test_fxb01_ipv4_next_to_a_colon_or_port_is_found(tmp_path: Path, text: str) -> None:
    """DEFECT FXB-01: a denylisted IPv4 address followed by ``:port`` or preceded by ':' / an
    encoded '%3A' / '%2F' is not reported in any form (raw, JSON or URL-decoded)."""
    assert _scan_json(tmp_path, LeakScanner({IP}), {"m": text})


@given(ip=st.ip_addresses(v=4, network="10.0.0.0/8"), port=st.integers(0, 65535))
@example(ip=ipaddress.IPv4Address(IP), port=443)
def test_fxb01_property_every_ip_port_pair_is_found(ip: ipaddress.IPv4Address, port: int) -> None:
    """DEFECT FXB-01 (property): ``<denylisted IPv4>:<port>`` is always reported."""
    assert LeakScanner({str(ip)}).scan_text(f"dst {ip}:{port}")


def test_fxb01_end_to_end_redirect_target_passes_verify(env: Env) -> None:
    """DEFECT FXB-01 (end to end): a proxy URL whose query carries an encoded redirect to an
    internal ``ip:port`` keeps the raw address (the sanitizer's IPv4 regex refuses a match glued
    to the 'F' of '%2F'), and ``verify`` still passes the fixture although it is denylisted."""
    env.sample(
        {
            "source": {"ip": IP},
            "url": {
                "original": "http://portal.example.org/login?next=http%3A%2F%2F10.1.2.3%3A8080%2F"
            },
        }
    )
    fixture = env.fixture_of_last_sample()
    assert _verify_planted(env, fixture, IP) == 1


# ====================================================================== FXB-02 (MEDIUM)


def test_fxb02_scanner_scales_to_a_corpus_sized_denylist(tmp_path: Path) -> None:
    """DEFECT FXB-02: one regex alternation of 40,000 identifiers is tried at every position of the
    text, so scanning is O(text x denylist). The real denylist is ~39k entries; a 1 MB fixture
    (a cassette) must take seconds, not minutes (projected here from a 25 kB file)."""
    rng = random.Random(0)
    ids: set[str] = set()
    while len(ids) < 20_000:
        ids.add(f"10.{rng.randrange(256)}.{rng.randrange(256)}.{rng.randrange(256)}")
    while len(ids) < 36_000:
        ids.add("".join(rng.choices(string.ascii_lowercase, k=rng.randrange(5, 14))) + "-pc")
    while len(ids) < 40_000:
        ids.add("".join(rng.choices(string.ascii_uppercase, k=rng.randrange(2, 5))))
    words = ["GET", "TCP_MISS/200", "http://cdn.example.org/a.js", "198.51.100.7", "proxy", "ok"]
    text = " ".join(rng.choice(words) for _ in range(5_000))[:25_000]
    path = tmp_path / "big.json"
    path.write_text(json.dumps({"event": {"original": text}}))
    start = time.perf_counter()
    scanner = LeakScanner(ids)
    built = time.perf_counter() - start
    start = time.perf_counter()
    scanner.scan_file(path)
    per_byte = (time.perf_counter() - start) / path.stat().st_size
    projected = built + per_byte * 1_000_000
    assert projected < 5.0, f"projected {projected:.0f} s for a 1 MB fixture"


# ====================================================================== FXB-03 (MEDIUM)


@pytest.mark.parametrize(
    "text",
    [
        "https://search.example.com/?q=Campus+University+hostel+wifi",
        "q=Campus+University",
        "q=campus+university%2Bfees",
    ],
)
def test_fxb03_plus_encoded_spaces_are_decoded(tmp_path: Path, text: str) -> None:
    """DEFECT FXB-03: a multi-word identifier (the campus-name literal, a building or department
    name) in a URL query string with '+' for space is never decoded (``unquote`` keeps '+'), so
    proxy-log search URLs carry it past the scanner (and past the sanitizer's literal pass)."""
    assert _scan_json(tmp_path, LeakScanner({"Campus University"}), {"url": {"original": text}})


# ====================================================================== FXB-04 (MEDIUM)


def test_fxb04_asset_map_names_reach_the_denylist(env: Env) -> None:
    """DEFECT FXB-04: ``build`` keeps an asset-map entry only if ``map_text(entry) != entry``. A
    name changes under ``map_text`` only when it is already a harvested dictionary entry, so asset
    names never add anything: a network name absent from the raw fields is not denylisted."""
    env.assets([{"name": "Dorm-Q-WingZ", "range": "10.20.0.0/16"}])
    env.sample({"source": {"ip": "10.20.3.4"}, "message": "port scan from hostel network"})
    _, scanner, _ = env.build()
    assert scanner.scan_text("port scan from Dorm-Q-WingZ")


def test_fxb04_end_to_end_asset_name_in_reason_passes_verify(env: Env) -> None:
    """DEFECT FXB-04 (end to end): an asset-map network name in alert text survives the sanitizer
    (it is in no identifier field) and ``verify`` passes the fixture."""
    env.assets([{"name": "Dorm-Q-WingZ", "range": "10.20.0.0/16"}])
    env.sample({"kibana.alert.reason": "port scan from Dorm-Q-WingZ (10.20.3.4)"})
    fixture = env.fixture_of_last_sample()
    assert _verify_planted(env, fixture, "Dorm-Q-WingZ") == 1


# ====================================================================== FXB-05 (MEDIUM)


@pytest.mark.parametrize(
    ("source", "survivor"),
    [
        (  # postfix: the address in one line, the SASL login (its local part) in another
            {
                "user": {"email": "alice.smith@campus.example.edu"},
                "message": "postfix/smtpd: client=x, sasl_method=LOGIN, sasl_username=alice.smith",
            },
            "alice.smith",
        ),
        (  # URL userinfo is pseudonymized inside the URL but never harvested
            {
                "url": {"original": "ftp://bob.jones:pw@files.example.net/x"},
                "message": "bob.jones uploaded 3 files",
            },
            "bob.jones",
        ),
    ],
)
def test_fxb05_email_local_parts_and_url_users_are_denylisted(
    env: Env, source: dict[str, Any], survivor: str
) -> None:
    """DEFECT FXB-05: only the whole e-mail address and the URL host are harvested. The local part
    (a login name) and the URL user are pseudonymized where they sit, but are neither in the
    sanitizer dictionary nor in the denylist, so the same name elsewhere passes both layers."""
    env.sample(source)
    fixture = env.fixture_of_last_sample()
    assert _verify_planted(env, fixture, survivor) == 1


# ====================================================================== pre-commit harness


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)  # noqa: S603, S607


@pytest.fixture
def hook_repo(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Path, Callable[[], int], list[list[str]]]:
    """A throwaway git repo, the real hook, and its ``verify`` call run in-process against
    synthetic raw sources (instead of ``uv run`` in the repo)."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    env = Env(repo)
    env.sample({"host": {"name": HOST}})
    monkeypatch.chdir(repo)
    hook = _load(HOOK, "adv_fxb_pre_commit")
    hook.ROOT = repo
    calls: list[list[str]] = []
    real_run = subprocess.run

    def fake_run(cmd: Any, *args: Any, **kwargs: Any) -> Any:
        if isinstance(cmd, list) and "scripts/sanitize_fixtures.py" in cmd:
            files = cmd[cmd.index("verify") + 1 :]
            calls.append(files)
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = env.verify(*(Path(kwargs["cwd"]) / f for f in files))
            return subprocess.CompletedProcess(cmd, code, out.getvalue(), err.getvalue())
        return real_run(cmd, *args, **kwargs)

    monkeypatch.setattr(hook.subprocess, "run", fake_run)
    return repo, hook.main, calls


def test_lockin_hook_refuses_a_staged_leaky_fixture(
    hook_repo: tuple[Path, Callable[[], int], list[list[str]]],
) -> None:
    """LOCK-IN: a staged .json fixture that leaks a denylisted host name is refused (also proves
    the harness: the hook's verify step really runs against the synthetic sources)."""
    repo, main, calls = hook_repo
    rel = "tests/fixtures/alerts/a.json"
    (repo / rel).parent.mkdir(parents=True)
    (repo / rel).write_text(json.dumps({"m": f"relayed by {HOST}"}))
    _git(repo, "add", rel)
    assert main() == 1
    assert calls == [[rel]]


def test_fxb06_hook_verifies_the_staged_blob_not_the_working_tree(
    hook_repo: tuple[Path, Callable[[], int], list[list[str]]],
) -> None:
    """DEFECT FXB-06: the hook passes file NAMES to ``verify``, which reads the working tree. A
    leaky fixture that is staged and then cleaned (or regenerated) only in the working tree is
    committed: the hook must scan the staged content (``git show :path``)."""
    repo, main, _ = hook_repo
    rel = "tests/fixtures/alerts/a.json"
    (repo / rel).parent.mkdir(parents=True)
    (repo / rel).write_text(json.dumps({"m": f"relayed by {HOST}"}))
    _git(repo, "add", rel)
    (repo / rel).write_text(json.dumps({"m": "relayed by h-abcdefgh"}))
    assert main() == 1


# ====================================================================== FXB-07 (MEDIUM)


@pytest.mark.parametrize("rel", ["tests/fixtures/cassettes/search.jsonl", "tests/fixtures/x.yaml"])
def test_fxb07_hook_scans_fixtures_that_are_not_dot_json(
    hook_repo: tuple[Path, Callable[[], int], list[list[str]]], rel: str
) -> None:
    """DEFECT FXB-07: the hook verifies only staged ``tests/fixtures/**.json``; a JSON Lines
    cassette or a YAML fixture under tests/fixtures/ is committed without a leak scan."""
    repo, main, _ = hook_repo
    (repo / rel).parent.mkdir(parents=True)
    (repo / rel).write_text(json.dumps({"m": f"relayed by {HOST}"}) + "\n")
    _git(repo, "add", rel)
    assert main() == 1


@pytest.mark.parametrize("suffix", [".jsonl", ".ndjson", ".yaml", ".txt"])
def test_fxb07_default_verify_scans_every_fixture_file(env: Env, suffix: str) -> None:
    """DEFECT FXB-07: ``verify`` with no arguments globs only ``tests/fixtures/**/*.json``."""
    env.sample({"host": {"name": HOST}})
    env.write(f"tests/fixtures/cassettes/c{suffix}", f'{{"m": "relayed by {HOST}"}}\n')
    assert env.verify() == 1


# ====================================================================== FXB-08 (MEDIUM)


def test_fxb08_identifier_kept_in_one_context_stays_denylisted(env: Env) -> None:
    """DEFECT FXB-08: ``build`` subtracts ``sanitizer.unchanged`` globally. During harvest an
    email-kind field without '@' goes through ``map_text`` before the dictionary exists, so a login
    name there is recorded as "kept" - and removed from the denylist although it is harvested
    (and pseudonymized) as user.name. Its case variant then survives the sanitizer AND verify."""
    env.sample(
        {
            "user": {"name": "asmith42", "email": "asmith42"},
            "message": "Failed password for ASMITH42 from 10.1.2.3",
        }
    )
    fixture = env.fixture_of_last_sample()
    assert _verify_planted(env, fixture, "ASMITH42") == 1


def test_fxb08_explicit_denylist_extra_is_never_subtracted(env: Env) -> None:
    """DEFECT FXB-08: a ``denylist_extra`` entry ("must never appear in fixtures") is dropped when
    it is also in ``unchanged`` (here: the bare value of an email-kind field)."""
    env.policy(denylist_extra=["logserver-x9"])
    env.sample({"user": {"email": "logserver-x9"}})
    _, scanner, _ = env.build()
    assert scanner.scan_text("forwarded by logserver-x9")


# ====================================================================== FXB-09 (MEDIUM)


def test_lockin_samples_exits_nonzero_on_a_leak(env: Env) -> None:
    """LOCK-IN: ``samples`` returns 1 when a fixture it wrote leaks a denylisted identifier."""
    env.policy(denylist_extra=[HOST])
    env.sample({"message": f"relayed by {HOST}"})
    assert env.samples() == 1


def test_fxb09_samples_leaves_no_leaky_fixture_on_disk(env: Env) -> None:
    """DEFECT FXB-09: ``samples`` writes every fixture and MANIFEST.json into the tracked
    tests/fixtures/alerts/ (overwriting the clean ones) BEFORE it scans them, and leaves them there
    when the scan fails; it should write to a staging directory and move only clean output."""
    env.policy(denylist_extra=[HOST])
    env.sample({"message": f"relayed by {HOST}"})
    assert env.samples() == 1
    written = [p for p in env.mod.OUT_DIR.rglob("*") if p.is_file()]
    assert not [p.name for p in written if HOST in p.read_text()]


# ====================================================================== FXB-10 (LOW)


def test_fxb10_real_address_equal_to_a_pseudonym_stays_detectable(env: Env) -> None:
    """DEFECT FXB-10: a real address that equals another real address's pseudonym is dropped as
    "ambiguous". The map is a permutation inside 10/8, so this happens on a large corpus; a
    sanitizer miss of that address (glued to '_') then passes verify."""
    other = _preimage_in_10_8(IP)  # map(other) == IP
    env.sample(
        {"source": {"ip": other}, "destination": {"ip": IP}, "message": f"peer host_{IP} up"}
    )
    fixture = env.fixture_of_last_sample()
    assert _verify_planted(env, fixture, f"host_{IP}") == 1


def test_fxb10_explicit_denylist_extra_is_never_ambiguous(env: Env) -> None:
    """DEFECT FXB-10: a ``denylist_extra`` address (e.g. the SIEM's own IP) is silently dropped
    when some raw address happens to map onto it; an explicit entry must stay (or fail loudly)."""
    env.policy(denylist_extra=["10.9.8.7"])
    env.sample({"source": {"ip": _preimage_in_10_8("10.9.8.7")}})
    _, scanner, ambiguous = env.build()
    assert ambiguous == 1
    assert scanner.scan_text("siem at 10.9.8.7")


# ====================================================================== FXB-11 (LOW)


@pytest.mark.parametrize(
    ("ident", "text"),
    [
        ("2001:db8::5", "src 2001:DB8::5"),
        ("2001:db8::5", "src 2001:0db8:0000:0000:0000:0000:0000:0005"),
        ("2001:db8::5", "src 2001:db8::0005"),
        ("2001:DB8::5", "src 2001:db8::5"),
        (IP, "src 010.001.002.003"),
    ],
)
def test_fxb11_non_canonical_address_forms_are_found(ident: str, text: str) -> None:
    """DEFECT FXB-11: addresses are matched as literal text, case-sensitively: another spelling of
    a denylisted address (case, expanded IPv6, leading zeros, zero-padded IPv4) is not found."""
    assert LeakScanner({ident}).scan_text(text)


def test_fxb11_end_to_end_zero_padded_ipv4(env: Env) -> None:
    """DEFECT FXB-11 (end to end): ``ipaddress`` rejects leading zeros, so the sanitizer leaves
    "010.001.002.003" verbatim, and verify passes it although 10.1.2.3 is denylisted."""
    env.sample({"source": {"ip": IP}, "message": "deny src=010.001.002.003 dst=198.51.100.7"})
    fixture = env.fixture_of_last_sample()
    assert _verify_planted(env, fixture, "010.001.002.003") == 1


# ====================================================================== FXB-12 (LOW)


@pytest.mark.parametrize(
    ("ident", "value"),
    [
        (IP, {"m": "10&#46;1&#46;2&#46;3"}),
        (IP, {"m": "10&#x2e;1&#x2e;2&#x2e;3"}),
        (IP, {"m": r"10\x2e1\x2e2\x2e3"}),
        (IP, {"m": "q=10%25252E1%25252E2%25252E3"}),
        ("CAMPUS\\alice", {"event": {"original": json.dumps({"user": "CAMPUS\\alice"})}}),
        ("café-lab7", {"event": {"original": json.dumps({"host": "café-lab7"})}}),
    ],
)
def test_fxb12_other_encodings_are_decoded(tmp_path: Path, ident: str, value: Any) -> None:
    """DEFECT FXB-12: HTML entities, ``\\x`` escapes, triple %-encoding and a JSON document nested
    in a JSON string (event.original) are not decoded, so an identifier in those forms passes."""
    assert _scan_json(tmp_path, LeakScanner({ident}), value)


# ====================================================================== FXB-13 (LOW)


@pytest.mark.parametrize(("ident", "text"), [("ws12", "logon from WS12"), ("LAB7", "lab7 up")])
def test_fxb13_short_host_like_names_ignore_case(ident: str, text: str) -> None:
    """DEFECT FXB-13: names under 5 characters are matched case-sensitively (meant for codes such
    as "EE"); short host names with a digit ("ws12" / "WS12") are not caught in another case."""
    assert LeakScanner({ident}).scan_text(text)


# ====================================================================== FXB-14 (LOW)


@pytest.mark.parametrize(
    "content",
    [
        '﻿{"a": "host 10\\u002e1.2.3"}',  # UTF-8 BOM: json.loads refuses it
        '{"a": "ok"}\n{"a": "host 10\\u002e1.2.3"}\n',  # JSON Lines
        '{"a": "host 10\\u002e1.2.3", "a": "ok"}',  # duplicate key: only the last value is kept
    ],
)
def test_fxb14_escaped_identifiers_in_any_json_file_shape(tmp_path: Path, content: str) -> None:
    """DEFECT FXB-14: ``\\u`` escapes are decoded only when the whole file is one JSON document
    without a BOM, and only for the last of duplicate keys; otherwise the escaped form passes."""
    path = tmp_path / "f.json"
    path.write_text(content, encoding="utf-8")
    assert LeakScanner({IP}).scan_file(path)


# ====================================================================== FXB-15 (LOW)


def test_fxb15_any_address_inside_a_site_prefix_is_a_leak(env: Env) -> None:
    """DEFECT FXB-15: site-prefix addresses always move to 198.18.0.0/15, so ANY address inside a
    site prefix in a fixture is a leak - but verify only knows harvested strings, and an address
    the harvest missed too (glued to '_') passes."""
    env.sample({"source": {"ip": "198.51.100.7"}, "message": "relay via gw_192.0.2.77 ok"})
    fixture = env.fixture_of_last_sample()
    assert _verify_planted(env, fixture, "gw_192.0.2.77") == 1


# ====================================================================== FXB-16 (LOW)


@pytest.mark.parametrize(
    ("network", "expected"),
    [
        ({"name": "LabNet-A", "ranges": "10.22.1.7"}, "10.22.1.7"),  # string, split into chars
        ({"name": "LabNet-B", "ranges": "10.22.0.0/16"}, "10.22.0.0/16"),  # crashes on "/"
        ({"name": "LabNet-C", "range": "10.23.0.0/16", "ranges": ["10.24.0.0/16"]}, "10.24.0.0/16"),
        ({"name": "EE", "range": "10.21.0.0/16"}, "EE"),
    ],
)
def test_fxb16_asset_identifiers_reads_every_entry(
    env: Env, network: dict[str, Any], expected: str
) -> None:
    """DEFECT FXB-16: a string ``ranges`` is iterated character by character (and raises on '/'),
    ``ranges`` is ignored when ``range`` is also set, and 2-letter names (department codes, which
    the scanner matches exactly) are dropped."""
    env.assets([network])
    assert expected in env.mod.asset_identifiers()


def test_lockin_asset_identifiers_ipv6_and_list_ranges(env: Env) -> None:
    """LOCK-IN: list ``ranges``, IPv6 ranges and their network addresses are all collected."""
    env.assets([{"name": "Lab-V6", "ranges": ["2001:db8:42::/48", "10.30.0.0/16"]}])
    assert set(env.mod.asset_identifiers()) == {
        "2001:db8:42::/48",
        "2001:db8:42::",
        "10.30.0.0/16",
        "10.30.0.0",
        "Lab-V6",
    }


# ====================================================================== FXB-17 (LOW)


def test_fxb17_leak_repr_hides_the_identifier() -> None:
    """DEFECT FXB-17: ``Leak.__str__`` hides the identifier but the dataclass ``repr`` prints it,
    e.g. in pytest's diff for ``assert scanner.scan_file(p) == []`` or ``print(leaks)``."""
    assert HOST not in repr(Leak("f.json", HOST, "raw"))
    assert HOST not in repr([Leak("f.json", HOST, "raw")])


def test_fxb17_verify_never_prints_a_leaking_file_name(
    env: Env, capsys: pytest.CaptureFixture[str]
) -> None:
    """DEFECT FXB-17: for a leak in a file NAME, verify prints ``LEAK <path>: ...`` - the path is
    the identifier."""
    env.sample({"host": {"name": HOST}})
    fixture = env.write(f"tests/fixtures/alerts/query__{HOST}.json", '{"m": "clean"}')
    assert env.verify(fixture) == 1
    captured = capsys.readouterr()
    assert HOST not in captured.out + captured.err


# ====================================================================== FXB-18 (LOW)


def test_fxb18_verify_scans_directory_names(env: Env) -> None:
    """DEFECT FXB-18: verify scans only ``p.name``; a directory named after an identifier is
    committed too."""
    env.sample({"host": {"name": HOST}})
    fixture = env.write(f"tests/fixtures/{HOST}/alert.json", '{"m": "clean"}')
    assert env.verify(fixture) == 1


def test_fxb18_samples_scans_its_manifest(env: Env) -> None:
    """DEFECT FXB-18: ``samples`` scans neither file names nor MANIFEST.json, which records each
    raw sample's path ("reference/alert-<name>.json"): it reports 0 leaks and exits 0 while the
    manifest carries a denylisted identifier (``verify`` would catch it later)."""
    env.policy(denylist_extra=[HOST])
    env.sample({"message": "clean"}, name=f"alert-{HOST}.json")
    code = env.samples()
    manifest = (env.mod.OUT_DIR / "MANIFEST.json").read_text()
    assert code == 1 or HOST not in manifest


# ====================================================================== FXB-19 (LOW)


@pytest.mark.parametrize("where", ["outside", "relative"])
def test_fxb19_samples_out_anywhere(
    env: Env, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, where: str
) -> None:
    """DEFECT FXB-19: ``samples --out`` outside the repo, or any relative path, raises ValueError
    in the final ``out_dir.relative_to(ROOT)`` - after the files were written, before the leak
    report is printed."""
    env.sample({"message": "clean"})
    monkeypatch.chdir(env.root)
    out = tmp_path / "elsewhere" if where == "outside" else "tests/fixtures/alt"
    assert env.samples(out) == 0


# ====================================================================== FXB-20 (LOW)


def _capture(env: Env, status: str) -> None:
    day = env.root / "data" / "corpus" / "2026-01-01"
    day.mkdir(parents=True)
    (day / "manifest.json").write_text(json.dumps({"status": status}))
    doc = {"_index": "logs-x", "_id": "c1", "_source": {"host": {"name": HOST}}}
    with gzip.open(day / "alerts.jsonl.gz", "wt", encoding="utf-8") as fh:
        fh.write(json.dumps(doc) + "\n")


def test_fxb20_incomplete_capture_still_feeds_the_denylist(env: Env) -> None:
    """DEFECT FXB-20: ``iter_corpus`` skips a capture whose manifest is not "complete"; the
    identifiers in an interrupted capture are just as real and are dropped from the denylist."""
    env.sample({"message": "unrelated"})
    _capture(env, "partial")
    fixture = env.write("tests/fixtures/alerts/a.json", json.dumps({"m": f"via {HOST}"}))
    assert env.verify(fixture) == 1


def test_lockin_complete_capture_feeds_the_denylist(env: Env) -> None:
    """LOCK-IN: identifiers from a complete capture are denylisted."""
    env.sample({"message": "unrelated"})
    _capture(env, "complete")
    fixture = env.write("tests/fixtures/alerts/a.json", json.dumps({"m": f"via {HOST}"}))
    assert env.verify(fixture) == 1


# ====================================================================== FXB-21 (LOW)


def test_fxb21_mixed_case_vendor_domain_is_not_a_false_positive(env: Env) -> None:
    """DEFECT FXB-21 (false positive): "GitHub.com" is harvested (the mapper lower-cases it, so
    raw != pseudonym), and the case-insensitive scanner then flags the kept "github.com": verify
    refuses a clean fixture."""
    env.sample({"message": "fetch https://GitHub.com/org/repo/archive.zip"})
    fixture = env.fixture_of_last_sample()
    assert "https://github.com/org/repo" in fixture.read_text()
    assert env.verify(fixture) == 0


# ====================================================================== LOCK-IN: what held up


@pytest.fixture(scope="module")
def module_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return tmp_path_factory.mktemp("fxb")


@given(ip=st.ip_addresses(v=4, network="10.0.0.0/8"))
def test_lockin_hidden_forms_of_an_ipv4_are_found(
    module_dir: Path, ip: ipaddress.IPv4Address
) -> None:
    """LOCK-IN: a denylisted IPv4 is found as stored, ``\\u002e``-escaped, %2E- and %252E-encoded,
    in a value or in an object key."""
    scanner = LeakScanner({str(ip)})
    dotted = str(ip)
    forms = [
        json.dumps({"a": f"host {dotted} seen"}),
        json.dumps({"a": f"host {dotted} seen"}).replace(".", "\\u002e"),
        json.dumps({"a": "q=" + dotted.replace(".", "%2E")}),
        json.dumps({"a": "q=" + dotted.replace(".", "%252e")}),
        json.dumps({dotted: 1}),
        json.dumps({dotted: 1}).replace(".", "\\u002e"),
    ]
    path = module_dir / "hidden.json"
    for text in forms:
        path.write_text(text)
        assert scanner.scan_file(path), text


@pytest.mark.parametrize(
    "text",
    ["ip10.1.2.3x", "dst=_10.1.2.3_", "seen 10.1.2.3.", "[10.1.2.3]", "10.1.2.3/32", "x 10.1.2.3"],
)
def test_lockin_glued_ipv4_forms_that_are_found(text: str) -> None:
    """LOCK-IN: an IPv4 glued to non-hex letters or '_', with a trailing dot, bracketed or with a
    prefix length is found."""
    assert LeakScanner({IP}).scan_text(text)


@pytest.mark.parametrize(
    "text",
    ["relay SECRET-HOSTNAME-X9 ok", "relay secret-hostname-x9_old", "x.Secret-Hostname-X9.lan"],
)
def test_lockin_long_names_any_case_and_glued_to_separators(text: str) -> None:
    """LOCK-IN: names of 5+ characters are found in any case and next to '_' / '.'."""
    assert LeakScanner({HOST}).scan_text(text)


def test_lockin_regex_metacharacters_and_overlapping_identifiers() -> None:
    """LOCK-IN: identifiers are escaped (no regex injection, no catastrophic pattern), and an
    identifier that is a prefix or substring of another is still found on its own."""
    meta = "a.b*c+(x)[y]{2}|z\\d"
    scanner = LeakScanner({meta, "alice", "alice.smith", "lab7", "lab7-gw", ".*", "(?i)x"})
    assert scanner.scan_text(f"v {meta} v") == [meta]
    assert not scanner.scan_text("v aXb*c+(x)[y]{2}|z\\d v")
    assert scanner.scan_text("alice.smith") == ["alice.smith"]
    assert scanner.scan_text("to alice now") == ["alice"]
    assert set(scanner.scan_text("gw lab7-gw / lab7")) == {"lab7-gw", "lab7"}
    assert not scanner.scan_text("any text at all X")


@given(ident=st.from_regex(r"[A-Z][A-Z0-9-]{5,30}", fullmatch=True))
def test_lockin_leak_str_never_contains_the_identifier(ident: str) -> None:
    """LOCK-IN: ``str(Leak)`` (what verify and samples print) never contains the identifier."""
    for form in ("raw", "json", "url-decoded", "file name"):
        assert ident not in str(Leak("tests/fixtures/alerts/a.json", ident, form))


def test_lockin_invalid_utf8_and_plain_text_files(tmp_path: Path) -> None:
    """LOCK-IN: undecodable bytes next to an identifier and non-JSON files are still scanned."""
    scanner = LeakScanner({IP, HOST})
    binary = tmp_path / "b.json"
    binary.write_bytes(b'{"a": "\xff10.1.2.3\xfe"}')
    assert scanner.scan_file(binary)
    text = tmp_path / "t.txt"
    text.write_text(f"squid relay {HOST} 10%2E1%2E2%2E3\n")
    assert {leak.form for leak in scanner.scan_file(text)} >= {"raw", "url-decoded"}


def test_lockin_verify_exit_codes(env: Env) -> None:
    """LOCK-IN: verify exits 1 on a content leak and on a file-name leak, 0 on a clean file."""
    env.sample({"host": {"name": HOST}})
    leaky = env.write("tests/fixtures/alerts/a.json", json.dumps({"m": f"via {HOST}"}))
    clean = env.write("tests/fixtures/alerts/b.json", json.dumps({"m": "via h-abcdefgh"}))
    named = env.write(f"tests/fixtures/alerts/{HOST}.json", "{}")
    assert env.verify(leaky) == 1
    assert env.verify(clean) == 0
    assert env.verify(named) == 1


def test_lockin_verify_refuses_without_raw_sources(
    env: Env, capsys: pytest.CaptureFixture[str]
) -> None:
    """LOCK-IN: with no local raw sources verify refuses (exit 1) instead of passing vacuously."""
    clean = env.write("tests/fixtures/alerts/b.json", "{}")
    assert env.verify(clean) == 1
    assert "refusing" in capsys.readouterr().err

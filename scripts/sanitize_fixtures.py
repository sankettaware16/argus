#!/usr/bin/env python3
"""Sanitize real alerts into committed test fixtures, and verify fixtures never leak (R2, D-030).

Commands
  init-key            create data/keys/fixtures.key (32 random bytes, base64) if missing
  samples             sanitize reference/alert*.json into tests/fixtures/alerts/ + MANIFEST.json;
                      everything is scanned first and nothing is written if anything leaks
  verify [FILES...]   leak-scan fixture files and their path names (default: every file under
                      tests/fixtures/) against the denylist built from the local raw sources
                      (every capture, complete or not, and the asset map); exit 1 on any leak
  check-assets        prove x in P <=> f(x) in f(P) for every network of the local asset map
                      under the real key and policy (R2 gate); exit 1 on any violation

The key and the raw sources stay local (gitignored). The same key, policy and sources always
produce byte-identical fixtures.
"""

from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import ipaddress
import json
import os
import random
import re
import secrets
import shutil
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import yaml

from argus.config.settings import AssetsSettings
from argus.fixtures import (
    SANITIZER_VERSION,
    FixturePolicy,
    IPMapper,
    Leak,
    LeakScanner,
    Sanitizer,
    load_policy,
)

ROOT = Path(__file__).resolve().parent.parent
KEY_PATH = ROOT / "data" / "keys" / "fixtures.key"
POLICY_PATH = ROOT / "config" / "fixtures.yaml"
# The organisation's own names and ranges, laid over POLICY_PATH: the private overlay (D-294).
LOCAL_POLICY_NAME = "fixtures.local.yaml"


def configured_map_path(config_dir: Path = ROOT / "config") -> Path:
    """The asset map the installation names (``assets.map_path`` in config/local.yaml, else in
    config/argus.yaml, else the default), read without loading the settings."""
    for name in ("local.yaml", "argus.yaml"):
        path = config_dir / name
        data = yaml.safe_load(path.read_text(encoding="utf-8")) if path.is_file() else None
        assets = data.get("assets") if isinstance(data, dict) else None
        if isinstance(assets, dict) and assets.get("map_path"):
            return ROOT / str(assets["map_path"])
    return ROOT / AssetsSettings().map_path


ASSETS_PATH = configured_map_path()


def fixture_policy() -> tuple[FixturePolicy, str]:
    """The policy with its private overlay beside it, and the hash of both."""
    return load_policy(POLICY_PATH, POLICY_PATH.with_name(LOCAL_POLICY_NAME))


SAMPLES = sorted((ROOT / "reference").glob("alert*.json"))
CORPUS_FILES = ("alerts.jsonl.gz", "ancestors.jsonl.gz", "context.jsonl.gz")
OUT_DIR = ROOT / "tests" / "fixtures" / "alerts"


def load_key() -> bytes:
    if not KEY_PATH.is_file():
        sys.exit(f"missing {KEY_PATH.relative_to(ROOT)} — run: sanitize_fixtures.py init-key")
    key = base64.b64decode(KEY_PATH.read_text().strip())
    if len(key) < 32:
        sys.exit("fixture key must be at least 32 bytes")
    return key


def key_fingerprint(key: bytes) -> str:
    return hashlib.sha256(b"argus-fixtures-key|" + key).hexdigest()[:16]


def wire(doc: dict[str, Any]) -> dict[str, Any]:
    """Collector wire format: what the collector stores (Discover exports carry more)."""
    return {"_index": doc["_index"], "_id": doc["_id"], "_source": doc["_source"]}


def iter_corpus() -> Iterator[dict[str, Any]]:
    """Every captured document, complete capture or not: an interrupted capture's identifiers
    are just as real, and the denylist must know them."""
    for day_dir in sorted((ROOT / "data" / "corpus").glob("*/")):
        for name in CORPUS_FILES:
            path = day_dir / name
            if path.is_file():
                with gzip.open(path, "rt", encoding="utf-8") as fh:
                    for line in fh:
                        yield json.loads(line)


def _asset_entries() -> list[dict[str, Any]]:
    if not ASSETS_PATH.is_file():
        return []
    data = yaml.safe_load(ASSETS_PATH.read_text()) or {}
    return [n for n in data.get("networks") or [] if isinstance(n, dict)]


def _ranges(network: dict[str, Any]) -> list[str]:
    """``range`` and ``ranges`` together; either may be one value or a list."""
    out: list[str] = []
    for key in ("range", "ranges"):
        value = network.get(key)
        items = value if isinstance(value, list) else [] if value is None else [value]
        out.extend(str(item).strip() for item in items if str(item).strip())
    return out


def asset_names() -> list[str]:
    names = (n.get("name") for n in _asset_entries())
    return [name.strip() for name in names if isinstance(name, str) and len(name.strip()) >= 2]


def identifying_asset_names() -> list[str]:
    """Asset names that go on the denylist: a 2-letter code (a department abbreviation such as
    EE) is public and matches ordinary tokens (AI_Report_Writer), so it identifies nothing."""
    return [name for name in asset_names() if len(name) >= 3]


def _asset_network(text: str, index: int) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    try:
        return ipaddress.ip_network(text, strict=False)
    except ValueError:
        # Never echo the entry: names and ranges in the asset map are identifiers.
        raise ValueError(f"asset map entry #{index}: a range is not an IP network") from None


def asset_identifiers() -> list[str]:
    out: list[str] = []
    for index, network in enumerate(_asset_entries()):
        for text in _ranges(network):
            out.append(text)
            if "/" in text:
                out.append(str(_asset_network(text, index).network_address))
    return out + asset_names()


def asset_networks() -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    return [
        _asset_network(text, index)
        for index, network in enumerate(_asset_entries())
        for text in _ranges(network)
    ]


def build(raw_docs: list[dict[str, Any]]) -> tuple[Sanitizer, LeakScanner, int]:
    """The sanitizer for the corpus, the leak scanner and the count of ambiguous identifiers
    (raw values equal to some pseudonym). Nothing explicit is ever dropped from the denylist."""
    policy, _ = fixture_policy()
    sanitizer = Sanitizer(policy, load_key())
    sanitizer.harvest(raw_docs)
    names = identifying_asset_names()
    sanitizer.add_names(names)  # network names are replaced wherever they appear
    denylist = set(sanitizer.harvested) | set(names)
    every_name = set(asset_names())
    for ident in asset_identifiers():
        # A network that maps to itself (a whole private class) identifies nothing.
        if ident not in every_name and sanitizer.map_text(ident) != ident:
            denylist.add(ident)
    # The campus domains themselves, even if the raw sources never spelled them out.
    denylist |= set(policy.denylist_extra) | set(policy.literals) | set(policy.campus_domains)
    ambiguous = len(denylist & sanitizer.pseudonyms)
    return sanitizer, LeakScanner(denylist, networks=policy.site_prefixes), ambiguous


def cmd_init_key(_: argparse.Namespace) -> int:
    if KEY_PATH.exists():
        fingerprint = key_fingerprint(load_key())
        print(f"{KEY_PATH.relative_to(ROOT)} already exists (fingerprint {fingerprint})")
        return 0
    KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(KEY_PATH.parent, 0o700)
    fd = os.open(KEY_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(base64.b64encode(secrets.token_bytes(32)).decode() + "\n")
    print(f"created {KEY_PATH.relative_to(ROOT)} — back it up: fixtures need it to be regenerated")
    return 0


def slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")[:70]


def shown(path: Path) -> str:
    """A path for messages: relative to the repository when it is inside it."""
    resolved = path.resolve()
    return str(resolved.relative_to(ROOT)) if resolved.is_relative_to(ROOT) else str(resolved)


def _path_parts(path: Path) -> tuple[str, ...]:
    """The components that get committed: the path as given when relative, else relative to the
    repository (a file outside it: its name). Not resolved: a symlink's own name is what git
    stores, and its target text too (``_link_text``)."""
    if not path.is_absolute():
        return path.parts
    absolute = Path(os.path.abspath(path))
    return absolute.relative_to(ROOT).parts if absolute.is_relative_to(ROOT) else (path.name,)


def _link_text(path: Path) -> tuple[str, ...]:
    """A symlink's target as git stores it (scanned like names), dangling or not."""
    return Path(os.readlink(path)).parts if path.is_symlink() else ()


def _scan_names(scanner: LeakScanner, parts: tuple[str, ...], label: str) -> list[Leak]:
    return [Leak(label, hit, "file name") for part in parts for hit in scanner.scan_name(part)]


def _safe_label(text: str) -> str:
    return "fixture#" + hashlib.sha256(text.encode()).hexdigest()[:12]


def cmd_samples(args: argparse.Namespace) -> int:
    """Sanitize the samples in memory, scan everything that would be committed (contents, file
    names, the manifest) and write only if it is clean, replacing the directory as a whole."""
    if not SAMPLES:
        sys.exit("no reference/alert*.json samples found")
    raw = [wire(json.loads(p.read_text())) for p in SAMPLES]
    # Harvest the corpus too: the same denylist (and dictionary) as verify, so samples never
    # writes what verify would refuse. Only the samples are sanitized.
    sanitizer, scanner, ambiguous = build([*raw, *iter_corpus()])
    out_dir = Path(args.out).resolve()
    texts: dict[str, str] = {}
    files: dict[str, Any] = {}
    for path, doc in zip(SAMPLES, raw, strict=True):
        clean = sanitizer.sanitize(doc)
        # Name the file from the SANITIZED rule name: raw rule names can contain campus names.
        source = clean["_source"]
        rule_type = source.get("kibana.alert.rule.type", "unknown")
        name = f"{rule_type}__{slug(source.get('kibana.alert.rule.name', 'unnamed'))}.json"
        text = json.dumps(clean, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        if name in texts:
            sys.exit(f"two samples would both be written as {_safe_label(name)}")
        texts[name] = text
        files[name] = {
            "sha256": hashlib.sha256(text.encode()).hexdigest(),
            # The raw file's hash, not its name: sample names can carry identifiers.
            "source_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "rule_type": rule_type,
        }
    _, policy_sha = fixture_policy()
    manifest = {
        "sanitizer_version": SANITIZER_VERSION,
        "key_fingerprint": key_fingerprint(load_key()),
        "policy_sha256": policy_sha,
        "harvest_sources": [f"reference/alert*.json ({len(SAMPLES)} files)"],
        "denylist_sources": [
            "harvested identifiers",
            "the asset map (assets.map_path)",
            "config/fixtures.yaml (+ fixtures.local.yaml) denylist_extra + literals",
        ],
        "denylist_size": scanner.size,
        "ambiguous_identifiers": ambiguous,
        "files": files,
    }
    texts["MANIFEST.json"] = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    leaks: list[Leak] = []
    for name, text in texts.items():
        name_leaks = _scan_names(scanner, (name,), _safe_label(name))
        label = _safe_label(name) if name_leaks else name
        leaks += name_leaks + scanner.scan_document(text, label)
    print(
        f"sanitized {len(files)} samples; denylist {scanner.size} identifiers, {ambiguous} "
        f"ambiguous; leaks: {len(leaks)}"
    )
    if leaks:
        for leak in leaks:
            print(f"  LEAK {leak}", file=sys.stderr)
        print(f"nothing written to {shown(out_dir)}", file=sys.stderr)
        return 1
    problem = _unsafe_out_dir(out_dir)
    if problem:
        print(f"refusing --out {shown(out_dir)}: {problem}; nothing written", file=sys.stderr)
        return 1
    out_dir.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{out_dir.name}.staging-", dir=out_dir.parent))
    for name, text in texts.items():
        (staging / name).write_text(text, encoding="utf-8")
    retired = None
    if out_dir.exists():
        retired = Path(tempfile.mkdtemp(prefix=f".{out_dir.name}.old-", dir=out_dir.parent))
        out_dir.rename(retired / out_dir.name)
    staging.rename(out_dir)
    if retired is not None:
        shutil.rmtree(retired)  # only ever a fixture directory: _unsafe_out_dir checked it
    print(f"wrote {len(files)} fixtures and MANIFEST.json to {shown(out_dir)}")
    return 0


def _unsafe_out_dir(out_dir: Path) -> str | None:
    """Why ``samples`` must not replace ``out_dir`` (it deletes the old one), or None.

    Only a fixture directory may be replaced: one that does not exist yet, is empty, or holds
    exactly the files its MANIFEST.json lists. Never the repository, never anything that holds the
    key or the raw sources."""
    protected = [ROOT, KEY_PATH, ASSETS_PATH, ROOT / "data", ROOT / "reference", *SAMPLES]
    for path in protected:
        resolved = path.resolve()
        if resolved == out_dir or resolved.is_relative_to(out_dir):
            return "it holds the repository, the key or raw data"
    if not out_dir.exists():
        return None
    if not out_dir.is_dir() or out_dir.is_symlink():
        return "it is not a directory"
    present = {p.name for p in out_dir.iterdir()}
    if not present:
        return None
    try:
        listed = set(json.loads((out_dir / "MANIFEST.json").read_text())["files"])
    except (OSError, ValueError, KeyError, TypeError):
        return "it is not a fixture directory (no readable MANIFEST.json)"
    if present != listed | {"MANIFEST.json"}:
        return "it holds files its MANIFEST.json does not list"
    return None


def cmd_verify(args: argparse.Namespace) -> int:
    raw: list[dict[str, Any]] = [wire(json.loads(p.read_text())) for p in SAMPLES]
    raw.extend(iter_corpus())
    if not raw:
        print(
            "verify: no local raw sources (reference/ or data/corpus/) — cannot prove fixtures are "
            "clean, refusing",
            file=sys.stderr,
        )
        return 1
    _, scanner, ambiguous = build(raw)
    paths = [Path(p) for p in args.files] or sorted(
        p for p in (ROOT / "tests" / "fixtures").rglob("*") if p.is_file() or p.is_symlink()
    )
    leaks: list[Leak] = []
    unreadable = 0
    for path in paths:
        parts = _path_parts(path)
        safe = _safe_label("/".join(parts))
        name_leaks = _scan_names(scanner, parts + _link_text(path), safe)
        # A path that names an identifier is never printed: a hash of it stands in.
        label = safe if name_leaks else "/".join(parts)
        leaks += name_leaks
        if path.is_symlink() and not path.exists():
            continue  # a dangling link: its text was scanned, there is no content
        try:
            leaks += scanner.scan_file(path, label)
        except OSError as exc:
            unreadable += 1
            print(f"  UNREADABLE {safe}: {type(exc).__name__}", file=sys.stderr)
    print(
        f"verify: {len(paths)} files, denylist {scanner.size} identifiers ({ambiguous} ambiguous), "
        f"leaks: {len(leaks)}, unreadable: {unreadable}"
    )
    for leak in leaks:
        print(f"  LEAK {leak}", file=sys.stderr)
    return 1 if leaks or unreadable else 0


def _span(net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> tuple[int, int, int]:
    return net.version, int(net.network_address), int(net.broadcast_address)


def _relation(a: tuple[int, int, int], b: tuple[int, int, int]) -> str:
    if a[0] != b[0] or a[2] < b[1] or b[2] < a[1]:
        return "disjoint"
    if a == b:
        return "equal"
    if b[1] <= a[1] and a[2] <= b[2]:
        return "inside"
    if a[1] <= b[1] and b[2] <= a[2]:
        return "contains"
    return "overlap"  # impossible for two CIDR networks


def cmd_check_assets(args: argparse.Namespace) -> int:
    """Gate criterion: x in P <=> f(x) in f(P) for every asset network, real key and policy."""
    nets = asset_networks()
    if not nets:
        print(f"check-assets: no local asset map ({shown(ASSETS_PATH)})", file=sys.stderr)
        return 1
    policy, _ = fixture_policy()
    mapper = IPMapper(load_key(), policy.site_prefixes)
    images = [mapper.map_network(net) for net in nets]
    rng = random.Random(args.seed)  # noqa: S311 (sampling, not secrecy)
    members = outsiders = violations = 0
    for net, image in zip(nets, images, strict=True):
        first, last = int(net.network_address), int(net.broadcast_address)
        inside = {first, last} | {rng.randint(first, last) for _ in range(args.samples)}
        outside = {v for v in (first - 1, last + 1) if 0 <= v < 2**net.max_prefixlen}
        make = ipaddress.ip_address
        for value in inside:
            members += 1
            violations += mapper.map_address(make(value)) not in image
        for value in outside:
            outsiders += 1
            violations += mapper.map_address(make(value)) in image
    spans = [_span(n) for n in nets]
    image_spans = [_span(n) for n in images]
    pairs = 0
    for i in range(len(spans)):
        for j in range(i + 1, len(spans)):
            pairs += 1
            if _relation(spans[i], spans[j]) != _relation(image_spans[i], image_spans[j]):
                violations += 1
    unchanged = sum(net == image for net, image in zip(nets, images, strict=True))
    print(
        f"check-assets: {len(nets)} networks ({unchanged} map to themselves), {members} members "
        f"and {outsiders} neighbours checked, {pairs} network pairs compared; "
        f"violations: {violations}"
    )
    return 1 if violations else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init-key").set_defaults(func=cmd_init_key)
    samples = sub.add_parser("samples")
    samples.add_argument("--out", default=str(OUT_DIR))
    samples.set_defaults(func=cmd_samples)
    verify = sub.add_parser("verify")
    verify.add_argument("files", nargs="*")
    verify.set_defaults(func=cmd_verify)
    check = sub.add_parser("check-assets")
    check.add_argument("--samples", type=int, default=64, help="random members per network")
    check.add_argument("--seed", type=int, default=0)
    check.set_defaults(func=cmd_check_assets)
    args = parser.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())

"""Adversarial round 3 on R2's fixture toolkit (SANITIZER_VERSION 2.1.0, D-042): lens FXH.

Round 2's fixes added code that no attack had seen yet. This file attacks it:
- the sanitizer's context kinds (``_context``, ``_bucket_kind``, ``_aggregation_fields``), the
  word-indexed dictionary (``_replace_names``, ``_DICT_START``), query pairs with lists, ``IN`` and
  wildcards, ``_AUTH`` redaction, plus tags, ``_ip_shaped`` and ``_map_key``;
- the scanner's file reading (``_unwrap``, ``_texts``), its decoded views and its name index;
- ``samples`` and ``verify`` in scripts/sanitize_fixtures.py.

Conventions, as in the sibling adversarial files:
- a docstring starting with **DEFECT** marks a test that fails on the current code on purpose and
  passes once the hole is closed;
- **LOCK-IN** tests pass today and pin behaviour that held up under attack.

A leak is shown in one of two ways. Either the sanitizer leaves the identifier in its output
without harvesting it, so the denylist that ``verify`` uses cannot know it. Or the full pipeline
runs: the newest sample is sanitized as ``samples`` would, and ``verify`` passes the fixture.
Every such test accepts either fix: the sanitizer maps the value, or ``verify`` refuses the
fixture.

All data is synthetic: documentation and private address ranges, ``*.example`` and
``campus.ac.in``-style names, the key ``b"k" * 32``. The script runs with every module-level path
pointed into ``tmp_path``. Nothing under reference/ or data/ is read, the committed fixtures are
never touched, and nothing touches the network.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import gzip
import importlib.machinery
import importlib.util
import io
import itertools
import json
import random
import string
import time
import zipfile
import zlib
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import yaml
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from argus.fixtures import FixturePolicy, LeakScanner, Sanitizer
from tests.conftest import REPO_ROOT

KEY = b"k" * 32
CAMPUS = "campus.ac.in"
HOST = "secret-host-x9"
SCRIPT = REPO_ROOT / "scripts" / "sanitize_fixtures.py"
POLICY = FixturePolicy(
    site_prefixes=("192.0.2.0/24",),
    own_domains=(CAMPUS,),
    keep_domains=("vendor-cdn.example",),
    literals={"Campus University": "Example University"},
    fields={
        "host": ("host.name", "observer.hostname"),
        "user": ("user.name", "related.user", "*.user.name"),
        "email": ("user.email",),
        "domain": ("url.domain", "destination.domain", "dns.question.name"),
        "id": ("_id", "event.id"),
    },
)


def _sanitizer(*docs: Any, policy: FixturePolicy = POLICY) -> Sanitizer:
    s = Sanitizer(policy, KEY)
    s.harvest(list(docs))
    return s


def _run(*docs: Any, policy: FixturePolicy = POLICY) -> tuple[Sanitizer, list[Any]]:
    """Harvest every document, then sanitize every document."""
    s = _sanitizer(*docs, policy=policy)
    return s, [s.sanitize(d) for d in docs]


def _text(node: Any) -> str:
    return json.dumps(node, ensure_ascii=False)


def _unknown_survivor(s: Sanitizer, out: Any, survivor: str) -> bool:
    """``survivor`` is in the output, and a scanner built as ``verify`` builds it (the harvested
    identifiers, the literals, the site prefixes) finds nothing there: the fixture would pass."""
    scanner = LeakScanner({*s.harvested, *s.policy.literals}, networks=s.policy.site_prefixes)
    rendered = _text(out)
    return survivor.lower() in rendered.lower() and not scanner.scan_document(rendered, "f.json")


# ====================================================================== pipeline harness


def _load(path: Path, name: str) -> Any:
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


@contextlib.contextmanager
def _quiet() -> Iterator[io.StringIO]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
        yield out


class Env:
    """scripts/sanitize_fixtures.py with every path inside ``root`` (a fresh module per test)."""

    _count = 0

    def __init__(self, root: Path) -> None:
        Env._count += 1
        self.root = root
        self.mod = _load(SCRIPT, f"adv_fxh_sanitize_fixtures_{Env._count}")
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
            "site_prefixes": ["192.0.2.0/24"],
            "own_domains": ["campus.example.edu"],
            "keep_domains": ["example.org"],
            "literals": {"Campus University": "Example University"},
            "fields": {
                "host": ["host.name"],
                "user": ["user.name"],
                "email": ["user.email"],
                "domain": ["url.domain", "destination.domain", "dns.question.name"],
                "id": ["_id", "kibana.alert.uuid"],
            },
        }
        data.update(override)
        self.mod.POLICY_PATH.parent.mkdir(parents=True, exist_ok=True)
        self.mod.POLICY_PATH.write_text(yaml.safe_dump(data))

    def sample(self, source: dict[str, Any]) -> None:
        index = len(self.mod.SAMPLES)
        path = self.root / "reference" / f"alert{index}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        source = {
            "kibana.alert.rule.name": f"Synthetic rule {index}",
            "kibana.alert.rule.type": "query",
            **source,
        }
        doc = {"_index": ".alerts-x", "_id": f"Id{index:017d}", "_source": source}
        path.write_text(json.dumps(doc))
        self.mod.SAMPLES.append(path)

    def fixture(self) -> Path:
        """The newest sample sanitized as ``samples`` writes it (same build, same serialization)."""
        raw = [self.mod.wire(json.loads(p.read_text())) for p in self.mod.SAMPLES]
        clean = self.mod.build(raw)[0].sanitize(raw[-1])
        path = self.root / "tests" / "fixtures" / "alerts" / "f.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(clean, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
        return path

    def write(self, rel: str, data: bytes) -> Path:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def verify(self, *files: Path) -> int:
        with _quiet():
            return int(self.mod.cmd_verify(argparse.Namespace(files=[str(f) for f in files])))

    def samples(self, out: Path | None = None) -> int:
        target = str(out if out is not None else self.mod.OUT_DIR)
        with _quiet():
            return int(self.mod.cmd_samples(argparse.Namespace(out=target)))


@pytest.fixture
def env(tmp_path: Path) -> Env:
    return Env(tmp_path / "repo")


def _leaks_past_verify(env: Env, survivor: str) -> bool:
    """The sanitized fixture of the newest sample holds ``survivor`` and ``verify`` passes it."""
    path = env.fixture()
    return survivor in path.read_text() and env.verify(path) == 0


# ====================================================================== FXH-01 (MEDIUM)


@pytest.mark.parametrize(
    ("query", "survivor"),
    [
        pytest.param(
            'FROM logs-* | WHERE host.name != "backup-srv-9"', "backup-srv-9", id="esql-ne"
        ),
        pytest.param(
            'FROM logs-* | WHERE user.name NOT IN ("svc-rpt-07", "svc-rpt-08")',
            "svc-rpt-07",
            id="esql-not-in",
        ),
        pytest.param(
            'process where host.name not in ("jump-box-03")', "jump-box-03", id="eql-not-in"
        ),
        pytest.param('process where user.name in~ ("ravi-k9")', "ravi-k9", id="eql-in-tilde"),
        pytest.param('process where host.name like~ "kiosk-71"', "kiosk-71", id="eql-like"),
        pytest.param('client.user.name : "neha-s4"', "neha-s4", id="kql-pattern-only-field"),
    ],
)
def test_fxh01_query_operators_that_hide_identifiers(query: str, survivor: str) -> None:
    """DEFECT FXH-01 (MEDIUM): ``_pair_re`` recognises a pair only with ``:``, ``=``, ``==`` or a
    positive ``in``, and only for the policy's exact paths.

    It misses exclusions, which are exactly where an identifier appears and nowhere else, because
    an excluded host raises no alerts:
    - ES|QL ``!=`` and ``NOT IN`` (two of today's eight fixtures are ES|QL rules);
    - EQL ``not in``, ``in~`` and ``like~``;
    - a field that only a policy pattern names (``client.user.name`` under ``*.user.name``).

    The value is neither mapped nor harvested, so ``verify`` passes it.

    Fix: match any field-path token and take its kind from ``_field_kind`` (patterns included).
    Accept the operators ``!=``, ``(not )?in~?``, ``like~?``, ``:``, ``==`` and ``=``,
    case-insensitive, with an optional ``not`` before ``in``."""
    s, out = _run({"kibana.alert.rule.parameters": {"query": query}})
    assert not _unknown_survivor(s, out, survivor)


def test_fxh01_end_to_end_esql_exclusion_passes_verify(env: Env) -> None:
    """DEFECT FXH-01 (MEDIUM), end to end: an ES|QL rule that excludes one backup server writes the
    server's name into the fixture, and ``verify`` passes it."""
    env.sample(
        {
            "kibana.alert.rule.parameters": {
                "language": "esql",
                "query": 'FROM logs-* | WHERE host.name != "backup-srv-9" | STATS c = COUNT()',
            }
        }
    )
    assert not _leaks_past_verify(env, "backup-srv-9")


# ====================================================================== FXH-02 (MEDIUM)

_COMPOSITE = {
    "request": {
        "size": 0,
        "aggs": {
            "pairs": {
                "composite": {
                    "sources": [
                        {"h": {"terms": {"field": "host.name"}}},
                        {"u": {"terms": {"field": "user.name"}}},
                    ]
                }
            }
        },
    },
    "response": {
        "aggregations": {
            "pairs": {
                "after_key": {"h": "lab-pc-07", "u": "ravi-k9"},
                "buckets": [{"key": {"h": "lab-pc-07", "u": "ravi-k9"}, "doc_count": 3}],
            }
        }
    },
}
_MULTI_TERMS = {
    "request": {
        "aggs": {"mt": {"multi_terms": {"terms": [{"field": "host.name"}, {"field": "user.name"}]}}}
    },
    "response": {
        "aggregations": {
            "mt": {
                "buckets": [
                    {
                        "key": ["lab-pc-07", "ravi-k9"],
                        "key_as_string": "lab-pc-07|ravi-k9",
                        "doc_count": 3,
                    }
                ]
            }
        }
    },
}
_DOTTED_NAME = {
    "request": {"aggs": {"host.name": {"terms": {"field": "host.name"}}}},
    "response": {
        "aggregations": {"host.name": {"buckets": [{"key": "lab-pc-07", "doc_count": 3}]}}
    },
}
_EXCLUDE = {
    "request": {"aggs": {"by_host": {"terms": {"field": "host.name", "exclude": ["lab-pc-07"]}}}}
}
_QUERY_STRING = {
    "query": {
        "bool": {
            "must_not": [
                {"query_string": {"query": "lab-pc-07", "fields": ["host.name"]}},
                {"multi_match": {"query": "ravi-k9", "fields": ["user.name"]}},
            ]
        }
    }
}


@pytest.mark.parametrize(
    ("doc", "survivor"),
    [
        pytest.param(_COMPOSITE, "lab-pc-07", id="composite-buckets-and-after-key"),
        pytest.param(_MULTI_TERMS, "lab-pc-07", id="multi-terms-listed-but-unhandled"),
        pytest.param(_DOTTED_NAME, "lab-pc-07", id="aggregation-named-after-a-dotted-field"),
        pytest.param(_EXCLUDE, "lab-pc-07", id="terms-exclude-list"),
        pytest.param(_QUERY_STRING, "lab-pc-07", id="query-string-fields"),
        pytest.param(_QUERY_STRING, "ravi-k9", id="multi-match-fields"),
    ],
)
def test_fxh02_search_forms_whose_values_take_no_kind(doc: dict[str, Any], survivor: str) -> None:
    """DEFECT FXH-02 (MEDIUM): several R4 cassette forms carry identifier values that take no
    kind. They are neither mapped nor harvested, so ``verify`` passes them.

    - **Composite aggregation:** ``aggs.<name>.composite.sources[].<src>.terms.field``. The
      response's ``buckets[].key`` and ``after_key`` are objects keyed by source name.
    - **``multi_terms``:** it is in ``_TERMS_AGGREGATIONS``, but its spec has ``terms: [{field}]``,
      not ``field``, and its bucket key is a list.
    - **An aggregation named ``host.name``:** ``_bucket_kind`` takes the name from
      ``path.rsplit(".", 2)[-2]``, which is ``name``. That fails with the request in the same
      document, and it fails D-042's "aggregation named after a field" rule for every dotted ECS
      field.
    - **``terms.include``/``exclude``:** value lists in the request.
    - **``query_string``/``multi_match``:** they name their fields in ``fields: [...]``.

    Fix:
    - record aggregation names by path (or a stack), not by splitting the path on dots;
    - read composite ``sources`` and ``multi_terms.terms[]``, and map ``key``/``after_key`` objects
      and lists by source and position;
    - give ``include``/``exclude`` (string items without regex metacharacters) the named kind;
    - give a ``query`` the kind of its ``fields`` when they all have one kind."""
    s, out = _run(doc)
    assert not _unknown_survivor(s, out, survivor)


def test_fxh02_end_to_end_dotted_aggregation_name_passes_verify(env: Env) -> None:
    """DEFECT FXH-02 (MEDIUM), end to end: a terms aggregation named after its (dotted) field,
    with the request in the same document, writes the raw bucket key into the fixture."""
    env.sample(_DOTTED_NAME)
    assert not _leaks_past_verify(env, "lab-pc-07")


# ====================================================================== FXH-03 (MEDIUM)

_EXISTS_PILL = {
    "kibana.alert.rule.parameters": {
        "filters": [
            {
                "meta": {
                    "alias": None,
                    "negate": True,
                    "disabled": False,
                    "type": "exists",
                    "key": "user.name",
                    "value": "exists",
                },
                "query": {"exists": {"field": "user.name"}},
            }
        ],
        "description": "Alerts when a lock file exists but the agent reports no user.",
    }
}
_DSL_WILDCARD = {"query": {"bool": {"must_not": [{"wildcard": {"user.name": {"value": "svc-*"}}}]}}}
_SORT_SHORTHAND = {
    "request": {"sort": [{"host.name": "asc"}]},
    "kibana.alert.rule.parameters": {"query": "FROM logs-* | SORT host.name ASC"},
}


@pytest.mark.parametrize(
    "doc",
    [
        pytest.param(_EXISTS_PILL, id="kibana-exists-filter-pill"),
        pytest.param(_DSL_WILDCARD, id="query-dsl-wildcard-pattern"),
        pytest.param(_SORT_SHORTHAND, id="sort-order-shorthand"),
    ],
)
def test_fxh03_context_kinds_rewrite_values_that_are_not_identifiers(doc: dict[str, Any]) -> None:
    """DEFECT FXH-03 (MEDIUM): ``_context`` gives an identifier kind to values that are not
    identifiers. None of these documents holds one, yet each is rewritten.

    The mapped values are also harvested, so they enter the free-text dictionary and the
    denylist:
    - **Kibana exists pill.** ``meta.value`` is the word ``"exists"``. It becomes a user
      pseudonym, and the dictionary then also rewrites ``meta.type`` and every "exists" in free
      text (``a lock file u-xxxxxxxx``).
    - **Query DSL patterns.** ``wildcard``/``prefix``/``regexp`` values are mapped whole. The KQL
      path leaves ``svc-*`` alone (D-042: a bare pattern stays).
    - **Sort shorthand.** In ``{"host.name": "asc"}``, ``asc`` is harvested as a host. The ES|QL
      ``SORT host.name ASC`` in the same corpus then reads ``SORT host.name j6va5a7e``.

    Fix:
    - give no kind to ``meta.value`` when ``meta.type`` is ``exists``;
    - give no kind to the values of ``wildcard``/``prefix``/``regexp`` (map them by fragments as
      in ``_map_query_value``);
    - give no kind to the values ``asc``/``desc`` under ``sort``."""
    _, out = _run(doc)
    assert out[0] == doc


def test_fxh03_end_to_end_clean_exists_pill_is_refused_by_samples(env: Env) -> None:
    """DEFECT FXH-03 (MEDIUM), end to end, a false positive. A rule whose only filter is an
    exists pill holds no identifier at all. Yet "exists" is harvested as a user and lands on the
    denylist. The structural DSL key ``{"exists": {...}}`` cannot be renamed, so ``samples``
    finds a "leak" in it and refuses to write any fixture."""
    env.sample(_EXISTS_PILL)
    assert env.samples() == 0


# ====================================================================== FXH-04 (MEDIUM)


@pytest.mark.parametrize(
    "doc",
    [
        pytest.param({"q": f"not url.domain : *.{CAMPUS}"}, id="kql-wildcard-pair"),
        pytest.param({"q": f'not destination.domain : "*.{CAMPUS}"'}, id="kql-quoted-wildcard"),
        pytest.param(
            {"q": f'FROM logs-* | WHERE NOT url.domain LIKE "*.{CAMPUS}"'}, id="esql-like"
        ),
        pytest.param({"message": f"acl campus_sites dstdomain .{CAMPUS}"}, id="squid-acl-dot"),
        pytest.param({"message": f"Set-Cookie: sid=1; Domain=.{CAMPUS}; Path=/"}, id="cookie"),
    ],
)
def test_fxh04_campus_domain_after_a_dot_or_wildcard_survives(doc: dict[str, Any]) -> None:
    """DEFECT FXH-04 (MEDIUM): a campus domain written as ``.campus.ac.in`` or
    ``*.campus.ac.in`` survives the sanitizer.

    Neither the campus-domain detector nor the dictionary may start after a ``.``. In a
    ``field: value`` pair, the pair span is final, and ``_map_fragment`` leaves a fragment that is
    not "name-like" (``.campus.ac.in`` has no digit, ``_`` or ``-``) as it is. So no literal pass
    runs on it either.

    With the real policy, the literal pass rewrites ``acme`` in free text (``.univ.ac.in``), but it
    never runs on a pair span. ``*.example.edu`` and ``*.example-univ.org`` stay raw, and
    ``verify`` catches them only through the literals ``acme`` and ``Example University``. So a
    rule that excludes campus sites (``not destination.domain : *.example.edu``, the natural next
    proxy rule) can never become a fixture: ``samples`` refuses. With a policy whose literals do
    not spell the campus label, it leaks: see the end-to-end test.

    Fix:
    - let ``_domain_re`` (and the dictionary) start after a ``.`` that follows ``*``, ``=``, a
      space or a string start;
    - in ``_map_fragment``, map any fragment that holds a campus or kept-sensitive domain through
      ``domains.map`` (after stripping the leading dot)."""
    _, out = _run(doc)
    assert CAMPUS not in _text(out).lower()


def test_fxh04_end_to_end_campus_wildcard_passes_verify(env: Env) -> None:
    """DEFECT FXH-04, end to end. The policy's campus domains never reach the denylist: only
    harvested spellings do. A KQL exclusion is the only place this corpus names the campus, so
    the raw campus domain is written into the fixture and ``verify`` passes it.

    Fix (scanner side, cheap): ``build()`` adds ``policy.own_domains`` and their first labels
    to the denylist."""
    env.sample(
        {
            "kibana.alert.rule.parameters": {
                "language": "kuery",
                "query": "event.action:allowed and not destination.domain : *.campus.example.edu",
            }
        }
    )
    assert not _leaks_past_verify(env, "campus.example.edu")


# ====================================================================== FXH-05 (MEDIUM)


@pytest.mark.parametrize(
    ("doc", "survivor"),
    [
        pytest.param({"host": {"name": "node-1-2-3-4"}}, "node-1-2-3-4", id="public-quad-host"),
        pytest.param(
            {"host": {"name": "ip-10-1-2-3.hpc-cluster7.local"}},
            "hpc-cluster7",
            id="class-quad-fqdn-keeps-other-labels",
        ),
        pytest.param(
            {"dns": {"question": {"name": "vpn-10-1-2-3.partner-lab.example.net"}}},
            "partner-lab",
            id="class-quad-domain-keeps-other-labels",
        ),
    ],
)
def test_fxh05_dashed_quad_anywhere_bypasses_domain_tokens(
    doc: dict[str, Any], survivor: str
) -> None:
    """DEFECT FXH-05 (MEDIUM): ``_ip_shaped`` uses ``_DASHED_V4.search``. Any host or domain value
    with a dashed quad *anywhere* goes through ``map_text`` instead of ``domains.map``:
    - a public quad (``node-1-2-3-4``) is not mapped, so the whole host name stays raw;
    - with a class quad, only the quad changes, and the other labels (``hpc-cluster7.local``)
      stay raw.

    The raw value is either "unchanged" (never harvested) or harvested only as the whole FQDN, so
    ``verify`` cannot find the surviving labels.

    Fix: treat as IP-shaped only a whole-value form (``_DASHED_V4.fullmatch``, optionally behind
    an ``ip-`` style prefix label). Otherwise map the dashed span of a class or site address and
    tokenize every other label with ``domains.label``/``map``."""
    s, out = _run(doc)
    assert not _unknown_survivor(s, out, survivor)


def test_fxh05_end_to_end_public_quad_host_passes_verify(env: Env) -> None:
    """DEFECT FXH-05 (MEDIUM), end to end: ``host.name: node-1-2-3-4`` (a cluster node named by
    rack position) reaches the fixture verbatim, and ``verify`` passes it."""
    env.sample({"host": {"name": "node-1-2-3-4"}, "message": "node-1-2-3-4 lost its heartbeat"})
    assert not _leaks_past_verify(env, "node-1-2-3-4")


# ====================================================================== FXH-06 (MEDIUM)


@pytest.mark.parametrize(
    ("url", "survivor"),
    [
        pytest.param(
            f"https://mail.vendor-cdn.example/unsub?email=ravi.k%2Bnews%40{CAMPUS}",
            "ravi.k",
            id="plus-tag-encoded",
        ),
        pytest.param(
            f"https://lms.vendor-cdn.example/login?next=%2F&user=neha%2Ecourses%40{CAMPUS}",
            "neha",
            id="encoded-dot",
        ),
    ],
)
def test_fxh06_url_encoded_plus_tag_hides_the_account(url: str, survivor: str) -> None:
    """DEFECT FXH-06 (MEDIUM): browsers encode ``+`` in a query string as ``%2B``. ``_EMAIL``'s
    local part may not hold ``%``, so in ``ravi.k%2Bnews%40campus.ac.in`` the match starts after
    the ``%2B`` (allowed by ``_PCT``) and takes the tag ``news`` as the account. ``ravi.k`` stays
    raw and is never harvested; ``verify`` passes it. ``%2E`` behaves the same way.

    Fix: allow ``%2B``, ``%2E``, ``%2D`` and ``%5F`` inside the local part, decode them before
    mapping and harvesting, and write the pseudonym back with the same escapes."""
    s, out = _run({"url": {"original": url}})
    assert not _unknown_survivor(s, out, survivor)


def test_fxh06_end_to_end_unsubscribe_link_passes_verify(env: Env) -> None:
    """DEFECT FXH-06 (MEDIUM), end to end, on a squid-style URL."""
    env.sample(
        {
            "url": {
                "original": "https://mail.example.org/unsub?email=ravi.k%2Bnews%40campus.example.edu"
            }
        }
    )
    assert not _leaks_past_verify(env, "ravi.k")


# ====================================================================== FXH-07 (MEDIUM)

_CREDENTIAL = base64.b64encode(b"ravi-k9:Hunter2pass").decode()
_API_KEY = base64.b64encode(b"VuaCfGcBCdbkQm-e5aOx:ui2lp2axTNmsyakw9tvNnw").decode()


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        pytest.param(f"GET /v1/report?auth=Basic%20{_CREDENTIAL}", _CREDENTIAL, id="basic-%20"),
        pytest.param(f"GET /v1/report?auth=Basic+{_CREDENTIAL}", _CREDENTIAL, id="basic-plus"),
        pytest.param(f"Authorization: ApiKey {_API_KEY}", _API_KEY, id="elastic-apikey"),
        pytest.param("Authorization: Token 9f86d081884c7d659a2feaa0c55ad015", "9f86d0", id="token"),
        pytest.param(
            'Authorization: Digest username="ravi-k9", realm="lab", nonce="dcd98b71",'
            ' response="6629fae49393a05397450978507c4ef1"',
            "ravi-k9",
            id="digest-username",
        ),
    ],
)
def test_fxh07_credentials_the_auth_redaction_misses(text: str, secret: str) -> None:
    """DEFECT FXH-07 (MEDIUM: a password and an account survive, though rarely): ``_AUTH``
    needs ``\\s+`` after the scheme. It knows only basic, bearer, negotiate, ntlm and digest.

    What it misses:
    - A URL-encoded ``Basic%20…`` or ``Basic+…`` keeps the base64 credential (account AND
      password) and harvests nothing.
    - ``ApiKey`` (Elasticsearch's own scheme) and ``Token`` are not redacted. ARGUS's own
      ``observability/redaction.py`` lists ``ApiKey``, ``Bearer``, ``Basic`` and ``Token``.
    - For Digest, only ``username=`` is "redacted"; the account in quotes stays, and the raw
      text ``Digest username=`` is harvested as an identifier.

    Fix:
    - allow ``%20`` and ``+`` as the separator;
    - add ``apikey`` and ``token``;
    - for Digest, redact the ``username``/``response``/``cnonce`` parameter values and harvest
      the username."""
    _, out = _run({"message": text})
    assert secret not in _text(out)


def test_fxh07_end_to_end_encoded_basic_credential_passes_verify(env: Env) -> None:
    """DEFECT FXH-07, end to end: the base64 credential reaches the fixture and ``verify`` passes
    it. The scanner decodes the base64 view, but nothing harvested the account."""
    env.sample({"url": {"original": f"https://api.example.org/v1?auth=Basic%20{_CREDENTIAL}"}})
    assert not _leaks_past_verify(env, _CREDENTIAL)


# ====================================================================== FXH-08 (LOW)


@pytest.mark.parametrize(
    "text",
    [
        "no user/password was provided for basic authentication, request: GET / HTTP/1.1",
        "Detects Basic authentication brute force against the intranet portal",
        "message digest algorithms MD5 and SHA1 are weak",
        "NTLM authentication failed for the share",
        "Bearer credentials expired before the request",
    ],
)
def test_fxh08_auth_redaction_rewrites_ordinary_prose(text: str) -> None:
    """DEFECT FXH-08 (LOW, fidelity): ``_AUTH``'s token class ``[A-Za-z0-9+/=._~-]{8,}`` matches
    any word of 8 or more letters. So "basic authentication" (an nginx error-log message, and a
    common phrase in rule descriptions and notes) becomes "basic REDACTED", and
    "digest algorithms" becomes "digest REDACTED".

    Fix: redact only a credential-shaped token. Require a preceding ``Authorization:``-style
    header name, or a token that is not a plain lower-case word: it holds a digit, ``+``, ``/``
    or ``=`` padding, or it decodes as Basic ``user:password``."""
    _, out = _run({"message": text})
    assert out[0] == {"message": text}


# ====================================================================== FXH-09 (LOW)


@pytest.mark.parametrize(
    ("user", "path"),
    [
        ("arun", "C:\\Users\\tarun\\Desktop\\report.xlsx"),
        ("isha", "\\\\fs01\\home\\nisha\\notes.txt"),
        ("ackup", "D:\\backup\\daily"),
    ],
)
def test_fxh09_escape_boundary_fires_inside_windows_paths(user: str, path: str) -> None:
    """DEFECT FXH-09 (LOW, fidelity): ``_ESC`` allows a dictionary start after a literal ``\\t``,
    ``\\n``, ``\\r``, ``\\b`` or ``\\f``, so that JSON escaped inside a log line works. In a Windows
    or UNC path, that backslash is a separator. A harvested user ``arun`` then rewrites
    ``C:\\Users\\tarun`` into ``C:\\Users\\tu-xxxxxxxx``. ``tarun`` is a different person, and the
    path is now corrupt.

    Fix: allow the ``_ESC`` start only where the string also holds a JSON escape (``\\"``,
    ``\\\\``, ``\\u``). Or try the match at the backslash's letter first, and skip the inner start
    when that letter begins a longer word."""
    _, out = _run({"user": {"name": user}, "message": f"copied {path}"})
    assert out[0]["message"] == f"copied {path}"


# ====================================================================== FXH-10 (LOW)


@pytest.mark.parametrize(
    ("spellings", "key"),
    [
        (("IP-10-1-2-3", "ip-10-1-2-3"), "Ip-10-1-2-3"),
        (("7.2.1.10.IN-ADDR.ARPA", "7.2.1.10.in-addr.arpa"), "7.2.1.10.In-Addr.Arpa"),
    ],
)
def test_fxh10_mapping_key_depends_on_harvest_order(spellings: tuple[str, str], key: str) -> None:
    """DEFECT FXH-10 (LOW, determinism): an IP-shaped host or domain is mapped through ``map_text``,
    which keeps the original's letter case. So the case variants of one name get pseudonyms that
    differ in case, and ``_remember``'s ``setdefault`` keeps whichever was harvested first.
    ``_map_key`` reads that entry, so a mapping key renders differently depending on document
    order.

    Fix: in ``_remember``, store the pseudonym of the case-folded raw value for
    host/domain/user kinds (or have ``_map_key`` map an IP-shaped key through ``map_text``)."""
    field = "host" if spellings[0].startswith("IP") else "dns"
    docs = [
        {"host": {"name": s}} if field == "host" else {"dns": {"question": {"name": s}}}
        for s in spellings
    ]
    keyed = {"counts": {key: 4}}
    first = _sanitizer(*docs, keyed).sanitize(keyed)
    second = _sanitizer(*reversed(docs), keyed).sanitize(keyed)
    assert first == second


# ====================================================================== FXH-11 (MEDIUM)

_DOC = (json.dumps({"host": {"name": HOST}, "message": "x" * 200}) + "\n").encode()


def _zip_with_gzip_member() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("readme.txt", "release notes " * 60)
        archive.writestr("alerts.jsonl.gz", gzip.compress(_DOC))
    return buffer.getvalue()


@pytest.mark.parametrize(
    "data",
    [
        pytest.param(zlib.compress(_DOC), id="zlib-stream"),
        pytest.param(zlib.compress(_DOC)[2:-4], id="raw-deflate"),
        pytest.param(b"\n" + gzip.compress(_DOC), id="gzip-after-one-byte"),
        pytest.param(b'{"note": "' + b"a" * 600 + b'"}\n' + gzip.compress(_DOC), id="text+gzip"),
        pytest.param(_zip_with_gzip_member(), id="zip-holding-a-gzip-member"),
        pytest.param(
            json.dumps(
                {"response": {"body": {"base64": base64.b64encode(gzip.compress(_DOC)).decode()}}}
            ).encode(),
            id="base64-of-gzip-in-a-cassette",
        ),
    ],
)
def test_fxh11_compressed_content_without_a_known_magic_passes(tmp_path: Path, data: bytes) -> None:
    """DEFECT FXH-11 (MEDIUM): "a corrupt, binary or unsupported file is reported as unscannable,
    never passed" (D-042) does not hold.

    ``_texts`` decodes with ``errors="replace"``, and U+FFFD counts as printable. Compressed bytes
    are mostly ≥ 0x80, and only about 13 % of them are control characters, so they clear the 0.7
    threshold as "text". Any compressed content whose magic is not at byte 0 is therefore scanned
    as garbage and passed:
    - a zlib or raw-deflate stream (HTTP ``Content-Encoding: deflate``);
    - a gzip after one stray byte, or after a text head;
    - a ``.gz`` member inside a zip;
    - base64 of gzip inside a string (a cassette body). ``_readable`` drops it silently.

    Fix:
    - count U+FFFD (or any invalid UTF-8) as unprintable, i.e. decode strictly and report
      "binary content" on failure;
    - also detect a zlib header (``78 01/5E/9C/DA``);
    - run ``_unwrap`` on decompressed members and on base64/hex payloads that start with a
      compression magic, reporting what cannot be read."""
    path = tmp_path / "fixture.json"
    path.write_bytes(data)
    assert LeakScanner({HOST}).scan_file(path)


def test_fxh11_end_to_end_zlib_fixture_passes_verify(env: Env) -> None:
    """DEFECT FXH-11 (MEDIUM), end to end: a deflate-encoded fixture holding a harvested host name
    passes ``verify`` with 0 leaks and 0 unscannable files."""
    env.sample({"host": {"name": HOST}})
    path = env.write("tests/fixtures/cassettes/search.json.z", zlib.compress(_DOC))
    assert env.verify(path) != 0


# ====================================================================== FXH-12 (LOW)


@pytest.mark.parametrize("encoding", ["utf-16-le", "utf-16-be"])
def test_fxh12_utf16_without_bom_and_few_nuls_is_read_as_utf8(
    tmp_path: Path, encoding: str
) -> None:
    """DEFECT FXH-12 (LOW): without a BOM, UTF-16 is tried only when NULs make up at least 10 %
    of the bytes. Text that is mostly non-Latin (Devanagari has no NUL bytes in UTF-16) falls below
    that. It is decoded as UTF-8 and passes the printable test (``(\\t`` pairs). The ASCII
    identifier inside then reads ``s\\0e\\0c\\0…`` and is never found.

    Fix: also try the UTF-16/32 readings whenever any NUL is present (a UTF-8 JSON or text fixture
    has none), and scan every reading that is printable."""
    text = "नमस्ते दुनिया " * 40 + HOST + " नमस्ते" * 40
    path = tmp_path / "event.txt"
    path.write_bytes(text.encode(encoding))
    assert LeakScanner({HOST}).scan_file(path)


# ====================================================================== FXH-13 (LOW)


def _zip_member(compression: int, corrupt: bool, encrypted: bool) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=compression) as archive:
        archive.writestr(f"{HOST}.json", _DOC * 4)
    raw = bytearray(buffer.getvalue())
    start = 30 + len(f"{HOST}.json")  # the member's data, after its local header
    if corrupt:
        for i in range(start + 4, start + 24):
            raw[i] ^= 0x5A
    if encrypted:  # general purpose flag bit 0, in the local header and the central directory
        raw[6] |= 1
        central = raw.find(b"PK\x01\x02")
        raw[central + 8] |= 1
    return bytes(raw)


_BROKEN_ZIPS = [
    pytest.param(_zip_member(zipfile.ZIP_DEFLATED, True, False), id="corrupt-deflate-zlib.error"),
    pytest.param(_zip_member(zipfile.ZIP_LZMA, True, False), id="corrupt-lzma-LZMAError"),
    pytest.param(_zip_member(zipfile.ZIP_STORED, False, True), id="encrypted-RuntimeError"),
]


@pytest.mark.parametrize("data", _BROKEN_ZIPS)
def test_fxh13_broken_zip_members_crash_the_scanner(tmp_path: Path, data: bytes) -> None:
    """DEFECT FXH-13 (LOW): ``_unzip`` catches ``BadZipFile``, ``OSError``, ``EOFError``,
    ``ValueError`` and ``NotImplementedError``. ``archive.read`` also raises:
    - ``zlib.error`` for a corrupt deflate member;
    - ``lzma.LZMAError`` for a corrupt LZMA member;
    - ``RuntimeError`` for an encrypted member.

    ``scan_file`` therefore crashes instead of reporting the file as unscannable.

    Fix: catch ``Exception`` around ``archive.read`` (or add these three) and report
    "corrupt archive" / "encrypted member"."""
    path = tmp_path / "bundle.zip"
    path.write_bytes(data)
    leaks = LeakScanner({HOST}).scan_file(path)
    assert any(leak.form.startswith("unscannable") for leak in leaks)


def test_fxh13_end_to_end_verify_crashes_and_prints_the_member_name(env: Env) -> None:
    """DEFECT FXH-13 (LOW), end to end. ``cmd_verify`` catches only ``OSError``, so an encrypted
    member crashes ``verify``. The uncaught ``RuntimeError`` reads "File <ZipInfo
    filename='secret-host-x9.json' …> is encrypted". The traceback prints a denylisted name,
    which FXF-12 forbids. ``verify`` should report the file as unscannable and exit 1, with
    nothing in its output that names the member."""
    env.sample({"host": {"name": HOST}})
    path = env.write("tests/fixtures/bundle.zip", _zip_member(zipfile.ZIP_STORED, False, True))
    with _quiet() as out:
        try:
            code = int(env.mod.cmd_verify(argparse.Namespace(files=[str(path)])))
        except Exception as exc:  # what the user sees: the exception text in the traceback
            print(f"{type(exc).__name__}: {exc}")
            code = -1
    assert code == 1
    assert HOST not in out.getvalue()


# ====================================================================== FXH-14 (LOW)


def _scan_seconds(scanner: LeakScanner, text: str) -> float:
    best = float("inf")
    for _ in range(2):
        start = time.perf_counter()
        scanner.scan_text(text)
        best = min(best, time.perf_counter() - start)
    return best


@pytest.mark.parametrize("shape", ["machine-account", "full-name"])
def test_fxh14_odd_names_and_phrases_are_still_one_alternation(shape: str) -> None:
    """DEFECT FXH-14 (LOW today, MEDIUM with Windows or directory sources): FXB-02 put plain words
    on a set index. But names with edge punctuation (machine accounts ``LAB-PC07$``, which
    ``HOST$`` harvesting creates for every Windows host) and names with spaces (full names, display
    names) still go into one ``re.IGNORECASE`` alternation. Its cost is O(text * entries).

    8,000 such names make ``scan_text`` about 30 times slower than 8,000 plain names: about
    12 s/MB per scan, against D-041's "about 2 s per MB with 40k entries". Every decoded view of
    every string pays that cost again.

    Fix: index both by their first alphanumeric word, as ``_words`` does. Check a phrase with a
    per-start match of its separator pattern, and check an odd name's punctuation by a direct
    comparison around the core hit."""
    rng = random.Random(7)

    def token(k: int) -> str:
        return "".join(rng.choices(string.ascii_uppercase + string.digits, k=k))

    if shape == "machine-account":
        special = {f"{token(3)}-PC{token(3)}$" for _ in range(8000)}
    else:
        special = {f"{token(5).title()} {token(6).title()}" for _ in range(8000)}
    plain = {f"{token(3)}-PC{token(3)}X" for _ in range(8000)}
    filler = {f"plain{i}x" for i in range(32000)}
    text = " ".join(
        "".join(rng.choices(string.ascii_lowercase, k=rng.randint(2, 9))) for _ in range(12000)
    )
    slow = _scan_seconds(LeakScanner(special | filler), text)
    fast = _scan_seconds(LeakScanner(plain | filler), text)
    assert slow < max(5 * fast, 0.25), f"{slow:.2f}s against {fast:.2f}s"


# ====================================================================== FXH-15 (LOW)


def test_fxh15_underscored_class_address_survives_and_is_not_canonical(env: Env) -> None:
    """DEFECT FXH-15 (LOW): the sanitizer's ``_DASHED_V4`` reads only ``-``. The scanner's
    ``_V4_SEPARATED`` reads ``-`` and ``_``, but finds only addresses that are on the denylist in
    canonical form. A dashed address is harvested as the *name* ``10-1-2-3``
    (``_canonicals`` does not parse it), and the dotted address is not harvested.

    So ``host.name: ip-10-1-2-3`` plus a file name ``dump_10_1_2_3.pcap``:
    - the sanitizer maps the first and leaves the second;
    - ``verify`` passes the fixture with a campus address in it.

    Fix:
    - let ``_DASHED_V4`` take a consistent ``[-_]`` separator;
    - make ``_canonicals`` parse dashed and underscored quads (and register the dotted address
      when harvesting a dashed one)."""
    env.sample({"host": {"name": "ip-10-1-2-3"}, "message": "saved dump_10_1_2_3.pcap"})
    assert not _leaks_past_verify(env, "10_1_2_3")


# ====================================================================== LOCK-INs


def _reference_replace(text: str, entries: dict[str, str]) -> str:
    """Leftmost-longest whole-word replacement by brute force (no index): a start is where the
    previous character is not ``[\\w.-]``, an end where the next is not ``[\\w-]``; entries match
    case-insensitively."""
    lowered = {k.lower(): v for k, v in entries.items()}
    out: list[str] = []
    pos = i = 0
    while i < len(text):
        before = text[i - 1] if i else ""
        ok_start = (text[i].isalnum() or text[i] in "_-") and not (
            before and (before.isalnum() or before in "_.-")
        )
        if ok_start:
            for end in range(len(text), i, -1):
                after = text[end] if end < len(text) else ""
                if after and (after.isalnum() or after in "_-"):
                    continue
                found = lowered.get(text[i:end].lower())
                if found is not None:
                    out.append(text[pos:i] + found)
                    pos = i = end
                    break
            else:
                i += 1
            continue
        i += 1
    return "".join(out) + text[pos:]


_ALPHABET = "ab-_. "


@settings(
    max_examples=300,
    deadline=None,
    derandomize=True,
    suppress_health_check=[HealthCheck.too_slow],
)
@given(
    names=st.lists(
        st.text(_ALPHABET, min_size=3, max_size=7).filter(lambda n: n[0] in "ab" and n[-1] in "ab"),
        min_size=1,
        max_size=6,
        unique_by=str.lower,
    ),
    text=st.text(_ALPHABET + "A", max_size=40),
)
def test_lockin_word_index_equals_brute_force_leftmost_longest(names: list[str], text: str) -> None:
    """LOCK-IN: the first-word index of ``_replace_names`` gives exactly the brute-force
    leftmost-longest result, with dotted, spaced and dashed entries sharing first words and the
    compound boundaries (``lab-pc`` is not replaced inside ``lab-pc-07`` or ``x.lab-pc``)."""
    s = Sanitizer(POLICY, KEY)
    s.add_names(names, kind="place")
    entries = {name: s.dictionary[name.lower()] for name in names}
    assert s._replace_names(text) == _reference_replace(text, entries)


_ORDER_DOCS: list[Any] = [
    {"user": {"name": "ravi-k9"}, "host": {"name": "LAB-PC-07"}},
    {
        "kibana.alert.rule.parameters": {
            "query": 'host.name : ("lab-pc-07" or "kiosk-71") and not user.name : svc-rpt-07*',
            "filters": [
                {
                    "meta": {"key": "host.name", "params": {"query": "kiosk-71"}, "type": "phrase"},
                    "query": {"match_phrase": {"host.name": "kiosk-71"}},
                }
            ],
        }
    },
    {
        "request": {"aggs": {"by_user": {"terms": {"field": "user.name"}}}},
        "response": {
            "aggregations": {"by_user": {"buckets": [{"key": "Ravi-K9", "doc_count": 2}]}}
        },
    },
    {"message": "LAB-PC-07 and kiosk-71 contacted ravi-k9%40campus.ac.in"},
]


def test_lockin_context_kinds_do_not_depend_on_document_order() -> None:
    """LOCK-IN: across every order of documents mixing plain fields, KQL value lists and
    wildcards, Kibana phrase pills, a terms aggregation with its request, and free text, every
    document sanitizes the same. Inside each document no raw name survives."""
    outputs = set()
    for order in itertools.permutations(_ORDER_DOCS):
        s = _sanitizer(*order)
        rendered = _text([s.sanitize(d) for d in _ORDER_DOCS])
        outputs.add(rendered)
        for raw in ("lab-pc-07", "kiosk-71", "ravi-k9", "svc-rpt-07"):
            assert raw not in rendered.lower()
    assert len(outputs) == 1


@pytest.mark.parametrize("aggregation", ["terms", "significant_terms", "rare_terms"])
def test_lockin_bucket_keys_take_the_requested_field_kind(aggregation: str) -> None:
    """LOCK-IN: buckets of ``terms``, ``significant_terms`` and ``rare_terms`` aggregations
    whose request is in the same document are mapped like the field, also in ``key_as_string``."""
    doc = {
        "request": {"aggs": {"top": {aggregation: {"field": "host.name"}}}},
        "response": {
            "aggregations": {
                "top": {
                    "buckets": [{"key": "lab-pc-07", "key_as_string": "lab-pc-07", "doc_count": 1}]
                }
            }
        },
    }
    _, out = _run(doc, {"host": {"name": "lab-pc-07"}})
    bucket = out[0]["response"]["aggregations"]["top"]["buckets"][0]
    assert bucket["key"] == bucket["key_as_string"] == out[1]["host"]["name"] != "lab-pc-07"


def test_lockin_plus_tags_and_basic_headers_keep_the_account() -> None:
    """LOCK-IN: a plus-tagged address in clear text keeps the account's own pseudonym, and a
    Basic header (with a real separator) is redacted and its account harvested and mapped in free
    text."""
    credential = base64.b64encode(b"neha-s4:pw-123456").decode()
    docs = [
        {"user": {"name": "ravi-k9"}},
        {"message": f"bounce for ravi-k9+lists@{CAMPUS}"},
        {"message": f"Authorization: Basic {credential} then neha-s4 logged out"},
    ]
    _, out = _run(*docs)
    account = out[0]["user"]["name"]
    assert f"{account}+" in out[1]["message"]
    assert credential not in out[2]["message"]
    assert "neha-s4" not in out[2]["message"]
    assert "REDACTED" in out[2]["message"]


@pytest.mark.parametrize(
    "data",
    [
        pytest.param(gzip.compress(b'{"m": "clean"}\n') + gzip.compress(_DOC), id="multi-member"),
        pytest.param(gzip.compress(gzip.compress(_DOC)), id="gzip-in-gzip"),
        pytest.param(b"\xef\xbb\xbf" + _DOC, id="utf8-bom"),
        pytest.param(b"\xff\xfe" + _DOC.decode().encode("utf-16-le"), id="utf16-bom"),
    ],
)
def test_lockin_layered_and_bom_files_are_read(tmp_path: Path, data: bytes) -> None:
    """LOCK-IN: a second gzip member, gzip inside gzip, and BOM-marked UTF-8 and UTF-16 are all
    read, and the host name in them is found."""
    path = tmp_path / "f.json"
    path.write_bytes(data)
    assert any(leak.form in ("raw", "json") for leak in LeakScanner({HOST}).scan_file(path))


def test_lockin_decoded_views_are_bounded_and_deep() -> None:
    """LOCK-IN: an identifier under nine layers of base64 is still found. A 650 KB string of
    nested ``%25``, ``&amp;`` and ``\\\\x`` escapes (a decoding bomb) is scanned in seconds, not
    minutes."""
    scanner = LeakScanner({HOST})
    value = HOST
    for _ in range(9):
        value = base64.b64encode(f"payload {value}".encode()).decode()
    assert scanner.scan_document(json.dumps({"m": value}), "f")
    bomb = "%25" * 100_000 + "&amp;" * 50_000 + "\\\\x41" * 20_000
    start = time.perf_counter()
    scanner.scan_document(json.dumps({"m": bomb}), "f")
    assert time.perf_counter() - start < 15


def test_lockin_samples_refuses_a_symlink_to_the_repository(env: Env, tmp_path: Path) -> None:
    """LOCK-IN: ``samples --out`` given a symlink that resolves to the repository (or to the
    directory holding the key) is refused, and nothing is renamed or deleted."""
    env.sample({"message": "clean"})
    for target in (env.root, env.root / "data"):
        link = tmp_path / f"link-{target.name}"
        link.symlink_to(target, target_is_directory=True)
        assert env.samples(link) == 1
    assert env.mod.KEY_PATH.is_file()
    assert (env.root / "reference" / "alert0.json").is_file()


def test_lockin_verify_fails_closed_on_directory_links_and_loops(env: Env) -> None:
    """LOCK-IN: under tests/fixtures/, a symlink to a directory is reported unreadable (exit 1),
    a self-referencing link is treated as dangling (its text is scanned), and neither crashes
    ``verify``."""
    env.sample({"host": {"name": HOST}})
    fixtures = env.root / "tests" / "fixtures"
    fixtures.mkdir(parents=True)
    (fixtures / "loop").symlink_to("loop")
    assert env.verify() == 0
    (fixtures / "dir").symlink_to(env.root / "config", target_is_directory=True)
    assert env.verify() == 1

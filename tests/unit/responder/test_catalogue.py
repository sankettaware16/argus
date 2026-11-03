"""The responder's catalogue (Q-H2): the real file is valid and complete, every refusal has its
reason, and no write is reachable from a verifier."""

from __future__ import annotations

import ast
import copy
import re
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from argus.config.sources import read_yaml_file
from argus.gateway import templates
from argus.gateway.templates import REGISTRY, Endpoint
from argus.gateway.transport import wire_path
from argus.responder import catalogue as cat
from argus.responder.facts import FACTS

FACTS_SET = frozenset(FACTS)
RAW, _ = read_yaml_file(cat.PATH)


def raw() -> dict[str, Any]:
    return copy.deepcopy(RAW)


def refused(data: dict[str, Any], match: str) -> None:
    with pytest.raises(cat.CatalogueError, match=match):
        cat.parse(data, FACTS_SET)


# --------------------------------------------------------------------------- the real file


def test_the_real_catalogue_loads_and_covers_every_fact_the_packs_establish() -> None:
    c = cat.load()
    assert c.version == 1
    used = {fact for f in c.families for fact in f.when}
    assert used == FACTS_SET  # every true-positive fact has a family, hence advice
    for fact in FACTS:
        assert [f for f in c.families if fact in f.when and f.actions]
    # the plan's table (§7.7) and the brute-force family
    ids = {a.id for a in c.actions}
    assert {
        "c2_beacon.isolate_host",
        "c2_beacon.block_destination",
        "exposed_file.remove_file",
        "exposed_file.rotate_secrets",
        "account_compromise.reset_account",
        "noisy_rule.tune_rule",
        "brute_force.block_source",
    } <= ids


def test_owners_wording_and_verifiers_of_the_real_file() -> None:
    c = cat.load()
    for action in c.actions:
        assert re.fullmatch(r"[a-z][a-z0-9_]*[.][a-z][a-z0-9_]*", action.id)  # the table's CHECK
        assert len(action.id) <= 80
        assert action.owner in c.owners
        assert 1 <= len(action.title) <= cat.TITLE_MAX
        assert 1 <= len(action.say) <= cat.SAY_MAX
        assert action.say.isascii()
        assert action.verify.kind in {"proxy.contact", "web.path_outcomes", "alerts", "none"}
    for owner in c.owners.values():
        assert owner.name
        assert owner.does
    plan = {
        "c2_beacon.isolate_host": ("network_team", "proxy.contact"),
        "c2_beacon.block_destination": ("network_team", "proxy.contact"),
        "exposed_file.remove_file": ("site_owner", "web.path_outcomes"),
        "account_compromise.reset_account": ("mail_admin", "none"),
    }
    for action_id, (owner, verifier) in plan.items():
        found = c.action(action_id)
        assert found is not None
        assert (found.owner, found.verify.kind) == (owner, verifier)
    assert c.action("c2_beacon.nope") is None


def test_the_order_of_advice_is_the_files_then_the_rank() -> None:
    c = cat.load()
    assert [f.key for f in c.families][:3] == ["c2_beacon", "exposed_file", "web_attack"]
    for family in c.families:
        assert [a.rank for a in family.actions] == sorted(a.rank for a in family.actions)


def test_a_noisy_rule_belongs_to_no_case() -> None:
    from argus.responder.facts import Facts, match

    c = cat.load()
    everything = Facts(frozenset(FACTS))
    assert "noisy_rule" not in [f.key for f in match(c, everything)]
    assert c.family("noisy_rule").scope == "rule"


# --------------------------------------------------------------------------- refusals


def test_unknown_keys_are_errors_at_every_level() -> None:
    for path in (
        [],
        ["owners", "network_team"],
        ["families", "c2_beacon"],
        ["families", "c2_beacon", "actions", "isolate_host"],
        ["families", "c2_beacon", "actions", "isolate_host", "verify"],
    ):
        data = raw()
        node = data
        for key in path:
            node = node[key]
        node["surprise"] = 1
        refused(data, "unknown key")


@pytest.mark.parametrize(
    ("edit", "message"),
    [
        (lambda d: d["families"]["c2_beacon"]["actions"]["isolate_host"].update(owner="nobody"),
         "no owner 'nobody'"),
        (lambda d: d["families"]["c2_beacon"].update(when=["telepathy"]), "no fact telepathy"),
        (lambda d: d["families"]["c2_beacon"]["actions"]["block_destination"].update(rank=1),
         "share a rank"),
        (lambda d: d["families"]["c2_beacon"].update(when=[]), "says when it applies"),
        (lambda d: d["families"]["noisy_rule"].update(when=["c2_indicator"]),
         "says when it applies"),
        (lambda d: d["families"]["c2_beacon"].update(actions={}), "at least one action"),
        (lambda d: (d["families"].pop("brute_force"),
                    d["families"]["account_compromise"].update(when=["mail_user"])),
         "no family uses the fact auth_failures"),
        (lambda d: d["families"].update({"Bad-Name": d["families"]["noisy_rule"]}),
         "lowercase letters"),
        (lambda d: d["families"]["c2_beacon"]["actions"].update(
            {"Bad Name": {**d["families"]["c2_beacon"]["actions"]["isolate_host"], "rank": 9}}),
         "lowercase letters"),
        (lambda d: d.update(version=0), "version"),
        (lambda d: d["families"]["c2_beacon"]["actions"]["isolate_host"].update(say=""),
         "the wording"),
        (lambda d: d["families"]["c2_beacon"]["actions"]["isolate_host"].update(say="x" * 301),
         "the wording"),
        (lambda d: d["families"]["c2_beacon"]["actions"]["isolate_host"].update(title="y" * 61),
         "a title"),
        (lambda d: d["families"]["c2_beacon"]["actions"]["isolate_host"].update(
            say="Run rm -rf now; then see https://example.com"), "plain words"),
        (lambda d: d["families"]["c2_beacon"]["actions"]["isolate_host"].update(
            say="Take it off the network " + chr(0x2013) + " now"), "plain words"),
        (lambda d: d["families"]["c2_beacon"]["actions"]["isolate_host"].update(
            say="Use <b>bold</b> words"), "plain words"),
        (lambda d: d["owners"]["siem_team"].update(does="`id`"), "plain words"),
        (lambda d: d.update(version=2**31), "version"),
    ],
)  # fmt: skip
def test_invalid_catalogues_are_refused_with_the_reason(edit: Any, message: str) -> None:
    data = raw()
    edit(data)
    refused(data, message)


@pytest.mark.parametrize(
    "verify",
    [
        {},
        {"template": "proxy.contact", "local": "alerts"},
        {"template": "proxy.contact", "not_verifiable": "x"},
        {"local": "alerts", "not_verifiable": "x"},
        {"template": "ti.lookup"},  # a real template, but not a verifier
        {"template": "kibana.case.update"},  # a write: not a template at all
        {"template": "PUT /_cluster/settings"},
        {"local": "siem"},
        {"not_verifiable": ""},
        {"not_verifiable": "see https://example.com"},
        {"method": "DELETE", "path": "/_all"},  # a request is not a catalogue entry
        {"template": "proxy.contact", "body": {"query": {}}},
    ],
)
def test_a_verifier_is_one_read_check_or_the_reason_there_is_none(verify: dict[str, Any]) -> None:
    data = raw()
    data["families"]["c2_beacon"]["actions"]["isolate_host"]["verify"] = verify
    with pytest.raises(cat.CatalogueError):
        cat.parse(data, FACTS_SET)


def test_a_verifier_that_is_not_a_read_of_the_logs_is_refused(monkeypatch: Any) -> None:
    """Even a template named in VERIFIERS is refused if it is not a document read of the log
    indices: the gateway's other endpoints (identity, license, settings) are not verifiers."""
    template = REGISTRY["proxy.contact"]
    for endpoint in (Endpoint.INFO, Endpoint.AUTHENTICATE, Endpoint.LICENSE,
                     Endpoint.INDEX_BLOCKS, Endpoint.HAS_PRIVILEGES):  # fmt: skip
        monkeypatch.setattr(template, "endpoint", endpoint)
        refused(raw(), "is not a read of the logs")
    monkeypatch.setattr(template, "endpoint", Endpoint.SEARCH)
    monkeypatch.setattr(template, "family", templates.Family.CLUSTER)
    refused(raw(), "is not a read of the logs")
    monkeypatch.undo()
    monkeypatch.delitem(REGISTRY, "proxy.contact")
    refused(raw(), "is not registered")


def test_a_missing_or_malformed_file_is_an_error_never_an_empty_catalogue(tmp_path: Path) -> None:
    with pytest.raises(cat.CatalogueError, match="is missing"):
        cat.load(tmp_path / "nope.yaml")
    (tmp_path / "a.yaml").write_text("version: 1\nversion: 2\n")
    with pytest.raises(Exception, match="duplicate"):  # the YAML loader's own refusal
        cat.load(tmp_path / "a.yaml")
    (tmp_path / "b.yaml").write_text("")
    with pytest.raises(cat.CatalogueError):
        cat.load(tmp_path / "b.yaml")
    (tmp_path / "c.yaml").write_text("- a\n- b\n")
    with pytest.raises(Exception, match="mapping"):
        cat.load(tmp_path / "c.yaml")


# --------------------------------------------------------------------------- no write reachable


def test_every_verifier_template_is_a_post_search_or_mget_and_nothing_else() -> None:
    """Followed down to the wire: the gateway sends a verifier template as ``POST /<indices>/
    _search`` (or ``_mget``), the only request shapes a verifier can become."""
    c = cat.load()
    named = {a.verify.template for a in c.actions if a.verify.template}
    assert named == set(cat.VERIFIERS) == {"proxy.contact", "web.path_outcomes"}
    for name in named:
        template = REGISTRY[name]
        assert template.endpoint in cat.READ_ENDPOINTS
        request = SimpleNamespace(spec=template.spec(), indices=("acme-logs-squid-x",),
                                  pattern=None)  # fmt: skip
        method, path = wire_path(request)  # type: ignore[arg-type]
        assert method == "POST"
        assert path.endswith(("/_search", "/_mget"))


def test_no_endpoint_the_gateway_can_send_writes() -> None:
    """The whole table, so a future write endpoint cannot become a verifier by accident: the
    verifier set is a fixed subset of the endpoints that read."""
    methods = {}
    for endpoint in Endpoint:
        request = SimpleNamespace(
            spec=SimpleNamespace(endpoint=endpoint), indices=("i",), pattern="p"
        )
        methods[endpoint] = wire_path(request)[0]  # type: ignore[arg-type]
    for endpoint in cat.READ_ENDPOINTS:
        assert methods[endpoint] == "POST"
        assert wire_path(  # type: ignore[arg-type]
            SimpleNamespace(spec=SimpleNamespace(endpoint=endpoint), indices=("i",), pattern="p")
        )[1].endswith(("/_search", "/_mget"))
    assert set(methods.values()) <= {"GET", "POST"}  # no PUT, DELETE or PATCH exists at all


FORBIDDEN = (
    "argus.writer",
    "argus.kibana_sync",
    "argus.writeback",
    "argus.gateway.gateway",
    "argus.gateway.transport",
    "argus.llm",
    "argus.agent.agent",
    "argus.agent.service",
    "httpx",
    "requests",
    "socket",
    "subprocess",
    "aiohttp",
    "urllib",
    "smtplib",
)


def test_the_responder_imports_nothing_that_sends_or_asks_a_model() -> None:
    """Static proof for the package (and the command that calls it): nothing in it can reach
    the SIEM, Kibana, a model, a mail relay or a shell, so advice cannot become an action."""
    root = Path(cat.__file__).parent
    for path in sorted(root.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module] + [f"{node.module}.{a.name}" for a in node.names]
            for name in names:
                assert not name.startswith(FORBIDDEN), f"{path.name} imports {name}"


# --------------------------------------------------------------------------- review Q-H2 (R3, R12)


@pytest.mark.parametrize(
    "wording",
    [
        "See [x](javascript:alert(1)) now",  # markup and a script link
        "Fetch ftp://files.example/x then go",
        "Visit evil.example for the fix",  # a domain
        "Run sudo rm -rf now",
        "Run it -rf now",  # a flag
        "Block it && wipe it",
        "Block it & wipe it",
        'Say "go"',
        "Open /etc/passwd",
        "Use ${HOME}",
        "Take it\toff",
        "Block it\u2013now",
        "Open C:\\temp",
    ],
)
def test_the_loader_takes_only_plain_words(wording: str) -> None:
    for owner_field in ("does",):
        data = raw()
        data["owners"]["siem_team"][owner_field] = wording
        refused(data, "plain words")
    data = raw()
    data["families"]["c2_beacon"]["actions"]["isolate_host"]["say"] = wording
    refused(data, "plain words")


def test_the_loader_takes_digits_and_basic_punctuation() -> None:
    data = raw()
    data["families"]["c2_beacon"]["actions"]["isolate_host"]["say"] = (
        "Within 24 hours (or sooner), take the 3 computers off the network - then report: done?"
    )
    assert cat.parse(data, FACTS_SET).action("c2_beacon.isolate_host") is not None


def test_an_action_id_the_table_cannot_hold_is_refused() -> None:
    data = raw()
    family = copy.deepcopy(data["families"]["c2_beacon"])
    family["actions"] = {"a" * 59: family["actions"]["isolate_host"]}
    data["families"]["f" * 59] = family  # 119 characters; the table allows 80
    refused(data, "at most 80 characters")

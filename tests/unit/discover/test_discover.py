"""`argus discover` end to end on fakes (P4-D1): the reads it makes, the proposal for a daily-index
Elastic, a data-stream Elastic and an empty one, the YAML it prints (which loads back as the
proposal), and what it refuses."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import typer
import yaml
from typer.testing import CliRunner

from argus import site
from argus.config.settings import load_settings
from argus.discover import run
from argus.discover.classify import Confidence
from argus.discover.propose import Inputs, Proposal, propose, render_text, render_yaml
from argus.gateway.health import HealthMemory, HealthState
from argus.gateway.state import MemoryStore
from argus.site import Role, SiteSettings
from tests.unit.discover.fakes import (
    DAYS,
    DNS,
    ECS_AUTH,
    ECS_NGINX,
    EMPTY_LISTING,
    NGINX,
    SQUID,
    SSO,
    daily_listing,
    elastic,
    gateways,
    kibana,
    stream_listing,
)
from tests.unit.gateway.fakes import T0

pytestmark = pytest.mark.unit

NEWEST = DAYS[-1]
DAILY_MAPPINGS = {
    f"acme-logs-squid-{NEWEST}": SQUID,
    f"acme-logs-nginx-{NEWEST}": NGINX,
    f"acme-logs-dns-{NEWEST}": DNS,
    f"acme-logs-sso-{NEWEST}": SSO,
}
STREAM_MAPPINGS = {
    f".ds-logs-nginx.access-default-{NEWEST}-000002": ECS_NGINX,
    f".ds-logs-system.auth-default-{NEWEST}-000002": ECS_AUTH,
}


async def discover(transport: Any, server: Any = None, **kw: Any) -> tuple[Proposal, Any, Any]:
    es, lane, store, clock = gateways(transport, server)
    inputs = await run.collect(es, lane, clock=clock, **kw)
    return propose(inputs), transport, (store, server)


def families(p: Proposal) -> dict[str, Any]:
    return {f.family.name: f for f in p.families}


def reloaded(p: Proposal) -> SiteSettings:
    """The printed YAML, loaded the way the settings load a file's ``site`` section."""
    return SiteSettings.model_validate(yaml.safe_load(render_yaml(p))["site"])


# --------------------------------------------------------------------------- a daily-index Elastic


async def test_a_daily_index_elastic_is_proposed_by_role_with_the_keyword_fields() -> None:
    transport = elastic(
        daily_listing(),
        DAILY_MAPPINGS,
        spaces=("default", "acme-soc"),
        read_ilm=True,
        ilm={
            "acme-logs-5d": {
                "policy": {"phases": {"delete": {"min_age": "5d"}}},
                "in_use_by": {"indices": [f"acme-logs-squid-{NEWEST}"]},
            }
        },
    )
    server = kibana(("default", "acme-soc"))
    p, *_ = await discover(transport, server)
    by = families(p)
    assert {n: f.family.role.value for n, f in by.items()} == {
        "proxy": "proxy",
        "web": "web",
        "dns": "dns",
        "auth": "auth",
        "mail": "mail",  # postfix: its name alone, the fixture has no mapping for it
    }
    assert by["mail"].confidence is Confidence.LOW
    assert by["mail"].family.pattern == "acme-logs-postfix-*"
    proxy = by["proxy"]
    assert proxy.family.pattern == "acme-logs-squid-*"
    assert proxy.confidence is Confidence.HIGH
    assert proxy.family.fields == {  # the fields the evidence modules query as keywords
        "url": "url.original.keyword",
        "action": "event.action.keyword",
    }
    assert by["web"].family.fields["domain"] == "url.domain.keyword"
    assert by["dns"].family.fields["query_name"] == "dns.question.name.keyword"
    auth = by["auth"]
    assert auth.family.pattern == "acme-logs-sso-*"
    assert auth.family.watch is False  # sign-ins are read, not watched
    assert auth.family.fields["user_name"] == "user.name.keyword"
    assert p.unclassified == ("acme-metrics-*",)
    r = proxy.retention
    assert (r.days_kept, r.oldest, r.newest, r.delete_after) == (3, DAYS[0], NEWEST, "5d")
    assert p.history_window == "3d"  # the shortest of the retentions found


async def test_the_space_and_the_features_come_from_kibana() -> None:
    transport = elastic(daily_listing(), DAILY_MAPPINGS, spaces=("default", "acme-soc"))
    p, *_ = await discover(transport, kibana(("default", "acme-soc"), space="default"))
    assert p.space == "default"  # both have alerts; the first is proposed and the choice is said
    assert any("2 spaces have alerts" in w for w in p.warnings)
    assert p.alerts_aliases == (  # in name order
        ".alerts-security.alerts-acme-soc",
        ".alerts-security.alerts-default",
    )
    assert (p.features.security, p.features.cases) == ("siemV2", "securitySolutionCasesV3")  # type: ignore[union-attr]
    assert (p.elastic_version, p.kibana_version) == ("8.19.12", "8.19.12")
    assert p.licence is not None
    assert p.licence.level == "basic"
    assert not p.licence.paid


async def test_a_single_space_with_alerts_is_the_space() -> None:
    transport = elastic(daily_listing(), DAILY_MAPPINGS, spaces=("acme-soc",))
    p, *_ = await discover(transport, kibana(("default", "acme-soc")))
    assert p.space == "acme-soc"
    assert "exists and Kibana has the space" in p.space_evidence
    assert reloaded(p).space == "acme-soc"
    assert reloaded(p).alerts_index_name == ".alerts-security.alerts-acme-soc"


async def test_the_yaml_loads_back_as_exactly_the_proposal() -> None:
    p, *_ = await discover(elastic(daily_listing(), DAILY_MAPPINGS), kibana())
    loaded = reloaded(p)
    assert loaded == p.site()
    assert [f.pattern for f in loaded.families] == [x.family.pattern for x in p.families]
    text = render_yaml(p)
    assert text.startswith("# Proposed by `argus discover`")
    assert "high confidence" in text
    assert "the mapping has" in text
    assert text.count("\n    - role:") == len(p.families)


# --------------------------------------------------------------------------- a data-stream Elastic


async def test_a_data_stream_elastic_is_proposed_with_plain_ecs_fields_and_exact_names() -> None:
    transport = elastic(
        stream_listing(),
        STREAM_MAPPINGS,
        read_ilm=True,
        ilm={
            "logs": {
                "policy": {"phases": {"delete": {"min_age": "30d"}}},
                "in_use_by": {
                    "data_streams": ["logs-nginx.access-default", "logs-system.auth-default"]
                },
            }
        },
    )
    p, *_ = await discover(transport, kibana())
    by = families(p)
    assert set(by) == {"web", "auth"}
    web = by["web"]
    assert web.family.pattern == "logs-nginx.access-default"
    assert not web.family.daily
    assert web.family.fields == {}  # keyword fields: the ECS names are the right ones
    assert web.kind == "stream"
    assert web.retention.delete_after == "30d"
    assert by["auth"].family.pattern == "logs-system.auth-default"
    assert by["auth"].family.watch is False
    assert p.space == "default"  # the only space, with an alerts index
    assert p.history_window == "30d"
    assert set(p.unclassified) == {
        "metrics-system.cpu-default",
        "logs-elastic_agent.filebeat-default",
    }
    assert reloaded(p) == p.site()
    # the whole thing is a site profile the gateway can work with
    with site.using(p.site()):
        assert site.source_for(Role.WEB) == "web"
        assert site.reads(["logs-nginx.access-default"], Role.WEB)


# --------------------------------------------------------------------------- an empty Elastic


async def test_an_empty_elastic_gets_a_neutral_proposal_and_says_what_is_missing() -> None:
    p, *_ = await discover(elastic(EMPTY_LISTING, {}, spaces=()), kibana())
    assert p.families == ()
    assert p.unclassified == ()
    assert p.space is None
    assert any("no .alerts-security.alerts-<space> index exists" in w for w in p.warnings)
    assert reloaded(p) == SiteSettings()  # nothing to propose: the neutral defaults
    assert "families: []" in render_yaml(p)
    assert "Log families proposed: 0" in render_text(p)


async def test_no_listing_is_a_warning_not_a_crash() -> None:
    p = propose(Inputs())
    assert p.families == ()
    assert p.space is None
    assert any("no index listing was read" in w for w in p.warnings)
    assert reloaded(p) == SiteSettings()


# --------------------------------------------------------------------------- what is sent


READ_PATHS = (
    "/_license",
    "/_resolve/index/",
    "/_mapping/field/",
    "/_security/user/_has_privileges",
)


async def test_only_metadata_reads_are_sent_never_a_search_or_a_write() -> None:
    transport = elastic(daily_listing(), DAILY_MAPPINGS, read_ilm=True)
    server = kibana()
    p, _, _ = await discover(transport, server)
    methods = {(c.method, c.path.split("?")[0]) for c in transport.calls}
    assert not [c for c in transport.calls if c.path.endswith(("_search", "_mget", "_doc"))]
    assert {m for m, _ in methods} == {"GET", "POST"}
    assert [c.path for c in transport.calls if c.method == "POST"] == [
        "/_security/user/_has_privileges"
    ]
    assert [c.path for c in transport.calls[:4]] == [
        "/", "/_license", "/_resolve/index/*", "/_resolve/index/.alerts-security.alerts-*"
    ]  # fmt: skip
    assert transport.calls[-1].path == "/_ilm/policy"  # read_ilm is held
    assert {(c.method, c.path) for c in server.calls} == {
        ("GET", "/s/default/api/status"),
        ("GET", "/s/default/api/spaces/space"),
        ("GET", "/s/default/api/features"),
    }
    assert p.requests == len(transport.calls) + len(server.calls)
    assert all(c.opaque_id.startswith("argus-discover/") for c in transport.calls[1:])


async def test_ilm_is_not_asked_without_the_privilege_and_the_reason_is_said() -> None:
    transport = elastic(daily_listing(), DAILY_MAPPINGS, read_ilm=False)
    p, *_ = await discover(transport, kibana())
    assert not [c for c in transport.calls if "_ilm" in c.path]
    assert any("lacks read_ilm" in w for w in p.warnings)
    assert families(p)["proxy"].retention.delete_after is None
    assert families(p)["proxy"].retention.days_kept == 3  # from the dated indices


async def test_the_mapping_reads_are_capped_and_the_likeliest_come_first() -> None:
    transport = elastic(daily_listing(), DAILY_MAPPINGS)
    p, *_ = await discover(transport, kibana(), max_mappings=2)
    asked = [c.path.split("/_mapping")[0] for c in transport.calls if "_mapping" in c.path]
    assert len(asked) == 2
    assert any("were not examined (--max-mappings 2)" in w for w in p.warnings)
    # a family judged by its name alone says so and keeps the ECS names
    unexamined = [f for f in p.families if any("mapping was not read" in n for n in f.notes)]
    assert unexamined
    assert all(f.confidence is not Confidence.HIGH for f in unexamined)


async def test_each_request_is_in_the_ledger_with_the_discover_purpose() -> None:
    transport = elastic(daily_listing(), DAILY_MAPPINGS)
    _, _, (store, _) = await discover(transport, kibana())
    purposes = {(e.component, e.purpose) for e in store.ledger}
    assert purposes <= {
        ("discover", "discover"),
        ("discover", "selftest"),
        ("discover", "kibana_read"),
    }
    assert all(e.outcome == "ok" for e in store.ledger)
    assert len(store.ledger) == len(transport.calls) + 3  # and Kibana's three reads


async def test_without_kibana_the_elasticsearch_part_still_proposes() -> None:
    p, *_ = await discover(
        elastic(daily_listing(), DAILY_MAPPINGS), None, kibana_note="--no-kibana"
    )
    assert p.space == "default"  # from the alerts alias alone
    assert p.kibana_version is None
    assert p.features is None
    assert any("Kibana was not asked (--no-kibana)" in w for w in p.warnings)


# --------------------------------------------------------------------------- failures are warnings


async def test_a_failing_kibana_read_is_a_warning() -> None:
    server = kibana()
    server.routes = [r for r in server.routes if not r[1].endswith("spaces/space")]  # a 404
    p, *_ = await discover(elastic(daily_listing(), DAILY_MAPPINGS), server)
    assert any("kibana.spaces was not read" in w for w in p.warnings)
    assert p.space == "default"  # from the alerts alias alone
    assert "Kibana's spaces were not read" in p.space_evidence


async def test_a_failing_mapping_read_is_a_warning_and_the_name_still_counts() -> None:
    from argus.gateway.transport import WireResponse

    transport = elastic(daily_listing(), {})
    transport.routes.insert(0, ("_mapping/field", [WireResponse(500, b"{}", 3.0)]))
    p, *_ = await discover(transport, kibana())
    assert any("the mapping of" in w and "was not read" in w for w in p.warnings)
    assert p.families  # judged by name alone: squid, nginx, dns, postfix, sso


async def test_a_failing_listing_is_a_warning_and_nothing_is_proposed() -> None:
    from argus.gateway.transport import WireResponse

    transport = elastic(daily_listing(), DAILY_MAPPINGS)
    transport.routes.insert(0, ("/_resolve/index/*", [WireResponse(503, b"{}", 3.0)]))
    p, *_ = await discover(transport, kibana())
    assert p.families == ()
    assert not p.listing_read
    assert any("the list of indices was not read" in w for w in p.warnings)


async def test_the_elasticsearch_gateway_refuses_when_the_siem_is_not_normal() -> None:
    store = MemoryStore(memory=HealthMemory(state=HealthState.CAUTION, probed_at=T0))
    transport = elastic(daily_listing(), DAILY_MAPPINGS)
    es, _, _, clock = gateways(transport, None, store)
    p = propose(await run.collect(es, None, clock=clock))
    assert p.families == ()  # every discovery read was deferred: nothing was sent
    assert [c for c in transport.calls if c.path != "/"] == []
    assert any("deferred" in w for w in p.warnings)


async def test_a_truncated_listing_is_said() -> None:
    from argus.gateway.discovery import MAX_NAMES

    big = {"indices": [{"name": f"x-{n}-2026.10.30"} for n in range(MAX_NAMES + 1)],
           "aliases": [], "data_streams": []}  # fmt: skip
    p, *_ = await discover(elastic(big, {}), kibana())
    assert any("was cut" in w for w in p.warnings)


# --------------------------------------------------------------------------- the report


async def test_the_text_report_says_what_decided_each_family() -> None:
    p, *_ = await discover(elastic(daily_listing(), DAILY_MAPPINGS, version="8.19.12"), kibana())
    text = render_text(p)
    assert "Elasticsearch 8.19.12; Kibana 8.19.12" in text
    assert "Licence basic (active): writes allowed; paid features" in text
    assert "off" in text
    assert "proxy [proxy] acme-logs-squid-* - high confidence" in text
    assert "the name has squid" in text
    assert "the mapping has" in text
    assert "kept: 3 days from 2026.10.28 to 2026.10.30" in text
    assert "Looked like no log role" in text
    assert f"{p.requests} requests were sent." in text


async def test_a_version_outside_the_supported_range_is_a_warning() -> None:
    p, *_ = await discover(elastic(EMPTY_LISTING, {}, version="7.17.5"), kibana(version="10.1.0"))
    assert any("Elasticsearch 7.17.5 is outside >=8.0,<10" in w for w in p.warnings)
    assert any("Kibana 10.1.0 is outside" in w for w in p.warnings)
    assert not [w for w in propose(Inputs(elastic_version="9.1.0")).warnings if "outside" in w]


async def test_an_expired_licence_is_said() -> None:
    p = propose(Inputs(licence=("platinum", "expired"), now=datetime(2026, 1, 1, tzinfo=UTC)))
    assert any("platinum/expired" in w and "writes need an active licence" in w for w in p.warnings)
    assert "writes not allowed" in render_text(p)


# --------------------------------------------------------------------------- the command


def write_config(tmp_path: Path) -> Path:
    path = tmp_path / "argus.yaml"
    path.write_text("environment: dev\nsiem:\n  url: https://siem.example:9200\n", encoding="utf-8")
    return path


def invoke(*args: str) -> Any:
    from argus.cli import app

    return CliRunner().invoke(app, ["discover", *args])


def test_dry_run_lists_the_requests_and_sends_nothing(tmp_path: Path) -> None:
    result = invoke("--dry-run", "--config", str(write_config(tmp_path)))
    assert result.exit_code == 0, result.output
    out = result.output
    for line in (
        "GET https://siem.example:9200/_resolve/index/*?expand_wildcards=open",
        "/_resolve/index/.alerts-security.alerts-*?expand_wildcards=open,hidden",
        "_license",
        "_mapping/field/",
        "/s/default/api/spaces/space",
        "/s/default/api/features",
        "dry run: nothing was sent",
    ):
        assert line in out
    assert "--no-kibana" not in out
    assert (
        "Kibana: not asked"
        in invoke("--dry-run", "--no-kibana", "-c", str(write_config(tmp_path))).output
    )


def test_write_never_overwrites_without_force(tmp_path: Path) -> None:
    config = write_config(tmp_path)
    (tmp_path / "site.yaml").write_text("site:\n  space: mine\n", encoding="utf-8")
    result = invoke("--write", "--config", str(config))
    assert result.exit_code == 2
    assert "site.yaml exists; --force replaces it" in result.output
    assert (tmp_path / "site.yaml").read_text(encoding="utf-8") == "site:\n  space: mine\n"


def test_the_writer_creates_the_file_and_only_replaces_with_force(tmp_path: Path) -> None:
    from argus.discover import cli

    target = tmp_path / "site.yaml"
    cli._write(target, "site:\n  space: a\n", force=False)
    assert target.read_text(encoding="utf-8") == "site:\n  space: a\n"
    with pytest.raises(typer.Exit) as caught:
        cli._write(target, "site:\n  space: b\n", force=False)
    assert caught.value.exit_code == 2
    assert target.read_text(encoding="utf-8") == "site:\n  space: a\n"
    cli._write(target, "site:\n  space: c\n", force=True)
    assert target.read_text(encoding="utf-8") == "site:\n  space: c\n"
    link = tmp_path / "link.yaml"
    link.symlink_to(target)
    with pytest.raises(typer.Exit) as linked:
        cli._write(link, "x", force=True)  # never through a link
    assert linked.value.exit_code == 1


def test_the_written_file_is_read_beside_the_config(tmp_path: Path) -> None:
    config = write_config(tmp_path)
    transport = elastic(daily_listing(), DAILY_MAPPINGS)

    async def go() -> Proposal:
        es, lane, _, clock = gateways(transport, kibana())
        return propose(await run.collect(es, lane, clock=clock))

    proposal = asyncio.run(go())
    (tmp_path / "site.yaml").write_text(render_yaml(proposal), encoding="utf-8")
    settings = load_settings(config, env_file=None)
    assert settings.site == proposal.site()
    assert {f.name for f in settings.site.families} >= {"proxy", "web", "dns", "auth"}


async def test_a_quiet_hour_is_refused_before_anything_is_sent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from argus.discover import cli

    class Night:
        @staticmethod
        def now(tz: Any = None) -> datetime:
            return datetime(2026, 10, 30, 0, 30, tzinfo=UTC)

    monkeypatch.setattr(cli, "datetime", Night)
    result = invoke("--config", str(write_config(tmp_path)))
    assert result.exit_code == 1
    assert "not between 00:00 and 01:30 UTC" in result.output


# ------------------------------------------------------------------ the command, end to end


async def a_proposal() -> Proposal:
    es, lane, _, clock = gateways(
        elastic(daily_listing(), DAILY_MAPPINGS, spaces=("acme-soc",)),
        kibana(("default", "acme-soc")),
    )
    return propose(await run.collect(es, lane, clock=clock))


@pytest.fixture
def daytime(monkeypatch: pytest.MonkeyPatch) -> None:
    """Not the quiet hours, whatever the clock says."""
    from argus.discover import cli

    monkeypatch.setattr(cli, "in_quiet_hours", lambda now: False)


def returning(monkeypatch: pytest.MonkeyPatch, outcome: Any) -> None:
    from argus.discover import cli

    async def fake(settings: object, max_mappings: int, no_kibana: bool) -> Proposal:
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome  # type: ignore[no-any-return]

    monkeypatch.setattr(cli, "_discover", fake)


def test_the_command_prints_the_report_and_the_yaml_and_writes_on_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, daytime: None
) -> None:
    proposal = asyncio.run(a_proposal())
    returning(monkeypatch, proposal)
    config = write_config(tmp_path)
    shown = invoke("--config", str(config))
    assert shown.exit_code == 0, shown.output
    assert "Log families proposed: 5" in shown.output
    assert "site:\n  # " in shown.output
    assert not (tmp_path / "site.yaml").exists()  # nothing is written unless asked
    written = invoke("--write", "--config", str(config))
    assert written.exit_code == 0
    assert f"written: {tmp_path / 'site.yaml'}" in written.output
    assert (tmp_path / "site.yaml").read_text(encoding="utf-8") == render_yaml(proposal)
    assert load_settings(config, env_file=None).site == proposal.site()
    again = invoke("--write", "--config", str(config))
    assert again.exit_code == 2  # never over a file
    forced = invoke("--write", "--force", "--config", str(config))
    assert forced.exit_code == 0


def test_nothing_is_written_when_the_listing_could_not_be_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, daytime: None
) -> None:
    returning(monkeypatch, propose(Inputs(warnings=("the list of indices was not read: x",))))
    result = invoke("--write", "--config", str(write_config(tmp_path)))
    assert result.exit_code == 1
    assert "nothing is proposed" in result.output
    assert not (tmp_path / "site.yaml").exists()


@pytest.mark.parametrize("failure", ["refused", "gateway", "config"])
def test_a_refusal_or_a_failure_is_an_error_message_and_an_exit_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, daytime: None, failure: str
) -> None:
    from argus.config.errors import ConfigError
    from argus.discover import cli
    from argus.gateway.errors import StoppedError

    outcome = {
        "refused": cli._RefusedError("the SIEM is caution: discovery needs NORMAL"),
        "gateway": StoppedError("the SIEM is in STOP"),
        "config": ConfigError("siem.api_key is not set"),
    }[failure]
    returning(monkeypatch, outcome)
    result = invoke("--config", str(write_config(tmp_path)))
    assert result.exit_code == (2 if failure == "config" else 1)
    assert "error:" in result.output

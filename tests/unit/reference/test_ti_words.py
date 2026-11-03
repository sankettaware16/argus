"""Where threat-intel sources show: the report's sentences, the Discover link, the sync job, the
doctor (P4-D4 part b, D-293). ACME's sentences are what they were."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

import pytest
from pydantic import SecretStr

from argus import site
from argus.config.settings import Settings, SiemSettings
from argus.doctor import siem_check
from argus.incident import discover as d
from argus.reference import jobs
from argus.reference.templates import lookup_params
from argus.report import facts as fx
from argus.site import SiteSettings, TiSource
from tests.unit.report.kit import lookup_params as legacy_params
from tests.unit.report.kit import request, row

pytestmark = pytest.mark.unit
ELASTIC = TiSource.model_validate({"index": "logs-ti_*", "schema": "ecs", "mode": "lookup"})
OWN = TiSource.model_validate({"index": "acme-ioc", "schema": "ioc", "mode": "lookup"})
AT = datetime(2026, 10, 15, 12, tzinfo=UTC)
CFG = d.Config(kibana_url="https://kibana.example", space="s1")


def with_params(params: Any) -> Any:
    base = row("ti.lookup")
    return fx.EvidenceRow(**{**base.__dict__, "params": params.model_dump(mode="json")})


# ----------------------------------------------------------------------------- the report


def test_acmes_sentences_name_its_source_as_before() -> None:
    legacy = row("ti.lookup")
    assert fx.ti_where(legacy) == "acme-threat-intel"
    assert fx.ti_where(None) == "the threat lists"
    req = request("ti.lookup", 2)
    prov = fx.provenance(req, legacy)
    assert "acme-threat-intel" in prov.line
    done = fx.check(req, legacy, [], prov, fx.Keys({}, {}, frozenset()))
    assert done.sentence == "Checked the indicators on acme-threat-intel: found 0 rows."


def test_a_check_names_the_sources_its_request_asked() -> None:
    with site.using(SiteSettings(ti_sources=(ELASTIC, OWN))):
        both = with_params(lookup_params([ELASTIC, OWN], ("45.9.9.9",)))
        assert fx.ti_where(both) == "logs-ti_*, acme-ioc"
        one = with_params(lookup_params([ELASTIC], ("45.9.9.9",)))
        req = request("ti.lookup", 2)
        done = fx.check(
            req, one, [], fx.provenance(req, one), fx.Keys({}, {}, frozenset()), other=True
        )
        assert done.sentence == "Checked more indicators on logs-ti_*: found 0 rows."


def test_a_listed_row_is_told_with_the_source_and_whichever_schema_it_has() -> None:
    ecs = {"@timestamp": "2026-10-12T00:00:00Z",
           "threat": {"indicator": {"type": "ipv4-addr", "ip": "77.221.155.150"}}}  # fmt: skip
    ioc = {"ioc_type": "ip", "ioc_value": "45.9.9.9", "intel_source": "feodo"}
    with site.using(SiteSettings(ti_sources=(ELASTIC, OWN))):
        params = lookup_params([ELASTIC, OWN], ("45.9.9.9", "77.221.155.150"))
        r = fx.EvidenceRow(**{**row("ti.lookup", "ok").__dict__, "row_count": 2,
                              "params": params.model_dump(mode="json"),
                              "snapshot": {"rows": [{"_source": ecs}, {"_source": ioc}]},
                              })  # fmt: skip
        got = fx.observations(request("ti.lookup", 2), r)
    (fact,) = got
    assert fact.sentence == "logs-ti_*, acme-ioc lists 2 of the indicators looked up."
    assert len(fact.values) == 2


def test_the_fresh_reading_follows_the_lookup_sources() -> None:
    body = {"context": {"pack": {"ti": {"answers": [{"value": "1.2.3.4", "sources": {
        "acme-threat-intel": {"no_match": {"stale": False}}}}]}}}}  # fmt: skip
    assert fx.lookups_fresh(body) is True
    stale = {"context": {"pack": {"ti": {"answers": [{"value": "1.2.3.4", "sources": {
        "acme-threat-intel": {"no_match": {"stale": True}}}}]}}}}  # fmt: skip
    assert fx.lookups_fresh(stale) is False
    assert fx.lookups_fresh({}) is None
    with site.using(SiteSettings()):
        assert fx.lookups_fresh(body) is None  # no lookup source: nothing to be fresh


def test_no_sources_is_a_reason_a_reviewer_can_read() -> None:
    assert "no threat-intel source" in fx.REASONS["no_sources"]
    assert "site.ti_sources" in fx.RESOLVERS["no_sources"]


# ----------------------------------------------------------------------------- the Discover link


def test_the_link_for_acmes_look_up_is_the_one_it_always_was() -> None:
    q = d.for_template(CFG, "ti.lookup", 1, {"values": ["77.1.2.3"]}, AT)
    assert q is not None
    assert q.index == "acme-threat-intel"
    assert q.text == 'FROM acme-threat-intel | WHERE ioc_value.keyword IN ("77.1.2.3") | LIMIT 100'
    assert q.other == 'ioc_value.keyword : "77.1.2.3"'


def test_the_link_for_an_ecs_look_up_asks_the_fields_of_each_kind() -> None:
    params = lookup_params([ELASTIC], ("77.1.2.3", "bad.example")).model_dump(mode="json")
    q = d.for_template(CFG, "ti.lookup", 1, params, AT)
    assert q is not None
    assert q.index == "logs-ti_*"
    assert "threat.indicator.ip" in q.text
    assert "threat.indicator.url.domain" in q.text
    assert "ioc_value" not in q.text


def test_a_look_up_with_no_source_to_link_to_has_no_link() -> None:
    with site.using(SiteSettings()):
        assert d.for_template(CFG, "ti.lookup", 1, {"values": ["77.1.2.3"]}, AT) is None


# ----------------------------------------------------------------------------- jobs and doctor


def test_the_sync_with_no_source_says_so_and_asks_nothing() -> None:
    class Never:
        def begin(self) -> Any:
            raise AssertionError("no source: no transaction")

    class Gate:
        async def run(self, *a: Any, **k: Any) -> Any:
            raise AssertionError("no source: no request")

    with site.using(SiteSettings()):
        got = asyncio.run(jobs.sync_ti(Never(), Gate()))  # type: ignore[arg-type]
    assert got == {"sources": 0, "mirror": {}, "newest": {}}


def test_doctor_says_the_siem_address_is_not_set_and_fails_a_key_without_one() -> None:
    quiet = asyncio.run(siem_check(Settings.model_construct(siem=SiemSettings())))
    address = next(r for r in quiet if r.name == "the SIEM address")
    assert address.ok
    assert "not configured" in address.detail
    keyed = SiemSettings(api_key=SecretStr("k"))
    bad = asyncio.run(siem_check(Settings.model_construct(siem=keyed)))
    assert not next(r for r in bad if r.name == "the SIEM address").ok
    set_ = SiemSettings(url="https://siem.example:9200")
    good = asyncio.run(siem_check(Settings.model_construct(siem=set_)))
    assert (
        next(r for r in good if r.name == "the SIEM address").detail == "https://siem.example:9200"
    )


def test_the_legacy_kit_params_are_the_ioc_default() -> None:
    assert legacy_params("45.9.9.9").model_dump(mode="json").keys() == {"values", "size"}

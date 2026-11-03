"""P4-D1 part 2 review F5 (D-285): ``LogFamily.ignore_above`` and ``types`` are read where the old
256 was. A value longer than a family's ``ignore_above`` in one of its keyword fields is not
indexed: the validator refuses it (``UnsupportedValueError``) and a template's parameter check
names it (``path_chars``), so a request never carries one; a site with a larger limit is not capped
by the default, and one with a smaller limit is not let through. ACME's family says 256, as
before."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from argus import site
from argus.context import batch1, paths, source_events
from argus.gateway.errors import UnsupportedValueError
from argus.gateway.templates import CostClass, Endpoint, Family, Spec
from argus.gateway.validator import FinalRequest, validate
from argus.site import LogFamily, Role, SiteSettings
from tests.unit.gateway.test_validator import FORCED

pytestmark = pytest.mark.unit

SPEC = Spec(
    name="t.log", version=1, endpoint=Endpoint.SEARCH, family=Family.LOG, cost=CostClass.HEAVY,
    filter_fields=frozenset({"url.domain.keyword", "url.path", "url.original", "source.ip",
                             "event.action.keyword", "other.field", "@timestamp"}),
    aggregate_fields=frozenset(), return_fields=frozenset({"@timestamp"}),
    sort_fields=frozenset({"@timestamp"}), max_size=10,
)  # fmt: skip
START, END = datetime(2026, 10, 9, 9, tzinfo=UTC), datetime(2026, 10, 9, 10, tzinfo=UTC)


def accepted(index: str, field: str, length: int) -> bool:
    since = {"range": {"@timestamp": {"gte": "2026-10-09T00:00:00Z", "lt": "2026-10-10T00:00:00Z"}}}
    body: dict[str, Any] = {
        "size": 0, "track_total_hits": False,
        "query": {"bool": {"filter": [{"term": {field: "x" * length}}, since]}},
    }  # fmt: skip
    try:
        validate(FinalRequest(SPEC, body=body, indices=(index,), url_params=FORCED))
    except UnsupportedValueError:
        return False
    return True


def family(name: str, role: Role, pattern: str, **more: Any) -> LogFamily:
    return LogFamily(name=name, role=role, pattern=pattern, **more)


def test_acmes_limits_are_what_they_were() -> None:
    squid, nginx = "acme-logs-squid-2026.10.09", "acme-logs-nginx-2026.10.09"
    assert accepted(squid, "event.action.keyword", 256)
    assert not accepted(squid, "event.action.keyword", 257)
    assert accepted(nginx, "url.domain.keyword", 256)
    assert not accepted(nginx, "url.domain.keyword", 257)
    assert accepted(squid, "source.ip", 1024)  # an address field: Elasticsearch's own default
    assert not accepted(squid, "source.ip", 1025)
    assert accepted("alerts", "url.domain.keyword", 256)  # not a log family's index: the defaults
    assert not accepted("alerts", "url.domain.keyword", 257)
    assert accepted("alerts", "other.field", 1024)
    assert not accepted("alerts", "other.field", 1025)


def test_a_larger_limit_of_the_family_is_not_capped_by_the_default() -> None:
    big = SiteSettings(families=(family("proxy", Role.PROXY, "p-*", ignore_above=1024),))
    with site.using(big):
        assert accepted("p-2026.10.09", "event.action.keyword", 300)  # was refused at 256
        assert accepted("p-2026.10.09", "event.action.keyword", 1024)
        assert not accepted("p-2026.10.09", "event.action.keyword", 1025)


def test_a_smaller_limit_refuses_what_the_template_would_pass() -> None:
    small = SiteSettings(
        families=(
            family("web", Role.WEB, "w-*", ignore_above=128),
            family("proxy", Role.PROXY, "p-*"),
        )
    )
    with site.using(small):
        assert not accepted("w-2026.10.09", "url.domain.keyword", 129)
        assert not accepted("w-2026.10.09", "url.path", 200)  # a keyword field: not 1024
        assert accepted("w-2026.10.09", "url.path", 128)
        assert accepted("p-2026.10.09", "event.action.keyword", 256)  # another family, its own
        assert accepted("w-2026.10.09", "source.ip", 500)  # not a keyword


def test_the_declared_type_decides_which_fields_are_keywords() -> None:
    agent = SiteSettings(
        families=(
            family("proxy", Role.PROXY, "logs-squid.access-default",
                   types={"url.original": "keyword"}, ignore_above=512),
        )
    )  # fmt: skip
    with site.using(agent):
        # url.original is a keyword here (no .keyword sub-field): the family's limit
        assert accepted("logs-squid.access-default", "url.original", 512)
        assert not accepted("logs-squid.access-default", "url.original", 513)
    plain = SiteSettings(families=(family("proxy", Role.PROXY, "logs-squid.access-default"),))
    with site.using(plain):  # by default url.original is analysed text: no keyword limit
        assert accepted("logs-squid.access-default", "url.original", 1024)
    assert agent.families[0].value_limit("url.original") == 512
    assert agent.families[0].value_limit("event.action.keyword") == 512
    assert agent.families[0].value_limit("source.ip") is None
    assert agent.families[0].value_limit("not.a.field") is None


def test_a_request_over_two_families_takes_the_smaller_limit() -> None:
    two = SiteSettings(
        families=(
            family("a", Role.PROXY, "a-*", ignore_above=1024),
            family("b", Role.PROXY, "b-*", ignore_above=300),
        )
    )
    with site.using(two):
        assert site.value_limit(("a-2026.10.09", "b-2026.10.09"), "event.action.keyword") == 300
        assert site.value_limit(("a-2026.10.09",), "event.action.keyword") == 1024
        assert site.value_limit(("zzz",), "event.action.keyword") is None


# --------------------------------------------------------------------------- the templates


def _web(ignore_above: int, **more: Any) -> SiteSettings:
    return SiteSettings(
        families=(family("nginx", Role.WEB, "n-*", ignore_above=ignore_above, **more),)
    )


def test_the_path_limit_is_the_web_familys() -> None:
    assert paths.path_chars() == 256  # ACME: the old PATH_CHARS
    assert paths.path_chars() == paths.PATH_CHARS
    with site.using(_web(128)):
        assert paths.path_chars() == 128
        assert paths.path_chars("nginx") == 128
        params = {"ip": "1.2.3.4", "site": "a.example", "start": START, "end": END}
        paths.PathParams(**params, paths=("/" + "p" * 127,))
        with pytest.raises(ValueError, match="1 to 128 characters"):
            paths.PathParams(**params, paths=("/" + "p" * 199,))  # passed at the fixed 256
        with pytest.raises(ValueError, match="site is 1 to 128"):
            paths.PathParams(**{**params, "site": "s" * 200}, paths=("/x",))
    with site.using(_web(1024)):  # a family that indexes more is not capped at 256
        paths.PathParams(
            ip="1.2.3.4", site="s" * 300, paths=("/" + "p" * 400,), start=START, end=END
        )


def test_paths_are_sorted_and_kept_once() -> None:
    got = paths.PathParams(
        ip="1.2.3.4", site="a.example", paths=("/b", "/a", "/b"), start=START, end=END
    )
    assert got.paths == ("/a", "/b")


def test_the_plan_leaves_out_a_path_the_family_does_not_index() -> None:
    now = END + timedelta(hours=7)
    long_path = "/" + "q" * 150  # long enough not to be a cut field fact (100), under 256
    with site.using(_web(128)):
        plan = batch1.paths_task("1.2.3.4", "a.example", [long_path, "/ok"], END, now,
                                 from_field_facts=False)  # fmt: skip
        assert plan.left_out == ((long_path, "too_long"),)
    plan = batch1.paths_task("1.2.3.4", "a.example", [long_path, "/ok"], END, now,
                             from_field_facts=False)  # fmt: skip
    assert plan.left_out == ()  # ACME's family indexes 256


def test_source_events_narrowing_follows_the_family() -> None:
    pair = SiteSettings(
        families=(
            family("small", Role.WEB, "s-*", ignore_above=64),
            family("big", Role.WEB, "b-*", ignore_above=512),
        )
    )
    value = "v" * 100
    with site.using(pair):
        ok = source_events.SourceParams(
            source="big", ip="1.2.3.4", start=START, end=END, narrow=(("url.domain", value),)
        )
        assert ok.narrow == (("url.domain", value),)
        with pytest.raises(ValueError, match="1 to 64 characters"):
            source_events.SourceParams(
                source="small", ip="1.2.3.4", start=START, end=END, narrow=(("url.domain", value),)
            )

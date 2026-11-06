"""Naming v2 on the Inbox: an investigation's row is titled by what it did (its key and its
evidence flags), never by its rule's name; the rule is shown as the rule's, on line 2. The API's
shape holds the two lines. Made-up values only."""

from __future__ import annotations

from typing import Any

from hypothesis import given
from hypothesis import strategies as st

from argus.cases import naming
from argus.web import queries
from argus.web.v1 import models as m
from argus.web.v1 import views
from tests.unit.web.test_web_units import summary

RULE = "Proxy: POST to a bare address (possible beacon)"


def test_a_row_says_what_happened_not_the_rule() -> None:
    s = summary(rule_name=RULE, group_key='[["source.ip","10.0.4.12"]]',
                raised_flags=[naming.BEACON, "not a flag"], alert_count=12)  # fmt: skip
    s.key_fields.extend(queries.key_fields(s.group_key))
    out = views.investigation(s)
    assert out.title == "10.0.4.12 · beacon-timed"
    assert out.key_words == "from 10.0.4.12"
    assert out.rule_name == RULE  # the rule stays, as the rule's own words
    assert "POST" not in out.title


def test_the_api_shape_requires_both_lines() -> None:
    fields = m.InvestigationOut.model_json_schema()
    assert {"title", "key_words"} <= set(fields["required"])
    assert fields["properties"]["title"]["type"] == "string"


@given(st.lists(st.tuples(st.sampled_from(["source.ip", "user.name", "destination.ip", "x"]),
                          st.text(max_size=30)), max_size=3),
       st.one_of(st.none(), st.lists(st.one_of(st.text(max_size=20), st.integers()), max_size=4)),
       st.integers(0, 10**6))  # fmt: skip
def test_any_stored_row_gives_a_short_title(pairs: list[Any], flags: Any, alerts: int) -> None:
    s = summary(raised_flags=flags, alert_count=alerts)
    s.key_fields.extend(pairs)
    out = views.investigation(s)
    assert 1 <= len(out.title) <= naming.FRONT
    assert out.key_words


def test_a_row_keyed_on_the_destination_says_to_and_an_account_is_never_named() -> None:
    to = summary(group_key='[["destination.ip","203.0.113.5"]]', alert_count=40)
    to.key_fields.extend(queries.key_fields(to.group_key))
    out = views.investigation(to)
    assert (out.title, out.key_words) == ("→ 203.0.113.5 · 40 alerts", "to 203.0.113.5")
    site = summary(group_key='[["url.domain","www.example.edu"]]', alert_count=3)
    site.key_fields.extend(queries.key_fields(site.group_key))
    assert views.investigation(site).key_words == "to www.example.edu"
    who = summary(group_key='[["source.user.name","jdoe"],["destination.ip","203.0.113.5"]]',
                  alert_count=4)  # fmt: skip
    who.key_fields.extend(queries.key_fields(who.group_key))
    out = views.investigation(who)
    assert (out.title, out.key_words) == (
        "1 account → 203.0.113.5 · 4 alerts", "from 1 account to 203.0.113.5",
    )  # fmt: skip
    assert "jdoe" not in out.title + out.key_words

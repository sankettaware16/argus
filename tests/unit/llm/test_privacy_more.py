"""P1: branches and limits mutation testing showed untested (D-040), including the URL query
rule for proxy URLs that hold blanks (a fix: their values were sent)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from argus.llm.privacy import Privacy, _cut, quote, template_words
from tests.unit.llm.test_privacy import dossier, web_dossier

pytestmark = pytest.mark.unit


def lines(privacy: Privacy, body: dict[str, Any], start: str) -> list[str]:
    return [x for x in privacy.request([body]).text.splitlines() if x.startswith(start)]


def rule(privacy: Privacy, name: Any) -> str:
    body = dossier()
    body["facts"]["rule_name"] = name
    return lines(privacy, body, "Rule:")[0].split(" \u00b7 ")[0]


def url_line(privacy: Privacy, url: str, body: dict[str, Any] | None = None) -> str:
    body = body or dossier()
    body["context"]["pack"]["fields"]["url.original"]["top"] = [[url, 1]]
    return lines(privacy, body, "- url.original")[0]


@pytest.mark.parametrize(
    ("url", "shown"),
    [
        ("/s?q=exam marks 2026&x=1", '"/s?q=...&x=..."'),  # a blank: still keys only
        ("http://a b/x?q=1", '"http://a b/x?q=..."'),
        ("http://[::1/x?q=secret", '"http://[::1/x?q=..."'),  # unreadable: keys only too
        ("tp8://evil.example/?q=1", '"I1.HOST_1://evil.example/?q=..."'),
        ("/p?=1&a=2", '"/p?...&a=..."'),
        ("mailto:a@b.org", '"mailto:I1.EMAIL_1"'),
        ("http://a\tb.example/x", '"http://a\\tb.example/x"'),
    ],
)
def test_proxy_urls_send_keys_only(privacy: Privacy, url: str, shown: str) -> None:
    assert url_line(privacy, url) == f"- url.original (1): {shown} x1"


def test_web_urls_with_blanks_keep_their_values(privacy: Privacy) -> None:
    line = url_line(privacy, "/s?q=1 OR 1=1&x=1", web_dossier())
    assert line == '- url.original (1): "/s?q=1 OR 1=1&x=1" x1'


def test_decoded_paths_follow_the_url_rule(privacy: Privacy) -> None:
    body = dossier()
    body["context"]["pack"]["web"] = {"decoded_paths": ["/a?q=secret"]}
    assert lines(privacy, body, "- decoded paths") == ['- decoded paths: "/a?q=..."']


def test_credentials_in_free_text(privacy: Privacy) -> None:
    assert rule(privacy, "see http://bob:pw@evil.example/x") == (
        'Rule: "see http://I1.CRED_1@evil.example/x"'
    )


def test_control_and_separator_characters_are_dropped(privacy: Privacy) -> None:
    name = "a\x07b\u0378c\u2028d\ud800e\n\tf\u200bg\ue000h\u2029"
    assert rule(privacy, name) == 'Rule: "abcde\\n\\tfgh"'


def test_quote_leaves_other_text_alone() -> None:
    assert quote("X") == '"X"'


def test_a_cut_moves_off_a_pseudonym_without_blanks() -> None:
    assert _cut("/" * 94 + "I1.IP_12345" + "/" * 20, 100) == "/" * 94 + " […]"


def test_a_replacement_after_one_character_is_set_apart(privacy: Privacy) -> None:
    assert rule(privacy, "x10.20.3.4") == 'Rule: "x I1.IP_1"'


def test_rules_and_steps_without_text(privacy: Privacy) -> None:
    assert rule(privacy, None) == 'Rule: "unnamed rule"'
    body = dossier()
    body["report"]["steps"] = [{"number": 1, "status": "answered"}]
    text = privacy.request([body]).text
    assert '\n1. [answered] ""\n   found: ""\n' in text
    body["report"] = {"summary": ["x"]}
    text = privacy.request([body]).text
    assert "\nThe rule's note has no investigation steps.\nSummary:" in text


def test_alerts_without_a_first_time_and_counts_unlike_the_list(privacy: Privacy) -> None:
    body = dossier()
    del body["facts"]["first_event_at"]
    body["facts"]["entity_counts"] = {"ip": 99}
    body["context"]["supernode_entities"] = 5
    text = privacy.request([body]).text
    assert "Alerts: ~1,200 over 45 min; duplicates 0" in text
    assert "; ip 99: " in text
    assert "entities shared with very many others: 5;" in text


def test_a_field_that_is_not_a_mapping(privacy: Privacy) -> None:
    body = dossier()
    body["context"]["pack"]["fields"] = {"source.ip": [1, 2]}
    assert lines(privacy, body, "- source.ip") == ["- source.ip (?): "]


def test_signals_without_a_plain_name(privacy: Privacy) -> None:
    body = dossier()
    body["signals"] = [
        {"name": "Bad Name", "status": "known", "value": 3},
        {"status": "known", "value": 4},
    ]
    text = privacy.request([body]).text
    assert '\n- "Bad Name": 3\n' in text
    assert '\n- "?": 4\n' in text


def test_heuristics_lists_maps_and_flags(privacy: Privacy) -> None:
    body = dossier()
    body["context"]["pack"]["heuristics"] = {"l": list(range(12)), "m": {"a": 1, "b": 2}, "t": True}
    assert lines(privacy, body, "Proxy heuristics") == [
        "Proxy heuristics: l: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], m: {a: 1, b: 2}, t: yes"
    ]


def test_web_lists_with_several_values(privacy: Privacy) -> None:
    body = dossier()
    body["context"]["pack"]["web"] = {
        "categories": ["a", "b"],
        "naxsi": [{"id": 1, "class": "x", "alerts": 2}, {"id": 3, "class": "y", "alerts": 4}],
    }
    assert lines(privacy, body, "- request categories") == ['- request categories: "a"; "b"']
    assert lines(privacy, body, "- WAF") == [
        '- WAF (naxsi) matches: rule 1 ("x"): 2 alerts; rule 3 ("y"): 4 alerts'
    ]


def test_threat_intel_shapes(privacy: Privacy) -> None:
    body = dossier()
    body["context"]["pack"]["ti"] = {
        "answers": [
            {
                "value": "1.1.1.1",
                "sources": {
                    "b": {"no_match": {}},
                    "a": {
                        "match": [
                            {"type": "ip", "first_seen": "2026-10-14T20:30:00Z",
                             "last_seen": "2026-10-14T21:30:00Z", "description": "one"},
                            {"type": "ip", "description": "two"},
                        ]
                    },
                    "c": None,
                },
            }
        ]
    }  # fmt: skip
    assert lines(privacy, body, "- value") == [
        '- value "1.1.1.1": a: match (ip, first seen t0+0m, last seen t0+60m: "one"; ip: "two");'
        " b: no_match; c: unknown"
    ]


def test_kibana_times_with_seconds(privacy: Privacy) -> None:
    assert rule(privacy, "at Oct 14, 2026 @ 20:40:15") == 'Rule: "at t0+10m"'


def test_template_words_include_the_parts() -> None:
    assert "file" in template_words()  # only in display.PARTS ("file hashes")


def known(name: str, value: Any) -> dict[str, Any]:
    return {"name": name, "status": "known", "value": value}


CAPS: list[tuple[str, int, Callable[[dict[str, Any], str], None], str]] = [
    ("shown", 160, lambda b, v: b["report"]["steps"][0].update(shown=[v]), "   shown: "),
    ("description", 200, lambda b, v: b["context"]["pack"]["ti"]["answers"][0]["sources"]
     ["abuse-ioc"]["match"][0].update(description=v), "- ip 8.8.8.8"),
    ("naxsi class", 80, lambda b, v: b["context"]["pack"].update(web={"naxsi": [{"class": v}]}),
     "- WAF"),
    ("group key", 200, lambda b, v: b["facts"].update(group_key=v), "Grouped by: "),
    ("count", 40, lambda b, v: b["facts"].update(alert_count=v), "Alerts: "),
    ("real", 40, lambda b, v: b["facts"].update(risk_score=v), "Rule: "),
    ("exact", 40, lambda b, v: b["report"]["steps"][0].update(number=v), "\"y"),
    ("word", 80, lambda b, v: b["facts"].update(severity=v), "Rule: "),
    ("signal name", 80, lambda b, v: b.update(signals=[known(v.upper(), 1)]), "- \"Y"),
    ("signal value", 120, lambda b, v: b.update(signals=[known("s", v)]), "- s: "),
    ("entity", 200, lambda b, v: b["facts"].update(entities={"x": [v]}), "Entities: "),
    ("ip text", 80, lambda b, v: b["facts"].update(entities={"ip": [v]}), "Entities: "),
    ("domain", 120, lambda b, v: b["facts"].update(entities={"domain": [v]}), "Entities: "),
]  # fmt: skip


@pytest.mark.parametrize(("name", "cap", "put", "start"), CAPS, ids=[c[0] for c in CAPS])
def test_each_cap_is_exact(
    privacy: Privacy, name: str, cap: int, put: Callable[[dict[str, Any], str], None], start: str
) -> None:
    for length, cut in ((cap, False), (cap + 1, True)):
        body = dossier()
        put(body, "y" * length)
        line = next(x for x in privacy.request([body]).text.splitlines() if x.startswith(start))
        longest = max(len(r) for r in line.replace('"', " ").split(" ") if set(r.lower()) == {"y"})
        assert longest == (cap - 4 if cut else cap), (name, length, longest)


@pytest.mark.parametrize(
    ("url", "shown"),
    [
        ("http://x.org/a?u=http://b.example/c", '"http://x.org/a?u=..."'),
        ("http://x.org:99999/a?q=1", '"http://x.org:99999/a?q=..."'),
    ],
)
def test_more_url_edges(privacy: Privacy, url: str, shown: str) -> None:
    assert url_line(privacy, url) == f"- url.original (1): {shown} x1"


def test_a_second_scheme_in_a_web_url_is_kept(privacy: Privacy) -> None:
    line = url_line(privacy, "http://x.org/a?u=http://b.example/c", web_dossier())
    assert line == '- url.original (1): "http://x.org/a?u=http://b.example/c" x1'


def test_an_entity_without_a_value(privacy: Privacy) -> None:
    body = dossier()
    body["facts"]["entities"] = {"x": [None]}
    assert lines(privacy, body, "Entities") == ["Entities: x 1: (none)"]


def test_a_domain_field_holding_an_address(privacy: Privacy) -> None:
    body = dossier()
    body["context"]["pack"]["fields"]["url.domain"] = {"top": [["10.20.3.4", 1]]}
    assert lines(privacy, body, "- url.domain") == ["- url.domain (?): I1.IP_1 x1"]


def test_the_legend_of_credentials_in_text(privacy: Privacy) -> None:
    body = dossier()
    body["facts"]["rule_name"] = "see http://bob:pw@evil.example/x"
    assert "\n- I1.CRED_1: credentials in a URL\n" in privacy.request([body]).text

"""Where the sanitizer finds identifiers, context by context (synthetic data; found missing by
mutation testing).

The golden document plants each identifier in several places, so one harvesting path can stand in
for another. Each test here puts an identifier in exactly one context and checks what follows from
it: its free-text mention is replaced, its value maps to the exact pseudonym, or exactly these
identifiers are harvested (the leak-scan denylist).
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from argus.fixtures import SANITIZER_VERSION, FixturePolicy, Sanitizer, Tokenizer, walk_strings
from argus.fixtures.sanitizer import SanitizerError
from tests.conftest import REPO_ROOT

KEY = b"k" * 32
TOKENS = Tokenizer(KEY)
POLICY = FixturePolicy(
    site_prefixes=("192.0.2.0/24",),
    campus_domains=("campus.ac.in",),
    keep_domains=("vendor-cdn.example",),
    literals={"Campus University": "Example University"},
    fields={
        "host": ("host.name", "*.hostname"),
        "user": ("user.name", "approval.reviewer", "*.auditor.name"),
        "email": ("user.email",),
        "place": ("source.site.department",),
        "org": ("organization.name",),
        "domain": ("destination.domain",),
        "id": ("_id", "kibana.alert.uuid"),
    },
)


def _sanitizer(*docs: Any, policy: FixturePolicy = POLICY) -> Sanitizer:
    s = Sanitizer(policy, KEY)
    s.harvest(list(docs))
    return s


def _user(name: str) -> str:
    """The pseudonym of an account name that is not a kept one."""
    return TOKENS.token("user", name.lower(), "u-")


def _replaced(s: Sanitizer, name: str, pseudonym: str) -> None:
    assert s.map_text(f"seen {name} today") == f"seen {pseudonym} today"


# ------------------------------------------------------------------ provenance


def test_the_committed_fixtures_were_made_by_this_sanitizer_version() -> None:
    """A change to the output comes with a new version and regenerated fixtures."""
    manifest = json.loads((REPO_ROOT / "tests/fixtures/alerts/MANIFEST.json").read_text())
    assert manifest["sanitizer_version"] == SANITIZER_VERSION


# ------------------------------------------------------------------ walking


def test_walk_strings_yields_every_string_value_with_its_dotted_path() -> None:
    doc = {"host": {"name": "lab-pc-07"}, "tags": ["a", {"b": "c"}], "n": 3, "ok": None}
    assert list(walk_strings(doc)) == [("host.name", "lab-pc-07"), ("tags", "a"), ("tags.b", "c")]
    assert list(walk_strings("x")) == [("", "x")]
    assert list(walk_strings({"a": "x"}, "root")) == [("root.a", "x")]


def test_mapping_keys_are_harvested() -> None:
    s = _sanitizer({"mailbox_sizes": {"kate7@campus.ac.in": 3}})
    assert "kate7@campus.ac.in" in s.harvested
    _replaced(s, "kate7", _user("kate7"))


def test_a_sanitizer_that_harvested_nothing_maps_what_it_detects_and_keeps_the_rest() -> None:
    s = Sanitizer(POLICY, KEY)
    out = s.sanitize({"labels": {"lab-pc-07": "on", "meta": "x"}, "message": "from 10.1.2.3"})
    assert out == {
        "labels": {"lab-pc-07": "on", "meta": "x"},
        "message": f"from {s.ips.map_text('10.1.2.3')}",
    }
    assert s.dictionary == {}


# ------------------------------------------------------------------ boundaries in text

_URL = "http://alice:hunter2@lab.campus.ac.in/x"  # fake-secret (synthetic)


@pytest.mark.parametrize(
    ("prefix", "identifier"),
    [
        *[("%22", i) for i in (_URL, "lab.campus.ac.in", "lab-pc-07", "Campus University")],
        *[
            (e, i)
            for e in (" \\n", "\\t", "x\\r\\n")
            for i in (_URL, "lab-pc-07", "Campus University")
        ],
    ],
)
def test_a_percent_code_or_an_escape_before_an_identifier_is_a_boundary(
    prefix: str, identifier: str
) -> None:
    """``%22`` (a URL-encoded quote) and ``\\n``-style escapes (JSON inside a log line) end the
    word before them: what follows is mapped as if it stood alone."""
    s = _sanitizer({"host": {"name": "lab-pc-07"}})
    alone = s.map_text(identifier)
    assert alone != identifier
    assert s.map_text(prefix + identifier) == prefix + alone


def test_an_email_after_a_percent_code_is_mapped_whole() -> None:
    s = Sanitizer(POLICY, KEY)
    assert s.map_text("%22kate.x@campus.ac.in") == f"%22{_user('kate.x')}@univ.example"


# ------------------------------------------------------------------ credentials

_DIGEST = (
    'Digest username="kate7", realm="lab", nonce="n0nce1", uri="/a", response="r3sp0",'
    ' cnonce="c0n2", opaque="0paq3", qop=auth, nc=00000001'
)


def test_digest_secrets_are_redacted_and_the_user_name_mapped() -> None:
    assert Sanitizer(POLICY, KEY).map_text(_DIGEST) == (
        f'Digest username="{_user("kate7")}", realm="lab", nonce="REDACTED", uri="/a",'
        ' response="REDACTED", cnonce="REDACTED", opaque="REDACTED", qop=auth, nc=00000001'
    )


def test_the_user_name_of_a_digest_credential_is_a_name() -> None:
    s = _sanitizer({"message": f"Authorization: {_DIGEST}"})
    assert s.harvested == {_DIGEST, "kate7"}
    _replaced(s, "kate7", _user("kate7"))


# ------------------------------------------------------------------ literals

_LITERALS = POLICY.model_copy(
    update={"literals": {"Campus University": "Example University", "ACME": "UNIV", "CU": "EU"}}
)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Campus University", "Example University"),
        ("CAMPUS UNIVERSITY", "EXAMPLE UNIVERSITY"),
        ("campus university", "example university"),
        ("campus_University", "Example University"),
        ("acme Acme ACME", "univ UNIV UNIV"),  # four letters: any case
        ("cu Cu CU", "cu Cu EU"),  # shorter: its own case only
    ],
)
def test_literals_follow_the_case_of_the_text(text: str, expected: str) -> None:
    assert Sanitizer(_LITERALS, KEY).map_text(text) == expected


def test_a_literal_in_its_own_spelling_gets_its_own_replacement() -> None:
    policy = POLICY.model_copy(update={"literals": {"campusnet": "ExampleNet"}})
    assert Sanitizer(policy, KEY).map_text("via campusnet") == "via ExampleNet"


@pytest.mark.parametrize(
    "text",
    [
        "Campus Un\N{LATIN SMALL LETTER DOTLESS I}versity",
        "CAMPUS UN\N{LATIN CAPITAL LETTER I WITH DOT ABOVE}VERSITY",
    ],
)
def test_a_match_no_literal_spelling_accounts_for_is_left_as_it_is(text: str) -> None:
    """The case-insensitive pattern also matches the Turkish dotless and dotted I, which case
    folding keeps apart: no replacement is known, so the text stays (and nothing fails)."""
    assert Sanitizer(POLICY, KEY).map_text(text) == text


# ------------------------------------------------------------------ campus domains


def test_the_longest_campus_domain_wins() -> None:
    policy = POLICY.model_copy(update={"campus_domains": ("campus.ac", "campus.ac.in")})
    s = Sanitizer(policy, KEY)
    assert s.map_text("see www.campus.ac.in now") == f"see {s.domains.map('www.campus.ac.in')} now"
    assert s.domains.map("www.campus.ac.in") != s.domains.map("www.campus.ac") + ".in"


# ------------------------------------------------------------------ exactly what is harvested


@pytest.mark.parametrize(
    ("doc", "harvested"),
    [
        ({"user": {"name": "kate7"}}, {"kate7"}),
        ({"user": {"name": "svc-ops.backup"}}, {"svc-ops.backup"}),  # no host label from a user
        ({"user": {"name": "LAB-PC-07$"}}, {"LAB-PC-07$", "LAB-PC-07"}),
        ({"user": {"name": "Q$"}}, {"Q$", "Q"}),
        ({"user": {"name": "$"}}, {"$"}),
        ({"user": {"name": "CAMPUSNB\\"}}, {"CAMPUSNB\\", "CAMPUSNB"}),
        ({"host": {"name": "pc7.campus.ac.in"}}, {"pc7.campus.ac.in"}),
        ({"host": {"name": "mail.campus.ac.in"}}, {"mail.campus.ac.in"}),
        ({"host": {"name": "pc-7.campus.ac.in"}}, {"pc-7.campus.ac.in", "pc-7"}),
        ({"host": {"name": "::ffff:10.1.2.3"}}, {"::ffff:10.1.2.3", "10.1.2.3"}),
        ({"message": "GET http://10.1.2.3/x"}, {"http://10.1.2.3", "10.1.2.3"}),
        ({"message": "allow 10.1.2.0/24"}, {"10.1.2.0/24"}),  # not its network address
        ({"file": {"path": "/home/kp/notes.txt"}}, {"kp"}),
        (
            {"user": {"email": "<kate.x@campus.ac.in>"}},
            {"<kate.x@campus.ac.in>", "kate.x@campus.ac.in", "kate.x", "campus.ac.in"},
        ),
        (
            {"message": "to ravi.k%2Bnews@campus.ac.in"},
            {
                "ravi.k%2Bnews@campus.ac.in",
                "ravi.k+news@campus.ac.in",
                "ravi.k+news",
                "ravi.k",
                "campus.ac.in",
            },
        ),
        ({"message": "mail +news@campus.ac.in"}, {"+news@campus.ac.in", "+news", "campus.ac.in"}),
        ({"user": {"name": "  ", "email": ""}, "host": {"name": ""}}, set()),
    ],
    ids=[
        "account",
        "dotted-account",
        "machine-account",
        "one-letter-machine-account",
        "lone-dollar",
        "realm-without-account",
        "short-first-label",
        "plain-first-label",
        "four-character-first-label",
        "mapped-address",
        "address-in-url",
        "network",
        "two-letter-home",
        "e-mail-without-display-name",
        "percent-encoded-tag",
        "tag-without-account",
        "blank-values",
    ],
)
def test_exactly_these_identifiers_are_harvested(doc: Any, harvested: set[str]) -> None:
    s = _sanitizer(doc)
    assert s.harvested == harvested
    assert s.unchanged == set()


def test_a_kept_domain_in_a_host_field_is_unchanged_not_harvested() -> None:
    s = _sanitizer({"host": {"name": "WWW.Vendor-CDN.example."}})
    assert s.harvested == set()
    assert s.unchanged == {"WWW.Vendor-CDN.example.", "WWW.Vendor-CDN.example"}


# ------------------------------------------------------------------ parts of qualified values


def test_the_realm_and_account_of_a_windows_login_are_names() -> None:
    s = _sanitizer({"user": {"name": "CAMPUSNB\\kate7"}})
    realm = s.domains.label("CAMPUSNB")
    assert s.map_text("kate7 at CAMPUSNB") == f"{_user('kate7')} at {realm}"


def test_the_host_of_a_machine_account_is_a_host_name() -> None:
    s = _sanitizer({"user": {"name": "LAB-PC-07$"}})
    _replaced(s, "LAB-PC-07", s.domains.label("LAB-PC-07"))


@pytest.mark.parametrize(
    ("host", "first"),
    [
        ("lab-pc-09.campus.ac.in", "lab-pc-09"),
        ("pc-7.campus.ac.in", "pc-7"),
        ("lab-pc-07.X", "lab-pc-07"),
    ],
)
def test_the_first_label_of_a_host_fqdn_is_a_host_name(host: str, first: str) -> None:
    s = _sanitizer({"host": {"name": host}})
    _replaced(s, first, s.domains.label(first))


def test_a_plain_first_label_is_no_name() -> None:
    s = _sanitizer({"host": {"name": "mail.campus.ac.in"}})
    assert s.map_text("mail server") == "mail server"


# ------------------------------------------------------------------ e-mail


@pytest.mark.parametrize("kind", ["user", "email", "host"])
def test_an_email_known_as_a_name_gives_its_account(kind: str) -> None:
    s = Sanitizer(POLICY, KEY)
    s.add_names(["kate.x@campus.ac.in"], kind=kind)
    _replaced(s, "kate.x", _user("kate.x"))


def test_the_address_of_a_display_email_known_as_a_name_gives_its_account() -> None:
    s = Sanitizer(POLICY, KEY)
    s.add_names(['"Dana Xu" <kate.x@campus.ac.in>'], kind="email")
    assert s.map_text("Dana Xu is kate.x") == f"{_user('Dana Xu')} is {_user('kate.x')}"


def test_the_display_name_of_an_email_field_is_a_name() -> None:
    s = _sanitizer({"user": {"email": '"Dana Xu" <kate.x@campus.ac.in>'}})
    _replaced(s, "Dana Xu", _user("Dana Xu"))


def test_a_display_name_in_another_field_is_not_parsed() -> None:
    s = _sanitizer({"user": {"name": "Dana Xu <kate.x@campus.ac.in>"}})
    assert s.map_text("from Dana Xu") == "from Dana Xu"


def test_an_email_found_in_text_is_a_dictionary_entry_with_its_parts() -> None:
    s = _sanitizer({"message": "mail kate.x@campus.ac.in"})
    assert s.dictionary == {
        "kate.x@campus.ac.in": f"{_user('kate.x')}@univ.example",
        "kate.x": _user("kate.x"),
        "campus.ac.in": "univ.example",
    }


def test_the_tagged_account_of_a_percent_encoded_email_is_a_name() -> None:
    s = _sanitizer({"message": "to ravi.k%2Bnews@campus.ac.in"})
    _replaced(s, "ravi.k", _user("ravi.k"))


def test_the_domain_of_an_email_is_harvested() -> None:
    s = _sanitizer({"message": "from kate.x@mail.evil-c2.ru"})
    _replaced(s, "mail.evil-c2.ru", s.domains.map("mail.evil-c2.ru"))


def test_the_host_of_a_url_is_harvested() -> None:
    s = _sanitizer({"message": "GET http://XLAB-07.evil-c2.ru/a"})
    _replaced(s, "XLAB-07.evil-c2.ru", s.domains.map("XLAB-07.evil-c2.ru"))


# ------------------------------------------------------------------ names by kind, ids


@pytest.mark.parametrize(
    ("doc", "name", "kind"),
    [
        ({"user": {"email": "carol"}}, "carol", "user"),  # a bare login in an e-mail field
        ({"destination": {"domain": "files.evil-c2.ru"}}, "files.evil-c2.ru", "domain"),
        ({"organization": {"name": "Acme Widgets"}}, "Acme Widgets", "org"),
    ],
)
def test_a_field_value_is_replaced_in_free_text(doc: Any, name: str, kind: str) -> None:
    s = _sanitizer(doc)
    expected = {
        "user": _user(name),
        "domain": s.domains.map(name),
        "org": TOKENS.token("org", name.lower(), "org-"),
    }[kind]
    _replaced(s, name, expected)


def test_a_two_letter_name_is_replaced_in_its_own_case_only() -> None:
    s = _sanitizer({"user": {"name": "KP"}})
    assert s.map_text("KP and kp") == f"{_user('KP')} and kp"


def test_a_two_letter_home_directory_is_an_account_in_its_own_case() -> None:
    s = _sanitizer({"file": {"path": "/home/kp/notes.txt"}})
    assert s.map_text("owner kp, not KP") == f"owner {_user('kp')}, not KP"


@pytest.mark.parametrize("doc_id", ["Zq81xKw3", "Zq81xKw3Zq81xKw3"])
def test_an_id_of_eight_or_more_characters_is_replaced_in_free_text(doc_id: str) -> None:
    _replaced(_sanitizer({"_id": doc_id}), doc_id, TOKENS.opaque_id(doc_id))


@pytest.mark.parametrize("doc_id", ["x7", "Zq81xKw"])
def test_a_shorter_id_is_not_replaced_in_free_text(doc_id: str) -> None:
    s = _sanitizer({"_id": doc_id})
    assert doc_id in s.harvested
    _replaced(s, doc_id, doc_id)


# ------------------------------------------------------------------ mapping keys


@pytest.mark.parametrize(
    ("doc", "name"),
    [({"user": {"name": "kate7"}}, "kate7"), ({"user": {"email": "carol"}}, "carol")],
)
def test_a_key_that_is_a_harvested_account_is_renamed(doc: Any, name: str) -> None:
    s = _sanitizer(doc)
    assert s.sanitize({"on_call": {name: "yes"}}) == {"on_call": {_user(name): "yes"}}


@pytest.mark.parametrize("name", ["reviewer", "auditor"])
def test_a_key_that_is_a_segment_of_a_policy_field_path_is_kept(name: str) -> None:
    """``reviewer`` (of approval.reviewer) and ``auditor`` (of the pattern *.auditor.name) are
    field names, even when an account has that name."""
    s = _sanitizer({"user": {"name": name}})
    _replaced(s, name, _user(name))
    assert s.sanitize({"steps": {name: "pending"}}) == {"steps": {name: "pending"}}


def test_a_key_that_holds_an_object_in_the_corpus_is_kept() -> None:
    s = _sanitizer({"host": {"name": "agent"}, "agent": {"type": "filebeat"}})
    _replaced(s, "agent", s.domains.label("agent"))
    assert s.sanitize({"agent": "x"}) == {"agent": "x"}


def test_two_keys_that_map_to_one_pseudonym_are_refused() -> None:
    s = _sanitizer({"host": {"name": "LAB-PC-07"}})
    with pytest.raises(SanitizerError, match=r"^two mapping keys map to one pseudonym$"):
        s.sanitize({"labels": {"LAB-PC-07": 1, "lab-pc-07": 2}})


# ------------------------------------------------------------------ values named by their field


@pytest.mark.parametrize(
    "doc",
    [
        {"threshold": {"field": "user.name", "values": ["kate7"]}},
        {"threshold": {"field": "user.name.keyword", "value": "kate7"}},
        {"meta": {"key": "user.name", "params": {"query": "kate7"}}},
        {"filter": {"field": "user.name", "query": "kate7"}},
        {"aggs": {"x": {"terms": {"field": "user.name", "include": ["kate7"]}}}},
        {"query": {"term": {"user.name": "kate7"}}},
        {"query": {"query_string": {"query": "kate7 OR erin9", "fields": ["user.name"]}}},
        {"query": {"query_string": {"query": "kate7", "fields": ["user.name^2"]}}},
        {"query": {"multi_match": {"query": "kate7", "fields": ["user.name.keyword"]}}},
        {"kibana": {"alert": {"rule": {"parameters": {"query": "user.name: kate7"}}}}},
        {"rule": {"query": "user.name.keyword : (kate7 or erin9)"}},
    ],
    ids=[
        "values",
        "keyword-value",
        "filter-params",
        "query",
        "include",
        "term",
        "query_string",
        "boosted-field",
        "keyword-field",
        "kql",
        "kql-keyword-list",
    ],
)
def test_a_value_named_by_its_field_is_harvested_with_that_fields_kind(doc: Any) -> None:
    _replaced(_sanitizer(doc), "kate7", _user("kate7"))


@pytest.mark.parametrize(
    "doc",
    [
        {"query": ["failed login"], "fields": ["user.name"]},
        {"query": "failed login", "fields": {"user.name": {}}},
        {"query": "failed login", "fields": ["user.name", "host.name"]},
    ],
    ids=["query-not-text", "fields-not-a-list", "fields-of-two-kinds"],
)
def test_a_query_is_mapped_by_kind_only_for_text_over_fields_of_one_kind(doc: Any) -> None:
    s = _sanitizer(doc)
    assert s.harvested == set()
    assert s.sanitize(doc) == doc


def test_a_wildcard_value_harvests_its_name_like_fragments() -> None:
    s = _sanitizer({"query": {"wildcard": {"user.name": "svc-backup-07*"}}})
    _replaced(s, "svc-backup-07", _user("svc-backup-07"))


# ------------------------------------------------------------------ aggregations


def _terms_response(aggregation: str, key: Any, field: str = "user.name") -> dict[str, Any]:
    return {
        "request": {"aggs": {"who": {aggregation: {"field": field}}}},
        "response": {"aggregations": {"who": {"buckets": [{"key": key, "doc_count": 3}]}}},
    }


@pytest.mark.parametrize(
    ("aggregation", "field"),
    [
        ("terms", "user.name"),
        ("significant_terms", "user.name"),
        ("rare_terms", "user.name"),
        ("terms", "user.name.keyword"),
    ],
)
def test_bucket_keys_of_a_terms_aggregation_take_its_fields_kind(
    aggregation: str, field: str
) -> None:
    _replaced(_sanitizer(_terms_response(aggregation, "kate7", field)), "kate7", _user("kate7"))


@pytest.mark.parametrize("container", ["aggs", "aggregations"])
def test_bucket_keys_of_an_aggregation_named_after_a_field_take_its_kind(container: str) -> None:
    s = _sanitizer({container: {"user.name": {"buckets": [{"key": "kate7"}]}}})
    _replaced(s, "kate7", _user("kate7"))


@pytest.mark.parametrize(
    "request_body",
    [
        {"aggregations": {"who": {"terms": {"field": "user.name"}}}},
        {"searches": [{"aggs": {"who": {"terms": {"field": "user.name"}}}}]},
    ],
    ids=["aggregations", "in-a-list"],
)
def test_an_aggregation_request_is_found_wherever_it_sits(request_body: dict[str, Any]) -> None:
    response = {"aggregations": {"who": {"buckets": [{"key": "kate7"}]}}}
    s = _sanitizer({"request": request_body, "response": response})
    _replaced(s, "kate7", _user("kate7"))


def test_a_list_of_aggregation_configs_is_no_aggregation_request() -> None:
    """Kibana visualizations keep their aggregations as a list of configs under ``aggs``."""
    doc = {"visState": {"aggs": [{"id": "1", "type": "terms", "schema": "segment"}]}}
    assert _sanitizer(doc).sanitize(doc) == doc


def test_harvest_reads_the_aggregation_requests_of_each_document() -> None:
    s = _sanitizer({"hits": 1}, _terms_response("terms", "kate7"), {"hits": 2})
    assert "kate7" in s.harvested


def test_sanitize_reads_the_aggregation_requests_of_the_document_it_sanitizes() -> None:
    """A numeric user id is no free-text name: only its field's kind maps it."""
    doc = _terms_response("terms", "1001")
    s = _sanitizer(doc, {"hits": 1})
    assert s.map_text("1001") == "1001"
    bucket = s.sanitize(doc)["response"]["aggregations"]["who"]["buckets"][0]
    assert bucket == {"key": _user("1001"), "doc_count": 3}


def test_a_sub_aggregation_inside_a_bucket_takes_its_fields_kind() -> None:
    by_user = {"terms": {"field": "user.name"}}
    request = {"by_host": {"terms": {"field": "host.name"}, "aggs": {"by_user": by_user}}}
    bucket = {"key": "lab-pc-07", "by_user": {"buckets": [{"key": "kate7"}]}}
    doc = {
        "request": {"aggs": request},
        "response": {"aggregations": {"by_host": {"buckets": [bucket]}}},
    }
    _replaced(_sanitizer(doc), "kate7", _user("kate7"))


def _composite(field: str, response: dict[str, Any]) -> dict[str, Any]:
    sources = [{"u": {"terms": {"field": field}}}]
    return {
        "request": {"aggs": {"pages": {"composite": {"sources": sources}}}},
        "response": {"aggregations": {"pages": response}},
    }


@pytest.mark.parametrize(
    ("field", "response"),
    [
        ("user.name", {"after_key": {"u": "kate7"}, "buckets": []}),
        ("user.name.keyword", {"buckets": [{"key": {"u": "kate7"}}]}),
    ],
    ids=["after-key", "keyword-source"],
)
def test_composite_keys_take_their_sources_kinds(field: str, response: dict[str, Any]) -> None:
    _replaced(_sanitizer(_composite(field, response)), "kate7", _user("kate7"))


def _multi_terms(bucket: dict[str, Any], *fields: str) -> dict[str, Any]:
    terms = [{"field": f} for f in fields or ("host.name", "user.name")]
    return {
        "request": {"aggs": {"pair": {"multi_terms": {"terms": terms}}}},
        "response": {"aggregations": {"pair": {"buckets": [bucket]}}},
    }


def test_a_multi_terms_key_as_string_is_split_by_field() -> None:
    s = _sanitizer(_multi_terms({"key_as_string": "lab-pc-07|kate7"}))
    expected = f"{_user('kate7')} on {s.domains.label('lab-pc-07')}"
    assert s.map_text("kate7 on lab-pc-07") == expected


def test_a_multi_terms_key_maps_each_value_by_its_field() -> None:
    doc = _multi_terms({"key": ["lab-pc-07", "1001"], "key_as_string": "lab-pc-07|1001"})
    s = _sanitizer(doc)
    bucket = s.sanitize(doc)["response"]["aggregations"]["pair"]["buckets"][0]
    values = [s.domains.label("lab-pc-07"), _user("1001")]
    assert bucket == {"key": values, "key_as_string": "|".join(values)}


def test_a_multi_terms_key_over_a_keyword_sub_field_takes_the_fields_kind() -> None:
    doc = _multi_terms({"key": ["kate7"]}, "user.name.keyword")
    _replaced(_sanitizer(doc), "kate7", _user("kate7"))


@pytest.mark.parametrize("key_as_string", ["lab-pc-07", "lab-pc-07|kate7|extra-1"])
def test_a_multi_terms_key_with_another_count_of_values_is_mapped_as_far_as_it_goes(
    key_as_string: str,
) -> None:
    doc = _multi_terms({"key": key_as_string.split("|"), "key_as_string": key_as_string})
    s = _sanitizer(doc)
    assert s.harvested == {"lab-pc-07", *(["kate7"] if "kate7" in key_as_string else [])}
    bucket = s.sanitize(doc)["response"]["aggregations"]["pair"]["buckets"][0]
    values = [s.domains.label("lab-pc-07"), _user("kate7"), "extra-1"]
    expected = values[: key_as_string.count("|") + 1]
    assert bucket == {"key": expected, "key_as_string": "|".join(expected)}

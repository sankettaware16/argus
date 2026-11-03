"""The Kibana tier's strict cassettes (tests/kibana/cassette.py, Q-D1) without the tier.

Byte-exact cassettes need a normalization that is deterministic, consistent (one value, one
placeholder; distinct values, distinct placeholders), idempotent and secret-free, and a replay
that answers only the recorded requests in their recorded order.
"""

from __future__ import annotations

import json
import string
import uuid
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from tests.kibana.cassette import (
    SECRET,
    CassetteMismatchError,
    Exchange,
    Normalizer,
    Recorder,
    dump,
    load,
)

RUN = "kt261023010203abcd"
CASE_ID = "7e4c472c-285a-41af-bfa6-941358d2d8bc"
ALERT_ID = "2384572da8a1c17863f071fb0dd7a860fdb90b88e1227386861c5f20630b93d0"
KEY_ID = "LQtbZaEBCnLM16IJp13P"


def exchange(path: str, body: Any = None, answer: Any = None, status: int = 200) -> Exchange:
    return Exchange("kibana", "elastic", "POST", path, (), body, (), status, answer)


# --------------------------------------------------------------------------- normalizing


def test_values_that_differ_between_runs_become_placeholders() -> None:
    n = Normalizer(RUN)
    n.secret("hunter2-secret-value")
    got = n.normalize(
        {
            "id": CASE_ID,
            "alert": ALERT_ID,
            "key": KEY_ID,
            "version": "WzMxLDFd",
            "created_at": "2026-10-22T20:44:31.638Z",
            "tag": f"run:{RUN}",
            "note": "the password is hunter2-secret-value",
            "took": 17,
            "_seq_no": 23,
            "password": "anything",
            "encoded": "c29tZTprZXk=",
            "title": "d" * 30_000,
        }
    )
    assert got == {
        "id": "<uuid:1>",
        "alert": "<hex:1>",
        "key": "<id:1>",
        "version": "<version:1>",
        "created_at": "<time>",
        "tag": "run:<run>",
        "note": f"the password is {SECRET}",
        "took": "<took>",
        "_seq_no": "<seq>",
        "password": SECRET,
        "encoded": SECRET,
        "title": "<repeat:dx30000>",
    }


def test_one_value_one_placeholder_in_first_appearance_order() -> None:
    other = "0f8e3c9a-1111-4222-8333-944455556666"
    got = Normalizer(RUN).normalize(
        [f"/api/cases/{other}", {"id": CASE_ID}, {"again": other, "case": CASE_ID.upper()}]
    )
    assert got == [
        "/api/cases/<uuid:1>",
        {"id": "<uuid:2>"},
        {"again": "<uuid:1>", "case": "<uuid:2>"},
    ]


def test_ordinary_words_and_numbers_stay() -> None:
    n = Normalizer(RUN)
    words = [
        "argus-cases-writer-a",  # 20 characters, but no upper case or digit: not an id
        "securitySolutionCases",
        "acme-soc",
        "version 2",
        "0" * 64 + "1",  # 65 hex: not an alert id
    ]
    assert n.normalize(words) == words
    assert n.normalize({"version": 3, "took": "fast", "sort": [{"a": "asc"}]}) == {
        "version": 3,
        "took": "fast",
        "sort": [{"a": "asc"}],
    }  # a numeric version, a text "took" and a request's sort are not volatile


def test_a_hits_sort_values_and_case_timings_are_volatile() -> None:
    got = Normalizer(RUN).normalize(
        {"sort": [1792703222000], "time_to_acknowledge": 2, "time_to_resolve": None}
    )
    assert got == {"sort": "<sort>", "time_to_acknowledge": "<seconds>", "time_to_resolve": None}


def test_constants_are_kept_verbatim() -> None:
    constant = str(uuid.uuid5(uuid.NAMESPACE_DNS, "tier-viewer"))
    n = Normalizer(RUN, constants=frozenset({constant}))
    assert n.normalize([constant, CASE_ID]) == [constant, "<uuid:1>"]


uuids = st.uuids().map(str)
hexes = st.text("0123456789abcdef", min_size=64, max_size=64)
words = st.text(string.ascii_lowercase + " -", max_size=30)
values = st.one_of(uuids, hexes, words, st.integers(-5, 5), st.none())
documents = st.recursive(
    values,
    lambda inner: st.one_of(
        st.lists(inner, max_size=4),
        st.dictionaries(
            st.sampled_from(["id", "title", "version", "tags", "a"]), inner, max_size=4
        ),
    ),
    max_leaves=20,
)


@given(documents)
def test_normalizing_is_deterministic_and_idempotent(document: Any) -> None:
    once = Normalizer(RUN).normalize(document)
    assert Normalizer(RUN).normalize(document) == once
    assert Normalizer(RUN).normalize(once) == once  # placeholders are fixed points


@given(st.lists(uuids, min_size=1, max_size=12))
def test_placeholders_are_a_bijection(ids: list[str]) -> None:
    got = Normalizer(RUN).normalize(ids)
    for a, pa in zip(ids, got, strict=True):
        for b, pb in zip(ids, got, strict=True):
            assert (a == b) == (pa == pb)


SECRET_ALPHABET = string.ascii_uppercase + string.digits  # never part of a placeholder


@given(
    st.text(SECRET_ALPHABET, min_size=8, max_size=40),
    st.text(SECRET_ALPHABET + " ", max_size=20),
    st.text(SECRET_ALPHABET + " ", max_size=20),
)
def test_a_secret_never_survives(secret: str, before: str, after: str) -> None:
    n = Normalizer(RUN)
    n.secret(secret)
    text = json.dumps(n.normalize({"note": before + secret + after, "list": [secret]}))
    assert secret not in text


@given(st.lists(uuids, min_size=1, max_size=8, unique=True))
def test_replay_gives_back_the_values_a_test_sent(ids: list[str]) -> None:
    """Replay maps a placeholder back to the value the test sent; a new one becomes a stand-in
    of the right shape that is then known, so it round-trips."""
    n = Normalizer("other-run", namespace="t")
    sent = n.normalize(ids)
    assert n.denormalize(sent) == [i.lower() for i in ids]
    fresh = n.denormalize([f"<uuid:{len(ids) + 1}>", "<hex:1>", "<id:1>", "<version:1>"])
    assert uuid.UUID(fresh[0]).version == 4
    assert len(fresh[1]) == 64
    assert Normalizer("other-run").normalize({"k": fresh[2]})["k"] == "<id:1>"
    assert n.normalize([fresh[0], fresh[1]]) == [f"<uuid:{len(ids) + 1}>", "<hex:1>"]
    assert n.normalize({"version": fresh[3]}) == {"version": "<version:1>"}


# --------------------------------------------------------------------------- recorder


def recorded(tmp_path: Path, run: str = RUN, record: bool | str = "new") -> Recorder:
    recorder = Recorder("t__case", run, "live", record=record, directory=tmp_path)
    recorder.secret("s3cret-password")
    case_id = str(uuid.uuid4())
    recorder.add(
        exchange(
            "/api/cases", {"title": f"x {run}", "password": "s3cret-password"}, {"id": case_id}
        )
    )
    recorder.add(exchange(f"/api/cases/{case_id}/comments", {"comment": "hi"}, {"id": case_id}))
    return recorder


def test_a_live_run_writes_then_must_match_byte_for_byte(tmp_path: Path) -> None:
    first = recorded(tmp_path)
    first.finish()
    text = first.path.read_text(encoding="utf-8")
    assert "s3cret-password" not in text
    assert RUN not in text
    recorded(tmp_path, run="kt999999999999ffff").finish()  # another run: the same bytes
    assert first.path.read_text(encoding="utf-8") == text

    changed = Recorder("t__case", RUN, "live", directory=tmp_path)
    changed.add(exchange("/api/cases", {"title": "another"}, {"id": CASE_ID}))
    with pytest.raises(CassetteMismatchError, match="answered differently"):
        changed.finish()
    rerecorded = Recorder("t__case", RUN, "live", record=True, directory=tmp_path)
    rerecorded.add(exchange("/api/cases", {"title": "another"}, {"id": CASE_ID}))
    rerecorded.finish()
    assert len(load(rerecorded.path)) == 1


def test_a_live_run_without_its_cassette_fails_unless_it_records(tmp_path: Path) -> None:
    """Review F12: a live run that found no committed cassette wrote one and passed, so a
    deleted cassette (or a new test's first, unreviewed recording) went unnoticed but for `git
    status`. Now only KIBANA_TIER_RECORD=new (missing ones) or =1 (all) writes one."""
    with pytest.raises(CassetteMismatchError, match="KIBANA_TIER_RECORD=new"):
        recorded(tmp_path, record=False).finish()
    assert not (tmp_path / "t__case.json").exists()
    first = recorded(tmp_path, record="new")
    first.finish()
    assert first.path.is_file()
    changed = Recorder("t__case", RUN, "live", record="new", directory=tmp_path)
    changed.add(exchange("/api/cases", {"title": "another"}, {"id": CASE_ID}))
    with pytest.raises(CassetteMismatchError, match="answered differently"):
        changed.finish()  # "new" never rewrites a committed cassette


def test_replay_answers_only_the_recorded_requests_in_order(tmp_path: Path) -> None:
    recorded(tmp_path).finish()
    replay_run = "kt000000000000aaaa"
    replay = Recorder("t__case", replay_run, "replay", directory=tmp_path)
    status, answer = replay.answer(
        exchange("/api/cases", {"title": f"x {replay_run}", "password": "other"}, None)
    )
    assert status == 200
    case_id = answer["id"]
    uuid.UUID(case_id)  # a stand-in of the right shape
    status, again = replay.answer(exchange(f"/api/cases/{case_id}/comments", {"comment": "hi"}))
    assert again == {"id": case_id}  # the same placeholder, the same value
    replay.finish()

    out_of_order = Recorder("t__case", replay_run, "replay", directory=tmp_path)
    with pytest.raises(CassetteMismatchError, match="differs from the cassette"):
        out_of_order.answer(exchange("/api/cases/x/comments", {"comment": "hi"}))
    short = Recorder("t__case", replay_run, "replay", directory=tmp_path)
    short.answer(exchange("/api/cases", {"title": f"x {replay_run}", "password": "p"}))
    with pytest.raises(CassetteMismatchError, match="never made"):
        short.finish()
    extra = Recorder("t__case", replay_run, "replay", directory=tmp_path)
    _, made = extra.answer(exchange("/api/cases", {"title": f"x {replay_run}", "password": "p"}))
    extra.answer(exchange(f"/api/cases/{made['id']}/comments", {"comment": "hi"}))
    with pytest.raises(CassetteMismatchError, match="not in the cassette"):
        extra.answer(exchange("/api/cases", {"title": "one more"}))


def test_replay_without_a_cassette(tmp_path: Path) -> None:
    quiet = Recorder("t__none", RUN, "replay", directory=tmp_path)
    quiet.finish()  # asked nothing, holds nothing: fine
    asking = Recorder("t__none", RUN, "replay", directory=tmp_path)
    with pytest.raises(CassetteMismatchError, match="no cassette"):
        asking.answer(exchange("/api/cases"))


def test_a_live_test_that_recorded_nothing_keeps_no_cassette(tmp_path: Path) -> None:
    Recorder("t__timing", RUN, "live", directory=tmp_path).finish()
    assert not (tmp_path / "t__timing.json").exists()


def test_dump_is_stable() -> None:
    a = dump([{"b": 1, "a": [2, {"d": 3, "c": 4}]}])
    assert a == dump([{"a": [2, {"c": 4, "d": 3}], "b": 1}])
    assert a.endswith("\n")
    assert json.loads(a)["format"] == 1


# --------------------------------------------------------------------------- ids by context

ES_ID_ALPHABET = string.ascii_letters + string.digits + "-_"


def _key_recording(tmp_path: Path, run: str, key_id: str) -> Recorder:
    """A key minted, then refused with its id in Elasticsearch's message: a seeded key's id
    first seen in a message, then one minted in the test."""
    recorder = Recorder("t__ids", run, "live", record="new", directory=tmp_path)
    recorder.add(
        exchange(
            "/_license",
            answer={"error": {"reason": f"unauthorized for API key id [{key_id}] of user"}},
            status=403,
        )
    )
    recorder.add(exchange("/_security/api_key/grant", {"name": "x"}, {"id": key_id[::-1]}))
    recorder.add(
        exchange(
            "/_security/api_key",
            {"ids": [key_id[::-1]]},
            {"invalidated_api_keys": [key_id[::-1]], "error_count": 0},
        )
    )
    return recorder


def test_an_elasticsearch_id_without_a_digit_is_an_id_by_where_it_stands(tmp_path: Path) -> None:
    """The gate found it: about 3 % of Elasticsearch's ids hold no digit (pmEoaKEByjUIXAfc_bzr),
    and the normalizer took only 20 characters with an upper, a lower case letter and a digit
    for an id, so a run with such an id differed from the committed cassette. Ids are now also
    known by where they stand: under an id key, or in "API key id [...]"."""
    first = _key_recording(tmp_path, RUN, "pmEoaKEByjUIXAfc_bzr")
    first.finish()
    text = first.path.read_text(encoding="utf-8")
    assert "pmEoaKEByjUIXAfc_bzr" not in text
    assert "rzb_cfAXIUjyBEKaoEmp" not in text
    _key_recording(tmp_path, "kt999999999999ffff", "WWEoaKEByjUIXAfcYrzg").finish()  # same bytes


@given(st.text(ES_ID_ALPHABET, min_size=20, max_size=20))
def test_every_shape_of_elasticsearch_id_becomes_a_placeholder(key_id: str) -> None:
    normalizer = Normalizer(RUN)
    document = {
        "error": {"reason": f"unauthorized for API key id [{key_id}] of user [argus]"},
        "keys": [{"id": key_id, "name": "k"}],
        "detail": f"API key: api key [{key_id}] has been invalidated",
    }
    normalizer.learn(document)
    normalized = normalizer.normalize(document)
    assert key_id not in json.dumps(normalized)
    assert normalized["keys"][0]["id"] == "<id:1>"


def test_twenty_letters_elsewhere_stay_words() -> None:
    normalizer = Normalizer(RUN)
    document = {"name": "securitySolutionCase", "description": "createConfigurationX"}
    normalizer.learn(document)
    assert normalizer.normalize(document) == document

"""P2's privacy comparison (D-078): every arm renders the same view; only the values differ,
and secrets stay removed in all of them."""

from __future__ import annotations

import inspect
import json
import re

import pytest

from argus.llm import arms, egress
from argus.llm.arms import ARMS, REAL_DATA, Fakes, Real, arm, render
from argus.llm.privacy import Privacy, Request
from tests.unit.llm.test_privacy import RAW, dossier

pytestmark = pytest.mark.unit


def text(privacy: Privacy, name: str) -> str:
    body = dossier()
    body["facts"]["rule_name"] = "beacon from 10.20.3.4, key sk-proj-abcdefghijklmnopqrstuv"
    return render(privacy, name, [body]).text


def test_b_is_the_policy(privacy: Privacy) -> None:
    assert render(privacy, "B", [dossier()]).text == privacy.request([dossier()]).text


def test_every_arm_has_the_same_shape(privacy: Privacy) -> None:
    def body(name: str) -> list[str]:  # the item without its legend (a removed secret has none)
        lines = text(privacy, name).split("Pseudonyms in this item:")[0].splitlines()
        return [re.sub(r"[^:]*$", "", line) for line in lines]

    shapes = {name: body(name) for name in ARMS}
    lengths = {len(s) for s in shapes.values()}
    assert len(lengths) == 1, {n: len(s) for n, s in shapes.items()}


def test_a_fake_holds_no_real_value_and_no_pseudonym(privacy: Privacy) -> None:
    shown = text(privacy, "A-fake")
    for raw in RAW:
        assert raw.lower() not in shown.lower(), raw
    assert "I1." not in shown
    for fake in ("10.200.0.1", "host-1", "user1", "moodle.campus.example"):
        assert fake in shown, fake
    assert '- 10.200.0.1: a campus device in the asset map (type "lab", zone "north")' in shown
    assert "[credential removed]" in shown
    assert "sk-proj" not in shown


def test_a_real_holds_real_values_but_no_secret(privacy: Privacy) -> None:
    shown = text(privacy, "A-real")
    for real in ("10.20.3.4", "tp8", "moodle.example.edu", "alice", "203.0.113.9"):
        assert real in shown, real
    assert "I1." not in shown
    assert "sk-proj" not in shown
    assert "bob:pw" not in shown
    assert "[credential removed]" in shown
    assert {"A-real"} == REAL_DATA


@pytest.mark.parametrize(
    ("name", "fake", "token"),
    [
        ("C-ips", "10.200.0.1", "I1.HOST_1"),
        ("C-hosts", "host-1", "I1.IP_1"),
        ("C-users", "user1", "I1.IP_1"),
        ("C-sites", "moodle.campus.example", "I1.IP_1"),
    ],
)
def test_c_arms_loosen_one_kind(privacy: Privacy, name: str, fake: str, token: str) -> None:
    shown = text(privacy, name)
    assert fake in shown
    assert token in shown
    for raw in ("10.20.3.4", "tp8", "alice", "moodle.example.edu"):
        assert raw not in shown, raw


def test_c_ids_fakes_hashes_and_identifiers(privacy: Privacy) -> None:
    body = dossier()
    body["report"]["steps"][0]["text"] = (
        "mac 00:1a:2b:3c:4d:5e hash " + "d" * 32 + " id 123e4567-e89b-12d3-a456-426614174000"
    )
    shown = render(privacy, "C-ids", [body]).text
    assert "02:00:5e:00:00:01" in shown
    assert "00000000-0000-0000-0000-000000000001" in shown
    assert "d" * 32 not in shown
    assert "I1.IP_1" in shown


def test_c_counts_and_c_times(privacy: Privacy) -> None:
    counts = text(privacy, "C-counts")
    assert "Alerts: 1234 over 45 min" in counts
    times = render(privacy, "C-times", [dossier()]).text
    assert "Check I1.IP_1 at 2026-10-14T20:40+00:00" in times
    assert "first seen 2026-10-12T20:30+00:00" in times


def test_unknown_arms_are_refused(privacy: Privacy) -> None:
    with pytest.raises(ValueError, match="unknown arm 'Z'"):
        arm(privacy, "Z")


def test_fakes_are_consistent_and_of_the_same_kind() -> None:
    fakes = Fakes("I1", frozenset({"IP", "SITE", "HOST", "USER", "EMAIL", "MAC", "HASH", "ID"}),
                  ("example.edu",))  # fmt: skip
    assert fakes.token("IP", "10.1.2.3") == "10.200.0.1" == fakes.token("IP", "10.1.2.3")
    assert fakes.token("IP", "10.1.2.4") == "10.200.0.2"
    assert fakes.token("IP", "fd00::1") == "fd00:fa:ce::3"
    assert fakes.token("IP", "198.51.100.4", "a campus public address") == "203.0.113.5"
    assert fakes.token("IP", "not an address") == "10.200.0.5"
    assert fakes.token("SITE", "example.edu") == "campus.example"
    assert fakes.token("SITE", "a.b.EXAMPLE.edu.") == "part1.part2.campus.example"
    assert fakes.token("SITE", "moodle.cse.example.edu") == "moodle.part3.campus.example"
    assert fakes.token("SITE", "www.b.example.edu") == "www.part2.campus.example"
    assert fakes.token("SITE", "other.example") == "site5.campus.example"
    assert fakes.token("HOST", "tp8") == "host-1"
    assert fakes.token("USER", "alice") == "user1"
    assert fakes.token("EMAIL", "a@b.org") == "user1@campus.example"
    assert fakes.token("MAC", "00:1a:2b:3c:4d:5e") == "02:00:5e:00:00:01"
    assert len(fakes.token("HASH", "a" * 40)) == 40
    assert fakes.token("ID", "x") == "00000000-0000-0000-0000-000000000001"
    assert fakes.token("CRED", "secret") == "[credential removed]"
    assert fakes.token("IP", "10.1.2.3", "a legend") == "10.200.0.1"
    assert fakes.legend == {"203.0.113.5": "a campus public address", "10.200.0.1": "a legend"}


def test_fakes_leave_other_labels_as_pseudonyms() -> None:
    fakes = Fakes("I2", frozenset({"IP"}), ("example.edu",))
    assert fakes.token("HOST", "tp8", "a host") == "I2.HOST_1"
    assert fakes.value("I2.HOST_1") == "tp8"


def test_real_values_and_legends() -> None:
    real = Real("I1")
    assert real.token("IP", "10.1.2.3", "a device") == "10.1.2.3"
    assert real.token("CRED", "pw") == "[credential removed]"
    assert real.legend == {"10.1.2.3": "a device"}


def test_the_arm_list() -> None:
    assert ARMS == (
        "B", "A-fake", "A-real", "C-ips", "C-hosts", "C-users", "C-sites", "C-ids",
        "C-counts", "C-times",
    )  # fmt: skip
    assert arms.FAKE_DOMAIN == "campus.example"


def test_the_generic_labels() -> None:
    words = "www mail webmail smtp imap pop mx vpn moodle lms portal api app apps admin login sso"
    words += " auth cloud git gitlab wiki ftp dns ns ns1 ns2 cdn static blog news library lib exam"
    words += " exams erp student students staff hostel hr intranet dev test staging"
    assert frozenset(words.split(" ")) == arms.GENERIC_LABELS


@pytest.mark.parametrize(
    ("label", "n", "legend", "fake"),
    [
        ("IP", 1, "", "10.200.0.1"),
        ("IP", 257, "", "10.200.1.1"),
        ("IP", 65537, "", "10.201.0.1"),
        ("IP", 65536 * 50 + 1, "", "10.200.0.1"),  # 50 blocks, then around again
        ("IP", 253, "a campus public address", "203.0.113.254"),
        ("IP", 254, "a campus public address", "203.0.113.1"),
        ("MAC", 257, "", "02:00:5e:00:01:01"),
        ("MAC", 65537, "", "02:00:5e:00:00:01"),
    ],
)
def test_fake_numbers(label: str, n: int, legend: str, fake: str) -> None:
    fakes = Fakes("I1", frozenset({label}), ("example.edu",))
    assert fakes._fake(label, "10.1.2.3", n, legend) == fake


def test_c_users_fakes_emails_and_c_ids_hashes(privacy: Privacy) -> None:
    body = dossier()
    body["report"]["steps"][0]["text"] = "mail a.b@x.org hash " + "d" * 32
    users = render(privacy, "C-users", [body]).text
    assert "user1@campus.example" in users
    ids = render(privacy, "C-ids", [body]).text
    assert "I1.HASH" not in ids
    assert "d" * 32 not in ids


def test_a_real_values_are_not_found_again(privacy: Privacy) -> None:
    shown = render(privacy, "A-real", [dossier()]).text
    assert "[withheld" not in shown
    assert '"Check 10.20.3.4 at t0+10m' in shown


def test_real_legends_keep_the_first_and_skip_none() -> None:
    real = Real("I1")
    real.token("IP", "10.1.2.3")
    real.token("IP", "10.1.2.3", "first")
    real.token("IP", "10.1.2.3", "second")
    assert real.legend == {"10.1.2.3": "first"}


def test_unreadable_times_in_c_times(privacy: Privacy) -> None:
    body = dossier()
    body["context"]["pack"]["ti"]["answers"][0]["sources"]["abuse-ioc"]["match"][0][
        "first_seen"
    ] = "not a time"
    assert "first seen [a time]" in render(privacy, "C-times", [body]).text


def test_the_unknown_arm_message_and_default_size(privacy: Privacy) -> None:
    with pytest.raises(ValueError) as caught:  # noqa: PT011 - the exact message follows
        arm(privacy, "Z")
    assert str(caught.value) == f"unknown arm 'Z'; arms: {', '.join(ARMS)}"
    assert inspect.signature(render).parameters["max_chars"].default == 60_000


@pytest.mark.parametrize("name", ["C-ips", "C-hosts", "C-users", "C-sites", "C-ids"])
def test_c_arms_do_not_find_their_own_fakes_again(privacy: Privacy, name: str) -> None:
    assert "[withheld" not in render(privacy, name, [dossier()]).text


# -- fake arms are sent only as a proof against their policy twin (P5) ----------------------


def _fake_request(privacy: Privacy, name: str = "A-fake") -> arms.FakeRequest:
    request = render(privacy, name, [dossier()])
    assert isinstance(request, arms.FakeRequest)
    return request


@pytest.mark.parametrize("name", sorted(arms.FAKE_ARMS))
def test_a_fake_arm_passes_as_the_policy_text_with_fakes(privacy: Privacy, name: str) -> None:
    from argus.llm.gateway import Call, body_for
    from tests.unit.llm.test_gateway import config

    request = _fake_request(privacy, name)
    assert request.proven()
    assert request.validate().allowed
    assert not egress.check(request.text, privacy.campus).allowed or name in (
        "C-hosts",
        "C-sites",
        "C-ids",
    )
    for provider in config().providers:
        body = body_for(provider, Call(request, "Assess it. Answer in JSON.", "evaluate"))
        assert request.check(body).allowed


def test_other_arms_are_plain_requests(privacy: Privacy) -> None:
    for name in ("B", "A-real", "C-counts", "C-times"):
        assert type(render(privacy, name, [dossier()])) is Request
    assert not render(privacy, "A-real", [dossier()]).validate().allowed


def test_a_real_value_in_a_fake_arm_breaks_the_proof(privacy: Privacy) -> None:
    from dataclasses import replace

    request = _fake_request(privacy)
    for real in RAW[:3]:
        tampered = replace(request, text=request.text + f"\nnote {real}")
        assert not tampered.proven()
        verdict = tampered.validate()
        assert not verdict.allowed
        assert verdict.error == "not the policy text with fakes"
        assert not tampered.check(json.dumps({"x": tampered.text}).encode()).allowed


def test_a_value_the_twin_removed_but_the_arm_kept_breaks_the_proof(privacy: Privacy) -> None:
    from dataclasses import replace

    request = _fake_request(privacy)
    assert request.base is not None
    other = privacy.request([dossier(), dossier()])
    assert not replace(request, base=other).proven()
    assert not replace(request, base=None).validate().allowed
    assert replace(request, base=None).validate().error == "no policy twin"
    assert not replace(request, base=None).check(b"{}").allowed


def test_a_twin_that_fails_the_validator_fails_the_arm(privacy: Privacy) -> None:
    from dataclasses import replace

    request = _fake_request(privacy)
    assert request.base is not None
    leaky = replace(request.base, text=request.base.text + "\n10.20.3.4")
    verdict = replace(request, base=leaky).validate()
    assert not verdict.allowed
    assert "ip" in verdict.audit()["kinds"]


def test_the_rest_of_the_body_is_still_checked(privacy: Privacy) -> None:
    request = _fake_request(privacy)
    text = json.dumps(request.text, ensure_ascii=False)
    ok = ('{"messages": [{"content": "Answer in JSON."}, {"content": ' + text + "}]}").encode()
    assert request.check(ok).allowed
    leak = ok.replace(b"Answer in JSON.", b"Ask moodle.example.edu")
    assert not request.check(leak).allowed
    twice = ('{"a": ' + text + ', "b": ' + text + "}").encode()
    assert request.check(twice).error == "not the policy body with fakes"
    assert request.check(b'{"a": "nothing"}').error == "not the policy body with fakes"
    assert request.check(b"\xff\xfe").error == "not UTF-8"


async def test_the_gateway_sends_a_fake_arm_and_its_fakes(privacy: Privacy) -> None:
    from argus.llm.gateway import Call
    from tests.unit.llm.test_gateway import make

    request = _fake_request(privacy)
    gw, fake, store, _ = make()
    done = await gw.complete(Call(request, "Assess it. Answer in JSON.", "evaluate"))
    assert done.provider == "paid"
    sent = fake.sent[0][0].body.decode()
    assert "10.200." in sent
    assert "I1.IP_" not in sent
    for real in RAW:
        assert real not in sent
    assert [e.outcome for e in store.ledger] == ["ok"]


# -- the exact values and edges (mutation testing, P5) --------------------------------------


@pytest.mark.parametrize("name", sorted(arms.FAKE_ARMS))
def test_a_fake_arm_through_arm_is_the_rendered_one(privacy: Privacy, name: str) -> None:
    shown = arm(privacy, name).request([dossier()]).text
    assert shown == render(privacy, name, [dossier()]).text
    assert "[withheld" not in shown


def test_arm_configures_fakes_for_every_kind_or_one(privacy: Privacy) -> None:
    every = arm(privacy, "A-fake").request([dossier()]).text
    assert "I1." not in every
    for fake in ("10.200.0.1", "host-1", "user1", "moodle.campus.example"):
        assert fake in every, fake
    ips = arm(privacy, "C-ips").request([dossier()]).text
    assert "10.200.0.1" in ips
    assert "I1.HOST_1" in ips
    assert "moodle.campus.example" not in ips


def test_the_unknown_arm_message_of_render(privacy: Privacy) -> None:
    with pytest.raises(ValueError) as caught:  # noqa: PT011 - the exact message follows
        render(privacy, "Z", [dossier()])
    assert str(caught.value) == f"unknown arm 'Z'; arms: {', '.join(ARMS)}"


def test_escaping_matches_json() -> None:
    assert arms._escaped('a"b\né') == 'a\\"b\\né'


def test_a_fake_request_without_a_twin_proves_nothing(privacy: Privacy) -> None:
    from dataclasses import replace

    request = _fake_request(privacy)
    assert replace(request, base=None).proven() is False
    assert "base=" not in repr(request)


def test_a_credential_the_twin_removed_is_part_of_the_proof(privacy: Privacy) -> None:
    body = dossier()
    body["facts"]["rule_name"] = "login with key sk-proj-abcdefghijklmnopqrstuv"
    request = render(privacy, "C-ips", [body])
    assert isinstance(request, arms.FakeRequest)
    assert "[credential removed]" in request.text
    assert request.proven()


def test_a_body_that_is_not_utf8_is_refused(privacy: Privacy) -> None:
    verdict = _fake_request(privacy).check(b"\xff\xfe")
    assert verdict.allowed is False

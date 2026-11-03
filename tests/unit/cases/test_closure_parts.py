"""Pure parts of Q-C3: signatures and key files, decision statements, group samples, the shared
closure payload builder, ARGUS's proposals in the machine, identity checks and the autonomy
ledger's bars."""

from __future__ import annotations

import copy
import uuid
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.cases import approvals, autonomy, closure, identity, machine, signing
from argus.cases.approvals import RequestRecord
from argus.cases.autonomy import ClassLine, Week
from argus.cases.machine import CaseRefused, ProposeClosure
from argus.cases.model import Actor, Case, QuietWindow
from argus.normalize.canon import canonical_json

pytestmark = pytest.mark.unit

NOW = datetime(2026, 10, 23, 9, 0, tzinfo=UTC)
KEY = signing.Key(signing.key_id(b"\x01" * 32), b"\x01" * 32)


def _request(**changes: Any) -> RequestRecord:
    base = RequestRecord(
        id=7, case_id=uuid.UUID(int=9), case_version=2, kind="closure",
        reason="benign_expected", target_case_id=None, outbox_id=None, outbox_sent_count=None,
        payload={"writes": []}, payload_hash="a" * 64, alert_count=3, alert_digest="b" * 64,
        kibana_version="WzEsMV0=", required=1, requested_by_user_id=1, proposed_by=None,
        requested_at=NOW, expires_at=NOW + timedelta(hours=8),
    )  # fmt: skip
    return replace(base, **changes)


def _check(user_id: int = 2, **changes: Any) -> dict[str, Any]:
    check = identity.LiveCheck(user_id, "ok", "fake", NOW, "person",
                               frozenset({"view", "manage_cases", "approve"}),
                               frozenset({"updateCase"}), "uid-2", "two@example.org")  # fmt: skip
    return {**check.snapshot(), **changes}


def _statement(**changes: Any) -> dict[str, Any]:
    return approvals.statement(_request(**changes), approver_user_id=2, decision="approved",
                               stepped_up_at=NOW, check=_check(), batch=None)  # fmt: skip


# ------------------------------------------------------------------ signing


def test_a_signature_verifies_only_its_own_statement_and_key() -> None:
    signer, verifier = signing.Signer(KEY), signing.Verifier([KEY])
    statement = _statement()
    signature = signer.sign(statement)
    assert signing.SIGNATURE.fullmatch(signature)
    assert verifier.verify(statement, signature)
    assert verifier.verify(dict(reversed(list(statement.items()))), signature)  # key order
    assert not verifier.verify(_statement(case_version=3), signature)
    assert not verifier.verify(statement, None)
    assert not verifier.verify(statement, signature.replace("hmac-sha256", "hmac-sha512"))
    assert not verifier.verify(statement, signature[:-1] + ("0" if signature[-1] != "0" else "1"))
    other = signing.new_key()
    assert not signing.Verifier([other]).verify(statement, signature)
    assert signing.Verifier([other, KEY]).verify(statement, signature)  # a rotation


def _paths(value: Any, prefix: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
    if isinstance(value, dict):
        return [p for k, v in value.items() for p in _paths(v, (*prefix, k))] or [prefix]
    if isinstance(value, list) and value:
        return [p for i, v in enumerate(value) for p in _paths(v, (*prefix, i))]
    return [prefix]


_STATEMENT = _statement()
_PATHS = [p for p in _paths(_STATEMENT) if p]


@given(st.sampled_from(_PATHS), st.one_of(st.integers(), st.text(max_size=8), st.none(),
                                          st.booleans()))  # fmt: skip
def test_changing_any_bound_value_breaks_the_signature(path: tuple[Any, ...], value: Any) -> None:
    """Every field a statement holds is bound: the request's, the approver's, the step-up,
    every field of the live check, the group."""
    signature = signing.Signer(KEY).sign(_STATEMENT)
    changed = copy.deepcopy(_STATEMENT)
    target = changed
    for step in path[:-1]:
        target = target[step]
    if canonical_json(target[path[-1]]) == canonical_json(value):
        return
    target[path[-1]] = value
    assert not signing.Verifier([KEY]).verify(changed, signature)


@pytest.mark.parametrize(
    "field",
    ["id", "case_id", "case_version", "kind", "reason", "outbox_id", "payload_hash",
     "alert_count", "alert_digest", "kibana_version", "required", "requested_by_user_id",
     "proposed_by", "expires_at"],
)  # fmt: skip
def test_the_statement_binds_every_request_field(field: str) -> None:
    other = {
        "id": 8, "case_id": uuid.UUID(int=10), "case_version": 3, "kind": "merge",
        "reason": "duplicate", "outbox_id": 4, "payload_hash": "c" * 64, "alert_count": 4,
        "alert_digest": "d" * 64, "kibana_version": None, "required": 2,
        "requested_by_user_id": None, "proposed_by": "argus:proposer",
        "expires_at": NOW + timedelta(hours=9),
    }[field]  # fmt: skip
    assert _statement() != _statement(**{field: other})


def test_a_key_file_is_private_to_its_owner(tmp_path: Path) -> None:
    path = tmp_path / "approval.key"
    key = signing.new_key()
    signing.write_key(path, key)
    assert path.stat().st_mode & 0o777 == 0o600
    assert signing.load_key(path) == key
    with pytest.raises(FileExistsError):
        signing.write_key(path, signing.new_key())
    path.chmod(0o640)
    with pytest.raises(signing.KeyFileError, match="read by others"):
        signing.load_key(path)
    path.chmod(0o600)
    path.write_text("not a key\n")
    with pytest.raises(signing.KeyFileError, match="64 hex digits"):
        signing.load_key(path)
    with pytest.raises(signing.KeyFileError, match="cannot read"):
        signing.load_key(tmp_path / "missing.key")
    with pytest.raises(signing.KeyFileError, match="not a regular file"):
        signing.load_key(tmp_path)
    assert key.secret.hex() not in repr(key)
    assert signing.key_id(key.secret) == key.key_id


def test_statement_times_are_utc_microseconds() -> None:
    assert signing.iso(datetime(2026, 10, 23, 14, 0, 1, 5, tzinfo=UTC)) == (
        "2026-10-23T14:00:01.000005+00:00"
    )
    with pytest.raises(ValueError, match="timezone"):
        signing.iso(datetime(2026, 10, 23))  # noqa: DTZ001


# ------------------------------------------------------------------ groups


@pytest.mark.parametrize(("n", "size"), [(2, 2), (3, 3), (5, 3), (20, 3), (31, 4), (200, 20)])
def test_a_groups_sample_is_max_three_and_ten_percent(n: int, size: int) -> None:
    assert approvals.sample_size(n) == size


@given(st.sets(st.integers(1, 10_000), min_size=2, max_size=20), st.text(max_size=6))
def test_a_sample_is_a_fixed_part_of_its_group(ids: set[int], seed: str) -> None:
    batch = approvals.group(ids, seed)
    assert batch["requests"] == sorted(ids)
    assert set(batch["sample"]) <= ids
    assert len(batch["sample"]) == approvals.sample_size(len(ids))
    assert batch == approvals.group(sorted(ids, reverse=True), seed)


@pytest.mark.parametrize("ids", [[], [1], list(range(1, 22))])
def test_a_group_holds_two_to_twenty(ids: list[int]) -> None:
    with pytest.raises(approvals.ApprovalError, match="2 to 20"):
        approvals.group(ids, "s")


# ------------------------------------------------------------------ the payload builder


def _case(**changes: Any) -> Case:
    base = Case(uuid.UUID(int=5), 42, "t", "open", "high", 3, "person", mirrored=True,
                opened_at=NOW)  # fmt: skip
    return replace(base, **changes)


@given(st.datetimes(timezones=st.just(UTC)), st.datetimes(timezones=st.just(UTC)))
def test_the_closure_payload_does_not_depend_on_the_time(a: datetime, b: datetime) -> None:
    assert closure.build(_case(), "benign_expected", a) == closure.build(
        _case(), "benign_expected", b
    )


def test_the_closure_payload_is_the_w3_writes_for_a_mirrored_case_only() -> None:
    built = closure.build(_case(), "benign_policy", NOW)
    assert [(w["class"], w["op"]) for w in built.writes] == [("W3", "close"), ("W3", "comment")]
    assert "argus:reason:benign_policy" in built.writes[0]["payload"]["argus_tags"]
    assert closure.build(_case(mirrored=False), "benign_policy", NOW).writes == []
    target = uuid.UUID(int=77)
    merged = closure.build(_case(), "duplicate", NOW, target=target)
    assert merged.payload["target"] == str(target)
    assert merged.payload_hash != closure.build(_case(), "duplicate", NOW).payload_hash
    assert closure.write_at(built.payload, 1) == built.writes[1]
    assert closure.write_at(built.payload, 2) is None
    assert closure.write_at({"writes": "x"}, 0) is None
    assert closure.write_at({"writes": [1]}, 0) is None


# ------------------------------------------------------------------ ARGUS's proposals


def test_argus_proposes_only_with_positive_evidence_and_never_as_a_person() -> None:
    argus = Actor.argus("proposer")
    step = machine.decide(_case(), ProposeClosure("benign_expected", "all reviewed"), argus, NOW)
    assert (step.kind, step.after.version, step.writes) == ("closure_requested", 4, ())
    assert step.details == {"reason": "benign_expected", "note": "all reviewed", "proposed": True}
    with pytest.raises(CaseRefused, match="evidence is required"):
        machine.decide(_case(), ProposeClosure("benign_expected"), argus, NOW)
    with pytest.raises(CaseRefused, match="verified evidence"):
        machine.decide(_case(), ProposeClosure("remediated_verified"), argus, NOW)
    quiet = QuietWindow(True, "72 quiet hours, verified")
    proposal = ProposeClosure("remediated_verified", window=quiet)
    step = machine.decide(_case(state="contained"), proposal, argus, NOW)
    assert step.details["note"] == "72 quiet hours, verified"
    for reason in ("risk_accepted", "remediated_unverified", "created_in_error", "duplicate"):
        with pytest.raises(CaseRefused, match="does not propose"):
            machine.decide(_case(), ProposeClosure(reason, "x"), argus, NOW)  # type: ignore[arg-type]
    with pytest.raises(CaseRefused, match="ARGUS's own move"):
        machine.decide(_case(), ProposeClosure("benign_expected", "x"),
                       Actor.person(1, via="test"), NOW)  # fmt: skip
    with pytest.raises(CaseRefused, match="cannot propose closing a suspected case"):
        machine.decide(_case(state="suspected", opened_at=None),
                       ProposeClosure("benign_expected", "x"), argus, NOW)  # fmt: skip


# ------------------------------------------------------------------ identity


def test_two_accounts_with_one_argus_uid_or_email_are_one_person() -> None:
    a = _check(2)
    assert identity.same_person(a, _check(2))
    assert not identity.same_person(a, _check(3, argus_uid="uid-3", email="three@example.org"))
    assert identity.same_person(a, _check(3, argus_uid="uid-2", email="three@example.org"))
    assert identity.same_person(a, _check(3, argus_uid="uid-3", email="TWO@example.org"))
    assert not identity.same_person(a, _check(3, argus_uid=None, email=None))


async def test_a_fake_provider_answers_what_it_was_set_up_with() -> None:
    async def clock(_: Any) -> datetime:
        return NOW

    fake = identity.FakeIdentityProvider(clock=clock)
    assert (await fake.check(None, 5, purpose="approval")).outcome == "denied"  # type: ignore[arg-type]
    fake.allow(5, frozenset({"view"}))
    found = await fake.check(None, 5, purpose="approval")  # type: ignore[arg-type]
    assert (found.good, found.checked_at, found.kibana) == (True, NOW, frozenset({"updateCase"}))
    fake.deny(5)
    assert not (await fake.check(None, 5, purpose="recheck")).good  # type: ignore[arg-type]
    fake.deny(6, "unavailable")
    assert (await fake.check(None, 6, purpose="recheck")).outcome == "unavailable"  # type: ignore[arg-type]
    assert fake.calls == [(5, "approval"), (5, "approval"), (5, "recheck"), (6, "recheck")]


# ------------------------------------------------------------------ the autonomy ledger


def _weeks(decided: int = 40, wrong: int = 0) -> tuple[Week, ...]:
    return tuple(Week(NOW - timedelta(weeks=k), decided, wrong) for k in range(4, 0, -1))


def test_a_class_is_only_ever_ready_for_the_users_decision() -> None:
    ready = ClassLine("benign_expected", 160, 160, 0, 0, 0, 0, _weeks())
    assert ready.right.interval is not None
    assert ready.right.interval[0] >= autonomy.MIN_LOWER_BOUND
    assert ready.missing() == list(autonomy.STILL_TO_DO)


@pytest.mark.parametrize(
    ("line", "lacks"),
    [
        (ClassLine("r", 124, 124, 0, 0, 0, 0, _weeks()), "125 audited"),
        (ClassLine("r", 200, 199, 1, 0, 0, 0, _weeks()), "no wrong proposal"),
        (ClassLine("r", 200, 200, 0, 1, 0, 0, _weeks()), "no wrong proposal"),
        (ClassLine("r", 124, 124, 0, 0, 0, 0, _weeks()), "lower bound"),
        (ClassLine("r", 200, 200, 0, 0, 0, 0, _weeks(decided=0)), "stable weeks"),
        (ClassLine("r", 200, 200, 0, 0, 0, 0, _weeks(wrong=1)), "stable weeks"),
        (ClassLine("r", 200, 200, 0, 0, 0, 0, _weeks()[1:]), "stable weeks"),
        (ClassLine("r", 0, 0, 0, 0, 0, 0, ()), "97.0% (none)"),
    ],
)
def test_each_bar_a_class_lacks_is_named(line: ClassLine, lacks: str) -> None:
    assert any(lacks in m for m in line.missing())

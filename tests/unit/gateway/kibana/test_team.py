"""The case team's part of the Kibana lane (AR8, D-158, D-195): class WC, the five templates, the
author in the request and in its hash, the multipart file, the alert tags, the caps counted apart,
and every refusal: a wrong author, a missing key, a file or tags from anyone else's key."""

from __future__ import annotations

import ssl
from dataclasses import replace
from datetime import timedelta
from typing import Any

import httpx
import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import SecretStr, ValidationError

from argus.gateway.errors import TemplateRejectedError
from argus.gateway.kibana import models, upload
from argus.gateway.kibana.errors import AnswerMismatchError, WriteRefusedError
from argus.gateway.kibana.gateway import KibanaGateway, WriteContext, build_final
from argus.gateway.kibana.paths import KEndpoint, Target, endpoint_of, wire_path
from argus.gateway.kibana.templates import (
    KREGISTRY,
    KeyRole,
    TeamAlertTags,
    TeamAttachAlerts,
    TeamAttachFile,
    TeamAttachParams,
    TeamComment,
    TeamCommentParams,
    TeamCreateCase,
    TeamFileParams,
)
from argus.gateway.kibana.transport import HttpxKibanaTransport, KWire, wire_refusal
from argus.gateway.kibana.validator import KFinal, encode, request_hash, validate
from argus.gateway.kibana.writes import (
    KibanaLaneState,
    WriteCaps,
    WriteClass,
    WriteUnits,
    admit_write,
    from_json,
    to_json,
)
from tests.unit.gateway.fakes import FakeClock
from tests.unit.gateway.kibana.fakes import (
    ALERT_ID,
    ALERT_INDEX,
    CASE_ID,
    FakeKibana,
    make,
    ready_kibana,
    reply,
    start,
)

pytestmark = pytest.mark.unit
SPACE = "acme-soc"
PREFIX = f".internal.alerts-security.alerts-{SPACE}-"
INCIDENT = "ACME-IR-2026-1027-01"
TAGS = (INCIDENT, "incident", "verdict:true-positive", "ioc:77.221.155.150", "source:argus-lead")


def create_body(**more: Any) -> models.TeamCaseCreate:
    values: dict[str, Any] = {
        "title": f"{INCIDENT} · DNS beaconing from hostel devices",
        "description": "## Summary\n\nWhat happened.",
        "tags": TAGS,
        "severity": "high",
    }
    values.update(more)
    return models.TeamCaseCreate(**values)


def csv_file(name: str = "x_indicators", data: bytes = b"a,b\n1,2\n") -> upload.FileUpload:
    return upload.FileUpload(filename=name, mime="text/csv", data=data)


def final_of(template: Any, params: Any) -> KFinal:
    return build_final(template, params, SPACE, PREFIX)


# --------------------------------------------------------------------------- the templates


def test_the_team_templates_are_wc_writes_by_the_team_key() -> None:
    team = {n: t for n, t in KREGISTRY.items() if n.startswith("team.")}
    assert sorted(team) == [
        "team.alert_tags",
        "team.attach_alerts",
        "team.comment",
        "team.create",
        "team.edit_case",
        "team.edit_comment",
        "team.file",
    ]
    for template in team.values():
        spec = template.spec()
        assert spec.write
        assert spec.classes == frozenset({WriteClass.WC})
        assert spec.key is KeyRole.TEAM


def test_the_create_is_the_leads_with_the_hand_made_cases_shape() -> None:
    final = final_of(TeamCreateCase(), create_body())
    assert (final.method, final.path) == ("POST", f"/s/{SPACE}/api/cases")
    assert final.as_user == "argus-lead"
    body = __import__("json").loads(final.body or b"")
    assert body["tags"][0] == INCIDENT
    assert body["owner"] == "securitySolution"
    assert body["settings"] == {"syncAlerts": False}
    assert body["connector"] == {"id": "none", "name": "none", "type": ".none", "fields": None}
    assert not {"assignees", "customFields", "category"} & set(body)


def test_a_comment_is_sent_by_the_author_named_and_the_hash_names_the_author() -> None:
    a = final_of(
        TeamComment(), TeamCommentParams(case_id=CASE_ID, author="argus-hunter", comment="Q")
    )
    b = final_of(
        TeamComment(), TeamCommentParams(case_id=CASE_ID, author="argus-intel", comment="Q")
    )
    assert (a.as_user, b.as_user) == ("argus-hunter", "argus-intel")
    assert a.body == b.body  # the same words
    assert request_hash(a) != request_hash(b)  # but not the same request: whose key sends it


def test_a_comment_cannot_name_a_user_who_is_not_one_of_the_six() -> None:
    for who in ("argus", "elastic", "argus-lead ", "ARGUS-LEAD", ""):
        with pytest.raises(ValidationError):
            TeamCommentParams(case_id=CASE_ID, author=who, comment="x")  # type: ignore[arg-type]


def test_the_attach_is_the_leads_and_names_the_alerts_it_expects_the_case_to_hold() -> None:
    params = TeamAttachParams(case_id=CASE_ID, alerts=((ALERT_ID, ALERT_INDEX),), expect_total=7)
    final = final_of(TeamAttachAlerts(), params)
    assert final.as_user == "argus-lead"
    assert final.path.endswith(f"/cases/{CASE_ID}/comments")
    many = TeamAttachParams(
        case_id=CASE_ID,
        alerts=tuple((f"{i:064x}", ALERT_INDEX) for i in range(100)),
        expect_total=100,
    )  # the team's calls hold up to 100 (the lane's cap, 25 by default, is what a call may use)
    assert final_of(TeamAttachAlerts(), many).as_user == "argus-lead"
    with pytest.raises(ValidationError):
        TeamAttachParams(
            case_id=CASE_ID,
            alerts=tuple((f"{i:064x}", ALERT_INDEX) for i in range(101)),
            expect_total=101,
        )
    with pytest.raises(ValidationError):  # the writer's (W1) attach stays at five
        models.AlertAttachment(
            alertId=tuple(f"{i:064x}" for i in range(6)), index=(ALERT_INDEX,) * 6
        )


def test_alert_tags_are_the_incident_id_and_the_verdict_tag_only() -> None:
    ok = models.AlertTagChange(
        ids=(ALERT_ID,), tags=models.AlertTagSet(tags_to_add=(INCIDENT, "incident:true-positive"))
    )
    final = final_of(TeamAlertTags(), ok)
    assert final.as_user == "argus-lead"
    assert (final.method, final.path) == ("POST", f"/s/{SPACE}/api/detection_engine/signals/tags")
    body = __import__("json").loads(final.body or b"")
    assert body == {
        "ids": [ALERT_ID],
        "tags": {"tags_to_add": [INCIDENT, "incident:true-positive"], "tags_to_remove": []},
    }
    for bad in (("owned",), ("system_tag",), (INCIDENT, INCIDENT), ("incident:True",), ("x:y",)):
        with pytest.raises(ValidationError):
            models.AlertTagSet(tags_to_add=bad)
    with pytest.raises(ValidationError):
        models.AlertTagSet(tags_to_add=(INCIDENT,), tags_to_remove=("x",))  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        models.AlertTagChange(
            ids=(ALERT_ID, ALERT_ID), tags=models.AlertTagSet(tags_to_add=(INCIDENT,))
        )


def test_a_file_is_the_reporters_a_multipart_with_the_name_without_its_extension() -> None:
    final = final_of(TeamAttachFile(), TeamFileParams(case_id=CASE_ID, file=csv_file()))
    assert final.as_user == "argus-reporter"
    assert final.path.endswith(f"/cases/{CASE_ID}/files")
    assert final.content_type.startswith("multipart/form-data; boundary=argus-")
    body = final.body or b""
    assert b'name="file"; filename="x_indicators.csv"' in body
    assert b"Content-Type: text/csv" in body
    assert b'name="filename"\r\n\r\nx_indicators\r\n' in body
    assert upload.decode(body) == csv_file()


# --------------------------------------------------------------------------- the case's tags


@pytest.mark.parametrize(
    "tags",
    [
        ("incident", INCIDENT, "source:argus-lead"),  # the ID is first
        (INCIDENT, "source:argus-lead", "x"),  # no 'incident'
        (INCIDENT, "incident", "x"),  # no 'source:argus-lead'
        (INCIDENT, "incident", "source:argus-lead", "argus"),  # ARGUS's own tags are the writer's
        (
            INCIDENT,
            "incident",
            "source:argus-lead",
            "argus:case:00000000-0000-4000-8000-000000000001",
        ),
        (INCIDENT, "incident", "source:argus-lead", "bad tag"),
        (INCIDENT, "incident", "source:argus-lead", "x" * 101),
        (INCIDENT, "incident", "source:argus-lead", "incident"),  # twice
        (INCIDENT, "incident"),
    ],
)
def test_the_case_refuses_tags_that_are_not_an_incidents(tags: tuple[str, ...]) -> None:
    with pytest.raises(ValidationError):
        create_body(tags=tags)


# --------------------------------------------------------------------------- the validator


def test_only_the_lead_opens_a_case_or_touches_alerts_and_only_the_reporter_uploads() -> None:
    cases = [
        (TeamCreateCase(), create_body(), "argus-lead"),
        (
            TeamAttachAlerts(),
            TeamAttachParams(case_id=CASE_ID, alerts=((ALERT_ID, ALERT_INDEX),), expect_total=1),
            "argus-lead",
        ),
        (
            TeamAlertTags(),
            models.AlertTagChange(
                ids=(ALERT_ID,), tags=models.AlertTagSet(tags_to_add=(INCIDENT,))
            ),
            "argus-lead",
        ),
        (TeamAttachFile(), TeamFileParams(case_id=CASE_ID, file=csv_file()), "argus-reporter"),
    ]
    for template, params, owner in cases:
        good = final_of(template, params)
        assert good.as_user == owner
        for who in models.TEAM_USERS:
            if who == owner:
                continue
            wrong = KFinal(
                good.spec, good.method, good.path, good.target, good.url_params, good.body, who
            )
            with pytest.raises(TemplateRejectedError, match="not sent as"):
                validate(wrong, SPACE, PREFIX)
        for who in (None, "argus", "someone"):
            stray = KFinal(
                good.spec, good.method, good.path, good.target, good.url_params, good.body, who
            )
            with pytest.raises(TemplateRejectedError):
                validate(stray, SPACE, PREFIX)


def test_a_team_write_without_an_author_and_an_arguss_write_with_one_are_refused() -> None:
    good = final_of(
        TeamComment(), TeamCommentParams(case_id=CASE_ID, author="argus-evidence", comment="x")
    )
    with pytest.raises(TemplateRejectedError):
        validate(
            KFinal(
                good.spec, good.method, good.path, good.target, good.url_params, good.body, None
            ),
            SPACE,
            PREFIX,
        )
    from argus.gateway.kibana.templates import CommentOnCase, CommentParams

    plain = final_of(CommentOnCase(), CommentParams(case_id=CASE_ID, comment="x"))
    with pytest.raises(TemplateRejectedError, match="not a case team write"):
        validate(
            KFinal(
                plain.spec,
                plain.method,
                plain.path,
                plain.target,
                plain.url_params,
                plain.body,
                "argus-lead",
            ),
            SPACE,
            PREFIX,
        )


def test_the_attach_still_names_only_the_spaces_own_alert_indices() -> None:
    bad = models.AlertAttachment.model_construct(
        type="alert",
        alertId=(ALERT_ID,),
        index=(".internal.alerts-security.alerts-other-000001",),
        rule=models.RuleRef(),
        owner="securitySolution",
    )
    good = final_of(
        TeamAttachAlerts(),
        TeamAttachParams(case_id=CASE_ID, alerts=((ALERT_ID, ALERT_INDEX),), expect_total=1),
    )
    forged = KFinal(
        good.spec,
        good.method,
        good.path,
        good.target,
        good.url_params,
        encode(bad.model_dump(mode="json")),
        good.as_user,
    )
    with pytest.raises(TemplateRejectedError, match="alert indices"):
        validate(forged, SPACE, PREFIX)


def test_a_file_body_that_is_not_what_the_lane_builds_is_refused() -> None:
    good = final_of(TeamAttachFile(), TeamFileParams(case_id=CASE_ID, file=csv_file()))
    body = good.body or b""
    for forged in (
        body.replace(b"text/csv", b"text/html"),
        body.replace(b'filename="x_indicators.csv"', b'filename="../x.csv"'),
        body + b"\r\nextra",
        body[: len(body) // 2],
        b"{}",
    ):
        with pytest.raises(TemplateRejectedError):
            validate(
                KFinal(
                    good.spec,
                    good.method,
                    good.path,
                    good.target,
                    good.url_params,
                    forged,
                    good.as_user,
                ),
                SPACE,
                PREFIX,
            )


# --------------------------------------------------------------------------- the upload codec


@given(
    name=st.from_regex(upload.NAME, fullmatch=True),
    data=st.binary(min_size=1, max_size=2000),
    mime=st.sampled_from(["application/pdf", "text/csv"]),
)
def test_any_file_survives_the_codec_and_the_same_file_is_the_same_bytes(
    name: str, data: bytes, mime: str
) -> None:
    made = upload.FileUpload(filename=name, mime=mime, data=data)  # type: ignore[arg-type]
    body = upload.encode(made)
    assert upload.decode(body) == made
    assert upload.encode(upload.FileUpload(filename=name, mime=mime, data=data)) == body  # type: ignore[arg-type]
    assert upload.content_type(body).endswith(upload.boundary_of(made))


@given(
    data=st.binary(min_size=1, max_size=300),
    cut=st.integers(0, 600),
    flip=st.integers(0, 600),
)
def test_a_changed_body_is_never_read_as_a_file(data: bytes, cut: int, flip: int) -> None:
    body = upload.encode(upload.FileUpload(filename="a_b", mime="text/csv", data=data))
    changed = bytearray(body)
    if flip < len(changed):
        changed[flip] ^= 0x01
    for candidate in (bytes(changed), body[: min(cut, len(body) - 1)]):
        if candidate == body:
            continue
        try:
            upload.decode(candidate)
        except ValueError:
            continue
        # a change inside the file's bytes is the file's change, and the boundary no longer fits
        raise AssertionError("a changed body was read as a file")


@pytest.mark.parametrize("name", ["", ".x", "-x", "a b", "a/b", "a\r\nb", "é", "x" * 200])
def test_a_file_name_is_plain(name: str) -> None:
    with pytest.raises(ValidationError):
        upload.FileUpload(filename=name, mime="text/csv", data=b"x")


def test_only_a_pdf_or_a_csv_under_five_megabytes() -> None:
    with pytest.raises(ValidationError):
        upload.FileUpload(filename="x", mime="text/html", data=b"x")  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        upload.FileUpload(filename="x", mime="text/csv", data=b"")
    with pytest.raises(ValidationError):
        upload.FileUpload(filename="x", mime="text/csv", data=b"x" * (upload.MAX_FILE_BYTES + 1))


# --------------------------------------------------------------------------- the transport


def transport(team: dict[str, str]) -> HttpxKibanaTransport:
    return HttpxKibanaTransport(
        "https://kibana.test:5601",
        "https://es.test:9200",
        ssl.create_default_context(),
        {KeyRole.READER: SecretStr("reader")},
        space=SPACE,
        team_keys={k: SecretStr(v) for k, v in team.items()},
    )


def wire(user: str | None, path: str | None = None, **more: Any) -> KWire:
    fields: dict[str, Any] = {
        "target": "kibana",
        "key": KeyRole.TEAM,
        "method": "POST",
        "params": (),
        "body": b"{}",
        "opaque_id": "x",
        "timeout_s": 5.0,
        "as_user": user,
        "path": path or f"/s/{SPACE}/api/cases/{CASE_ID}/comments",
    }
    fields.update(more)
    return KWire(**fields)


def test_a_user_whose_key_is_not_installed_is_refused_before_anything_leaves() -> None:
    t = transport({"argus-lead": "L", "argus-hunter": "H"})
    assert t.refusal(wire("argus-lead")) is None
    refused = t.refusal(wire("argus-reporter"))
    assert refused is not None
    assert refused.code == "no_key"
    assert t.refusal(wire(None)) is not None
    assert t.refusal(wire("argus")) is not None  # ARGUS's own user has no team key


@pytest.mark.asyncio
async def test_each_request_carries_its_authors_key_and_only_that() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={})

    t = transport({"argus-lead": "L-key", "argus-hunter": "H-key"})
    t.clients["kibana"] = httpx.AsyncClient(
        base_url="https://kibana.test:5601", transport=httpx.MockTransport(handler)
    )
    await t.send(wire("argus-hunter"))
    await t.send(wire("argus-lead"))
    assert [r.headers["authorization"] for r in seen] == ["ApiKey H-key", "ApiKey L-key"]
    assert all("reader" not in r.headers["authorization"] for r in seen)


def test_the_team_keys_send_only_the_incident_cases_own_writes() -> None:
    api = f"/s/{SPACE}/api"
    allowed = [
        ("POST", f"{api}/cases"),
        ("POST", f"{api}/cases/{CASE_ID}/comments"),
        ("POST", f"{api}/cases/{CASE_ID}/files"),
        ("POST", f"{api}/detection_engine/signals/tags"),
        ("PATCH", f"{api}/cases"),  # the lead corrects the title and description (D-236)
        ("PATCH", f"{api}/cases/{CASE_ID}/comments"),  # a user corrects their own comment
    ]
    for method, path in allowed:
        assert wire_refusal(wire("argus-lead", path, method=method), SPACE) is None
    refused = [
        ("PATCH", f"{api}/cases/{CASE_ID}"),  # no such route
        ("PATCH", f"{api}/cases/{CASE_ID}/files"),
        ("PUT", f"{api}/cases/{CASE_ID}/comments"),
        ("GET", f"{api}/cases/_find"),
        ("GET", f"{api}/cases/{CASE_ID}"),
        ("POST", f"{api}/detection_engine/signals/status"),
        ("POST", f"{api}/cases/{CASE_ID}/comments/x"),
        ("DELETE", f"{api}/cases/{CASE_ID}"),
    ]
    for method, path in refused:
        assert wire_refusal(wire("argus-lead", path, method=method), SPACE) is not None, path


def test_a_file_or_alert_tags_from_any_other_key_never_leave() -> None:
    api = f"/s/{SPACE}/api"
    for key in (KeyRole.CASES, KeyRole.READER, KeyRole.ALERTS):
        for path in (f"{api}/cases/{CASE_ID}/files", f"{api}/detection_engine/signals/tags"):
            assert wire_refusal(wire(None, path, key=key), SPACE) is not None
        edit = wire(None, f"{api}/cases/{CASE_ID}/comments", key=key, method="PATCH")
        assert wire_refusal(edit, SPACE) is not None  # a comment is edited by the team alone


def test_every_team_route_is_a_route_the_path_builder_makes() -> None:
    assert endpoint_of(
        "POST", wire_path(KEndpoint.CASE_FILES, SPACE, Target(case_id=CASE_ID))[1], SPACE
    ) is (KEndpoint.CASE_FILES)
    assert endpoint_of("GET", f"/s/{SPACE}/api/cases/x/files", SPACE) is None
    assert endpoint_of("POST", "/internal/x", SPACE) is None


# --------------------------------------------------------------------------- the caps


NOW = __import__("datetime").datetime(2026, 10, 23, 10, 0, tzinfo=__import__("datetime").UTC)


def admit(state: KibanaLaneState, cls: WriteClass, now: Any, run: str = "r", **kw: Any) -> Any:
    return admit_write(
        state,
        cls,
        kw.get("units", WriteUnits(case_write=True)),
        now,
        run,
        kw.get("caps", WriteCaps()),
    )


def test_the_case_teams_writes_are_counted_apart_from_the_writers() -> None:
    state, now = KibanaLaneState(), NOW
    for n in range(12):  # more than the writer's 10 a run
        refused, state = admit(state, WriteClass.WC, now)
        assert refused is None, n
        now += timedelta(seconds=4)
    c = state.counters
    assert (c.team_writes, c.case_writes) == (12, 0)
    refused, _ = admit(state, WriteClass.W1, now, run="writer")
    assert refused is None  # the writer's allowance is untouched


def test_a_run_of_the_case_team_stops_at_its_own_cap_and_a_day_at_its_own() -> None:
    caps = WriteCaps(team_per_run=3, team_per_day=5)
    state, now = KibanaLaneState(), NOW
    for _ in range(3):
        refused, state = admit(state, WriteClass.WC, now, caps=caps)
        assert refused is None
        now += timedelta(seconds=4)
    refused, _ = admit(state, WriteClass.WC, now, caps=caps)
    assert refused == "run_cap"
    for run in ("r2", "r3"):  # new runs: two more reach the day's five
        refused, state = admit(state, WriteClass.WC, now, run=run, caps=caps)
        now += timedelta(seconds=4)
        assert refused is None
    refused, _ = admit(state, WriteClass.WC, now, run="r4", caps=caps)
    assert refused == "case_daily_cap"


def test_alert_calls_of_the_team_are_100_and_3_seconds_apart_and_the_others_keep_five_and_60() -> (
    None
):
    """D-235, D-242: the lane's bucket (a 60 s burst at NORMAL) paces the server time,
    so the team's gap between alert calls is a courtesy of 3 s and a call may name 100 alerts."""
    state, now = KibanaLaneState(), NOW
    refused, state = admit(state, WriteClass.WC, now, units=WriteUnits(case_write=True, alerts=100))
    assert refused is None
    refused, _ = admit(
        state,
        WriteClass.WC,
        now + timedelta(seconds=2),
        units=WriteUnits(case_write=False, alerts=100),
    )
    assert refused == "alert_gap"
    refused, again = admit(
        state,
        WriteClass.WC,
        now + timedelta(seconds=3),
        units=WriteUnits(case_write=False, alerts=100),
    )
    assert refused is None
    refused, _ = admit(
        again,
        WriteClass.WC,
        now + timedelta(seconds=100),
        units=WriteUnits(case_write=False, alerts=101),
    )
    assert refused == "alerts_per_call"
    # the writer's classes keep the lane's five a call and a minute apart
    refused, _ = admit(state, WriteClass.W1, now + timedelta(seconds=50),
                       units=WriteUnits(case_write=True, alerts=5), run="w")  # fmt: skip
    assert refused == "alert_gap"
    refused, _ = admit(state, WriteClass.W1, now + timedelta(seconds=61),
                       units=WriteUnits(case_write=True, alerts=6), run="w")  # fmt: skip
    assert refused == "alerts_per_call"


def test_a_500_alert_case_fits_the_teams_daily_alert_cap_but_a_third_one_does_not() -> None:
    caps = WriteCaps()
    state, now = KibanaLaneState(), NOW
    for _ in range(40):  # two cases of 500: attached and tagged, 25 a call
        refused, state = admit(
            state, WriteClass.WC, now, units=WriteUnits(case_write=False, alerts=25), caps=caps
        )
        assert refused is None
        now += caps.team_alert_gap
    assert state.counters.alert_mutations == 1_000
    assert caps.team_alerts_per_day == 2_000
    state = KibanaLaneState(counters=replace(state.counters, alert_mutations=1_990))
    refused, _ = admit(
        state, WriteClass.WC, now, units=WriteUnits(case_write=False, alerts=25), caps=caps
    )
    assert refused == "alert_daily_cap"


def test_the_lane_state_round_trips_with_the_team_count() -> None:
    state = KibanaLaneState()
    _, state = admit(state, WriteClass.WC, NOW)
    again = from_json(to_json(state))
    assert again.counters.team_writes == 1
    old = to_json(state)
    del old["counters"]["team_writes"]  # type: ignore[attr-defined]
    assert from_json(old).counters.team_writes == 0  # a row written before AR8


# --------------------------------------------------------------------------- through the lane


async def test_a_team_write_needs_its_class_switched_on_by_name() -> None:
    gateway, kibana, _, clock, _ = make(classes=frozenset({WriteClass.W1}))
    run = await start(gateway, clock)
    params = create_body()
    context = WriteContext(WriteClass.WC, "team:1", gateway.payload_hash(TeamCreateCase(), params))
    with pytest.raises(WriteRefusedError) as refused:
        await gateway.write(
            TeamCreateCase(),
            params,
            run=run,
            context=context,
            component="t",
            deadline=clock.now + timedelta(seconds=60),
        )
    assert refused.value.reason == "class_off"
    assert not [c for c in kibana.calls if c.method == "POST"]


async def test_a_team_template_cannot_be_sent_as_a_writer_class() -> None:
    gateway, _, _, clock, _ = make(classes=frozenset({WriteClass.W1, WriteClass.WC}))
    run = await start(gateway, clock)
    params = create_body()
    context = WriteContext(WriteClass.W1, "team:1", gateway.payload_hash(TeamCreateCase(), params))
    with pytest.raises(WriteRefusedError) as refused:
        await gateway.write(
            TeamCreateCase(),
            params,
            run=run,
            context=context,
            component="t",
            deadline=clock.now + timedelta(seconds=60),
        )
    assert refused.value.reason == "wrong_class"


def kibana_with_team_case(by: str = "argus-lead") -> FakeKibana:
    k = ready_kibana()
    case = {
        "id": CASE_ID,
        "version": "WzEsMV0=",
        "owner": "securitySolution",
        "status": "open",
        "tags": list(TAGS),
        "settings": {"syncAlerts": False},
        "severity": "high",
        "title": create_body().title,
        "description": create_body().description,
        "created_by": {"username": by},
        "totalAlerts": 0,
        "totalComment": 0,
        "comments": [],
    }
    k.routes = [r for r in k.routes if not (r[0] == "POST" and r[1] == "/api/cases")]
    k.on("POST", "/api/cases", reply(case))
    return k


async def test_the_answer_must_show_the_lead_as_the_author_of_the_case() -> None:
    gateway, _, _, clock, _ = make(
        kibana_with_team_case("argus"), classes=frozenset({WriteClass.WC})
    )
    run = await start(gateway, clock)
    params = create_body()
    context = WriteContext(WriteClass.WC, "team:1", gateway.payload_hash(TeamCreateCase(), params))
    with pytest.raises(AnswerMismatchError, match="lead"):
        await gateway.write(
            TeamCreateCase(),
            params,
            run=run,
            context=context,
            component="t",
            deadline=clock.now + timedelta(seconds=60),
        )


async def test_a_team_create_through_the_lane_is_checked_and_recorded() -> None:
    gateway, kibana, store, clock, _ = make(
        kibana_with_team_case(), classes=frozenset({WriteClass.WC})
    )
    run = await start(gateway, clock)
    params = create_body()
    context = WriteContext(WriteClass.WC, "team:1", gateway.payload_hash(TeamCreateCase(), params))
    result = await gateway.write(
        TeamCreateCase(),
        params,
        run=run,
        context=context,
        component="t",
        deadline=clock.now + timedelta(seconds=60),
    )
    assert result.body["id"] == CASE_ID
    [sent] = [c for c in kibana.calls if c.method == "POST"]
    assert sent.key is KeyRole.TEAM
    assert sent.as_user == "argus-lead"
    ledger = [e for e in store.ledger if e.write_class == "WC"]
    assert len(ledger) == 1
    assert ledger[0].outbox_id == "team:1"


async def test_the_payload_hash_in_the_context_must_be_the_requests() -> None:
    gateway, _, _, clock, _ = make(kibana_with_team_case(), classes=frozenset({WriteClass.WC}))
    run = await start(gateway, clock)
    params = create_body()
    other = create_body(description="changed")
    context = WriteContext(WriteClass.WC, "team:1", gateway.payload_hash(TeamCreateCase(), other))
    with pytest.raises(WriteRefusedError) as refused:
        await gateway.write(
            TeamCreateCase(),
            params,
            run=run,
            context=context,
            component="t",
            deadline=clock.now + timedelta(seconds=60),
        )
    assert refused.value.reason == "payload_changed"


def test_the_clock_fake_is_the_gateways() -> None:
    assert isinstance(FakeClock, type)
    assert KibanaGateway.__name__ == "KibanaGateway"


# --------------------------------------------------------------------------- the tag answer


def tag_change(n: int) -> models.AlertTagChange:
    return models.AlertTagChange(
        ids=tuple(f"{i:064x}" for i in range(n)),
        tags=models.AlertTagSet(tags_to_add=(INCIDENT, "incident:true-positive")),
    )


def report(**more: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "took": 3, "timed_out": False, "total": 25, "updated": 25, "deleted": 0, "batches": 1,
        "version_conflicts": 0, "noops": 0, "failures": [],
    }  # fmt: skip
    base.update(more)
    return base


def test_a_complete_tag_answer_is_complete() -> None:
    tagged = models.tag_report(report(), tag_change(25))
    assert (tagged.updated, tagged.gone, tagged.conflicts, tagged.complete) == (25, 0, 0, True)
    assert models.check_alert_tags(report(), tag_change(25))["updated"] == 25


def test_alerts_the_index_no_longer_holds_are_a_report_not_a_wrong_answer() -> None:
    """Index lifecycle removes old alerts: update-by-ids matches only those that exist, so
    ``updated`` and ``total`` are under the number named. That must not pause class WC."""
    answer = report(total=22, updated=22)
    tagged = models.tag_report(answer, tag_change(25))
    assert (tagged.updated, tagged.gone, tagged.conflicts, tagged.complete) == (22, 3, 0, False)
    assert models.check_alert_tags(answer, tag_change(25)) is answer
    everything_gone = report(total=0, updated=0)
    assert models.tag_report(everything_gone, tag_change(25)).gone == 25


def test_version_conflicts_are_a_report_too() -> None:
    answer = report(total=25, updated=20, version_conflicts=5)
    tagged = models.tag_report(answer, tag_change(25))
    assert (tagged.updated, tagged.gone, tagged.conflicts) == (20, 0, 5)
    assert not tagged.complete
    models.check_alert_tags(answer, tag_change(25))
    both = models.tag_report(report(total=23, updated=20, version_conflicts=3), tag_change(25))
    assert (both.updated, both.gone, both.conflicts) == (20, 2, 3)


def test_alerts_that_already_carry_the_tags_count_as_done() -> None:
    answer = report(total=25, updated=10, noops=15)
    tagged = models.tag_report(answer, tag_change(25))
    assert (tagged.updated, tagged.complete) == (25, True)


@pytest.mark.parametrize(
    "answer",
    [
        None,
        [],
        report(updated="25"),
        report(updated=True),
        report(updated=-1),
        {k: v for k, v in report().items() if k != "updated"},
        report(failures=[{"cause": "x"}]),
        report(failures="none"),
        report(timed_out=True),
        report(total=26, updated=26),  # more than were named
        report(total=25, updated=25, deleted=1),
        report(total=25, updated=20),  # five matched and neither updated nor in conflict
        report(total=25, updated=25, version_conflicts=1),  # does not add up
        report(version_conflicts="1"),
    ],
)
def test_an_answer_that_is_not_a_clean_report_is_still_a_wrong_answer(answer: Any) -> None:
    with pytest.raises(AnswerMismatchError):
        models.check_alert_tags(answer, tag_change(25))


@given(
    named=st.integers(1, 100),
    gone=st.integers(0, 100),
    conflicts=st.integers(0, 100),
)
def test_the_tag_report_adds_up_for_any_split_of_the_named_alerts(
    named: int, gone: int, conflicts: int
) -> None:
    gone = min(gone, named)
    conflicts = min(conflicts, named - gone)
    matched = named - gone
    answer = report(total=matched, updated=matched - conflicts, version_conflicts=conflicts)
    tagged = models.tag_report(answer, tag_change(named))
    assert (tagged.gone, tagged.conflicts) == (gone, conflicts)
    assert tagged.updated == matched - conflicts
    assert tagged.complete is (gone == 0 and conflicts == 0)

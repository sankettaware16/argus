"""P4-B1 (D-270): the read-back reads the case team's cases too. The reporters of every find are
the service user and the case team's users (from settings); an action by any of them is ARGUS's
(explained by a sent step of its own author, else an alarm) and any other username is a person's;
a team case is adopted through its post and its sent open step; a person's edit, close, reopen or
delete reaches the mirror within one cycle; nothing is ever written to Kibana."""

from __future__ import annotations

import uuid
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from argus.caseteam import cli as team_cli
from argus.caseteam.model import Author
from argus.config.settings import CaseTeamSettings, KibanaSettings, KibanaSyncSettings, Settings
from argus.gateway.kibana import models
from argus.gateway.kibana.templates import CasesFind, FindParams
from argus.gateway.kibana.writes import WriteClass
from argus.kibana_sync import classify, cli
from argus.kibana_sync.cycle import SyncConfig
from argus.kibana_sync.model import KAction, KCase, Kind, Mirror, SentWrite, TeamPost
from tests.unit.kibana_sync.fake import Rig, rig

T0 = datetime(2026, 10, 26, 9, 0, tzinfo=UTC)
LEAD, EVIDENCE, HUNTER = "argus-lead", "argus-evidence", "argus-hunter"
TEAM = CaseTeamSettings().users()
INCIDENT = "ACME-IR-2026-1026-01"
TAGS = (INCIDENT, "incident", "source:argus-lead")
PERSON = "ra-anita"
CASE = uuid.UUID(int=7)


def kinds(r: Rig) -> list[Kind]:
    return sorted(f.kind for _, f in r.store.findings.values())


def sent(op: str, by: str, n: int = 1) -> SentWrite:
    return SentWrite(op, frozenset(), n, by=by)


def team_rig(**config: Any) -> Rig:
    return rig(config=SyncConfig(team=TEAM, **config))


async def team_case(r: Rig, *writes: SentWrite, incident: str = INCIDENT) -> tuple[str, uuid.UUID]:
    """A case the lead opened (its open step sent, the post known), mirrored by one cycle."""
    case = uuid.uuid4()
    r.store.posts[case] = TeamPost(case, incident, None, 1, LEAD)
    r.sent(case, sent("create", LEAD), *writes)
    kid = r.kibana.create(by=LEAD, title="[IR] Amadey on a campus host", tags=(incident, *TAGS[1:]))
    record = await r.cycle()
    assert record.outcome == "complete", record.reason
    assert r.store.mirror[kid].case_id == case
    return kid, case


# --------------------------------------------------------------------------- the reporters set


def test_the_reporters_are_the_service_user_and_the_case_teams_users_from_settings() -> None:
    settings = Settings(kibana=KibanaSettings(service_user="soc-bot"))
    config = cli.config_of(settings)
    assert config.author == "soc-bot"
    assert config.team == settings.case_team.users()
    assert isinstance(config.reporters, tuple)
    assert config.reporters[0] == "soc-bot"
    assert set(config.reporters) == {"soc-bot", *settings.case_team.users()}
    assert config.identities == set(config.reporters)


def test_the_team_users_do_not_depend_on_the_keys_the_unit_holds() -> None:
    """The read-back's unit holds only the reader key, so the names cannot come from the keys."""
    assert CaseTeamSettings().keys() == {}
    assert CaseTeamSettings().users() == CaseTeamSettings(lead_api_key="k").users()
    # the names are the case team's vocabulary and the gateway's allow-list: one list
    assert set(TEAM) == {a.value for a in Author} == set(models.TEAM_USERS)


def test_the_team_can_be_left_out_of_the_read_back() -> None:
    sync = KibanaSyncSettings(team_cases=False)
    config = cli.config_of(Settings(kibana=KibanaSettings(sync=sync)))
    assert config.team == ()
    assert config.reporters == "argus"
    assert config.identities == {"argus"}


def test_the_service_user_named_in_the_team_is_one_reporter() -> None:
    config = SyncConfig(author=LEAD, team=TEAM)
    assert config.reporters == tuple(dict.fromkeys(TEAM))
    assert len(config.reporters) == len(set(config.reporters))


def test_the_dry_run_names_every_reporter() -> None:
    wanted = "&".join(f"reporters={n}" for n in ("argus", *TEAM))
    finds = [line for line in cli._plan(Settings()) if "cases/_find" in line]
    assert len(finds) == 3  # the change poll, the listing, the closed probe
    assert all(wanted in line for line in finds)


# --------------------------------------------------------------------------- the find's params


def query(reporters: Any) -> list[tuple[str, str]]:
    plan = CasesFind().build(FindParams(reporters=reporters))
    return [(k, v) for k, v in plan.url_params if k == "reporters"]


def test_one_reporter_is_one_parameter_and_several_are_a_repeated_key() -> None:
    assert query("argus") == [("reporters", "argus")]
    assert query(("argus", LEAD, EVIDENCE)) == [
        ("reporters", "argus"),
        ("reporters", LEAD),
        ("reporters", EVIDENCE),
    ]
    assert query(("argus", "argus", LEAD)) == [("reporters", "argus"), ("reporters", LEAD)]
    assert FindParams().reporters is None
    assert query(None) == []


def test_the_lane_lets_reporters_repeat_and_nothing_else_but_tags() -> None:
    from argus.gateway.errors import TemplateRejectedError
    from argus.gateway.kibana.gateway import build_final
    from argus.gateway.kibana.validator import validate

    space, prefix = "acme-soc", ".internal.alerts-security.alerts-acme-soc-"
    final = build_final(CasesFind(), FindParams(reporters=("argus", LEAD, EVIDENCE)), space, prefix)
    validate(final, space, prefix)
    assert [v for k, v in final.url_params if k == "reporters"] == ["argus", LEAD, EVIDENCE]
    twice = replace(final, url_params=(*final.url_params, ("status", "open"), ("status", "closed")))
    with pytest.raises(TemplateRejectedError, match="given twice"):
        validate(twice, space, prefix)


@pytest.mark.parametrize(
    "bad",
    [
        (),
        ("",),
        ("a b",),
        ("a&reporters=x",),
        ("a/b",),
        tuple(f"u{i}" for i in range(17)),
        "x" * 65,
    ],
)
def test_reporters_are_usernames_and_at_most_sixteen(bad: Any) -> None:
    with pytest.raises(ValidationError):
        FindParams(reporters=bad)


async def test_every_find_of_a_cycle_names_all_the_reporters() -> None:
    r = team_rig()
    await team_case(r)
    await r.cycle()
    finds = [w for w in r.kibana.requests if w.path.endswith("/cases/_find")]
    assert len(finds) >= 4  # the poll, open, in-progress, the closed probe
    for wire in finds:
        named = [v for k, v in wire.params if k == "reporters"]
        assert named == ["argus", *TEAM], wire.params


async def test_a_read_back_without_the_team_asks_for_argus_alone() -> None:
    r = rig()
    await r.cycle()
    finds = [w for w in r.kibana.requests if w.path.endswith("/cases/_find")]
    assert finds
    for wire in finds:
        assert [v for k, v in wire.params if k == "reporters"] == ["argus"]


# --------------------------------------------------------------------------- classification


def mirror(**kw: object) -> Mirror:
    base: dict[str, Any] = {
        "case_id": CASE,
        "kibana_case_id": "k-1",
        "kibana_version": "v1",
        "status": "open",
        "title": "[IR] t",
        "severity": "medium",
        "tags": (),
        "created_by": LEAD,
        "sync_alerts": False,
        "kibana_created_at": T0,
        "kibana_updated_at": None,
        "read_at": T0,
    }
    base.update(kw)
    return Mirror(**base)


def kcase(**kw: object) -> KCase:
    base: dict[str, Any] = {
        "id": "k-1",
        "version": "v9",
        "status": "open",
        "title": "[IR] t",
        "severity": "medium",
        "tags": TAGS,
        "created_by": LEAD,
        "sync_alerts": False,
        "created_at": T0,
        "updated_at": T0,
    }
    base.update(kw)
    return KCase(**base)


def action(n: int, kind: str, by: str, verb: str = "update", **payload: object) -> KAction:
    return KAction(f"a{n}", kind, verb, T0 + timedelta(seconds=n), by, payload)


def run(
    actions: list[KAction], writes: tuple[SentWrite, ...] = (), **case: object
) -> classify.CaseOutcome:
    return classify.classify_case(
        mirror(),
        kcase(**case),
        actions,
        writes,
        author="argus",
        now=T0,
        kibana_now=T0 + timedelta(minutes=5),
        complete=True,
        team=frozenset(TEAM),
    )


def comment(n: int, by: str) -> KAction:
    return action(n, "comment", by, "create", comment={"type": "user", "comment": "x"})


def test_a_team_users_action_is_explained_by_a_step_of_its_own_author_only() -> None:
    steps = (sent("create", LEAD), sent("comment", EVIDENCE, 2))
    acts = [action(1, "create_case", LEAD, "create"), comment(2, EVIDENCE), comment(3, EVIDENCE)]
    out = run(acts, steps)
    assert out.findings == ()
    assert not out.pause_all
    assert dict(out.mirror.argus_actions) == {f"{LEAD}:create": 1, f"{EVIDENCE}:comment": 2}
    # the hunter's comment is not the evidence agent's: nothing explains it
    odd = run([*acts, comment(4, HUNTER)], steps)
    assert [f.kind for f in odd.findings] == [Kind.UNEXPLAINED_ARGUS_ACTION]
    assert odd.findings[0].details["counted"] == f"{HUNTER}:comment"
    assert odd.pause_all
    # one comment more than was sent
    more = run([*acts, comment(4, EVIDENCE)], steps)
    assert [f.kind for f in more.findings] == [Kind.UNEXPLAINED_ARGUS_ACTION]


def test_the_service_users_own_counts_keep_their_plain_keys() -> None:
    out = run([action(1, "create_case", "argus", "create")], (SentWrite("create", frozenset(), 1),))
    assert out.findings == ()
    assert dict(out.mirror.argus_actions) == {"create": 1}
    assert classify.capacity([sent("comment", EVIDENCE)], "argus") == {f"{EVIDENCE}:comment": 1}
    assert classify.capacity([SentWrite("comment", frozenset(), 1)], "argus") == {"comment": 1}


def test_each_step_kind_explains_its_own_action() -> None:
    steps = (
        sent("create", LEAD),
        sent("attach", LEAD, 2),
        sent("comment", "argus-reporter", 2),  # a comment and a file: both are comment actions
        sent("title", LEAD),
        sent("description", LEAD),
        sent("edit_comment", EVIDENCE),
    )
    acts = [
        action(1, "create_case", LEAD, "create"),
        action(2, "comment", LEAD, "create", comment={"type": "alert", "alertId": ["a"]}),
        action(3, "comment", LEAD, "create", comment={"type": "alert", "alertId": ["b"]}),
        comment(4, "argus-reporter"),
        action(
            5,
            "comment",
            "argus-reporter",
            "create",
            comment={"type": "externalReference", "externalReferenceAttachmentTypeId": ".files"},
        ),
        action(6, "title", LEAD, title="[IR] corrected"),
        action(7, "description", LEAD, description="corrected"),
        action(8, "comment", EVIDENCE, "update", comment={"type": "user", "comment": "fixed"}),
    ]
    out = run(acts, steps)
    assert out.findings == ()
    assert out.mirror.unmanaged == frozenset()
    # without the steps every one of them is unexplained
    bare = run(acts)
    assert [f.kind for f in bare.findings] == [Kind.UNEXPLAINED_ARGUS_ACTION] * len(acts)
    # a retitle is not explained by a redescribe
    swapped = run(
        [action(1, "title", LEAD, title="x")],
        (sent("description", LEAD),),
    )
    assert [f.kind for f in swapped.findings] == [Kind.UNEXPLAINED_ARGUS_ACTION]


def test_a_comment_edit_is_its_own_kind_and_a_persons_edit_is_still_theirs() -> None:
    edit = action(1, "comment", EVIDENCE, "update", comment={"type": "user", "comment": "x"})
    assert classify.action_kind(edit) == "edit_comment"
    assert classify.action_kind(comment(2, EVIDENCE)) == "comment"
    assert run([edit], (sent("comment", EVIDENCE),)).findings[0].kind is (
        Kind.UNEXPLAINED_ARGUS_ACTION
    ), "a comment posted does not explain a comment edited"
    theirs = action(3, "comment", PERSON, "update", comment={"type": "user", "comment": "mine"})
    out = run([theirs])
    assert [f.kind for f in out.findings] == [Kind.PERSON_COMMENTED]
    assert not out.pause_all


def test_a_persons_edits_on_a_team_case_are_theirs_and_never_reverted() -> None:
    out = run(
        [
            action(1, "title", PERSON, title="My title"),
            action(2, "description", PERSON, description="notes"),
            action(3, "tags", PERSON, "add", tags=["phishing"]),
            comment(4, PERSON),
            action(5, "assignees", PERSON, assignees=[{"uid": "u"}]),
            action(6, "status", PERSON, status="closed"),
            action(7, "status", PERSON, status="open"),
            action(8, "comment", PERSON, "delete", comment={"type": "user", "comment": "old"}),
        ],
        title="My title",
    )
    assert [f.kind for f in out.findings] == [
        Kind.PERSON_EDITED,
        Kind.PERSON_EDITED,
        Kind.PERSON_EDITED,
        Kind.PERSON_COMMENTED,
        Kind.PERSON_EDITED,
        Kind.CLOSED_IN_KIBANA,
        Kind.REOPENED_IN_KIBANA,
        Kind.PERSON_DELETED,
    ]
    assert out.mirror.unmanaged == {"title", "description", "assignees"}
    assert out.mirror.title == "My title"
    assert not out.pause_all
    assert out.mirror.paused_reason is None, "a person's edit pauses nothing on a team case"


def test_a_status_or_delete_by_a_team_user_is_unexplained() -> None:
    """ARGUS never closes a case, and never deletes a comment."""
    out = run(
        [
            action(1, "status", LEAD, status="closed"),
            action(2, "comment", LEAD, "delete", comment={"type": "user", "comment": "x"}),
        ]
    )
    assert [f.kind for f in out.findings] == [Kind.UNEXPLAINED_ARGUS_ACTION] * 2
    assert out.mirror.status == "closed", "it is still what Kibana says"


def test_a_case_by_a_team_user_is_argus_s_and_by_anyone_else_is_not() -> None:
    assert run([], created_by=EVIDENCE).findings == ()
    out = run([], created_by=PERSON)
    assert [f.kind for f in out.findings] == [Kind.NOT_ARGUS_CASE]
    assert out.pause_all
    # without the team the same case is not ARGUS's
    alone = classify.classify_case(
        mirror(),
        kcase(),
        [],
        (),
        author="argus",
        now=T0,
        kibana_now=T0 + timedelta(minutes=5),
        complete=True,
    )
    assert [f.kind for f in alone.findings] == [Kind.NOT_ARGUS_CASE]


KIND_OF = {  # the kinds of ARGUS action and the Kibana action each is
    "create": ("create_case", "create", {}),
    "comment": ("comment", "create", {"comment": {"type": "user", "comment": "x"}}),
    "edit_comment": ("comment", "update", {"comment": {"type": "user", "comment": "x"}}),
    "attach": ("comment", "create", {"comment": {"type": "alert", "alertId": ["a"]}}),
    "title": ("title", "update", {"title": "t"}),
    "description": ("description", "update", {"description": "d"}),
}
WHO = st.sampled_from(["argus", *TEAM])
WHAT = st.sampled_from(sorted(KIND_OF))


@given(
    st.lists(st.tuples(WHO, WHAT), max_size=30),
    st.lists(st.tuples(WHO, WHAT, st.integers(0, 3)), max_size=12),
    st.integers(0, 30),
)
def test_an_argus_action_is_unexplained_exactly_when_its_authors_steps_run_out(
    seen: list[tuple[str, str]], steps: list[tuple[str, str, int]], cut: int
) -> None:
    """Whatever ARGUS identity did what, in whatever split of the reads: the unexplained actions
    are those past what that author's sent steps of that kind account for, and the alarm
    pauses writes exactly then."""
    writes = tuple(
        SentWrite(op, frozenset(), n, by="" if by == "argus" else by) for by, op, n in steps
    )
    actions = [
        action(i, KIND_OF[what][0], by, KIND_OF[what][1], **KIND_OF[what][2])
        for i, (by, what) in enumerate(seen, 1)
    ]
    room: dict[tuple[str, str], int] = {}
    for by, op, n in steps:
        room[(by, op)] = room.get((by, op), 0) + n
    used: dict[tuple[str, str], int] = {}
    for by, what in seen:
        used[(by, what)] = used.get((by, what), 0) + 1
    expected = sum(max(0, n - room.get(key, 0)) for key, n in used.items())

    whole = run(actions, writes)
    assert sum(f.kind is Kind.UNEXPLAINED_ARGUS_ACTION for f in whole.findings) == expected
    assert whole.pause_all is (expected > 0)
    assert all(f.kind is Kind.UNEXPLAINED_ARGUS_ACTION for f in whole.findings)

    first = classify.classify_case(
        mirror(),
        kcase(),
        actions[:cut],
        writes,
        author="argus",
        now=T0,
        kibana_now=T0 + timedelta(minutes=5),
        complete=True,
        team=frozenset(TEAM),
    )
    second = classify.classify_case(
        first.mirror,
        kcase(),
        actions[cut:],
        writes,
        author="argus",
        now=T0,
        kibana_now=T0 + timedelta(minutes=5),
        complete=True,
        team=frozenset(TEAM),
    )
    assert {f.dedupe_key for f in (*first.findings, *second.findings)} == {
        f.dedupe_key for f in whole.findings
    }
    assert dict(second.mirror.argus_actions) == dict(whole.mirror.argus_actions)


# --------------------------------------------------------------------------- adoption


def post(**kw: Any) -> TeamPost:
    base: dict[str, Any] = {
        "case_id": CASE,
        "incident_id": INCIDENT,
        "kibana_case_id": None,
        "opens": 1,
        "opener": LEAD,
    }
    base.update(kw)
    return TeamPost(**base)


def test_a_team_case_is_adopted_by_its_recorded_id_or_by_its_incident_tag() -> None:
    case = kcase(id="k-9")
    recorded = classify.adopt_team(case, posts=[post(kibana_case_id="k-9")], mirrored={})
    assert recorded.case_id == CASE
    waiting = classify.adopt_team(case, posts=[post()], mirrored={})
    assert waiting.case_id == CASE
    assert not waiting.findings
    # the id the poster recorded wins, and needs no sent open step to be recorded
    assert classify.adopt_team(case, posts=[post(kibana_case_id="k-9", opens=0)], mirrored={})


def test_a_team_case_nothing_explains_is_an_alarm() -> None:
    case = kcase(id="k-9")
    for posts in (
        [],  # no post at all
        [post(opens=0)],  # a post whose open was never sent
        [post(incident_id="ACME-IR-2026-1026-02")],  # another incident
        [post(), post(case_id=uuid.UUID(int=8))],  # two posts claim it: nothing says which
    ):
        out = classify.adopt_team(case, posts=posts, mirrored={})
        assert out.case_id is None
        assert out.pause_all
        assert [f.kind for f in out.findings] == [Kind.UNEXPLAINED_ARGUS_CASE]


def test_a_second_kibana_case_for_a_post_is_flagged_not_adopted() -> None:
    case = kcase(id="k-9")
    other_case = classify.adopt_team(case, posts=[post(kibana_case_id="k-1")], mirrored={})
    assert other_case.case_id is None
    assert not other_case.pause_all
    assert [f.kind for f in other_case.findings] == [Kind.DUPLICATE_CASE]
    mirrored = classify.adopt_team(case, posts=[post()], mirrored={CASE: "k-1"})
    assert mirrored.case_id is None
    assert not mirrored.pause_all
    assert [f.kind for f in mirrored.findings] == [Kind.DUPLICATE_CASE]


# --------------------------------------------------------------------------- the cycle


async def test_a_team_case_is_mirrored_with_its_create_explained() -> None:
    r = team_rig()
    kid, _ = await team_case(r)
    mirror_ = r.store.mirror[kid]
    assert mirror_.created_by == LEAD
    assert mirror_.actions_seen == 1
    assert dict(mirror_.argus_actions) == {f"{LEAD}:create": 1}
    assert kinds(r) == []
    assert not (await r.lane.kibana_lane()).paused
    assert all(w.method == "GET" for w in r.kibana.requests), "the read-back only reads"


async def test_the_team_s_cases_and_the_service_user_s_are_one_listing() -> None:
    r = team_rig()
    kid, _ = await team_case(r)
    own = uuid.uuid4()
    r.sent(own, SentWrite("create", frozenset(), 1))
    mine = r.kibana.create(argus_case=own)
    await r.cycle()
    assert {kid, mine} <= set(r.store.mirror)
    assert kinds(r) == []
    open_listing = [w for w in r.kibana.requests if dict(w.params).get("status") == "open"]
    assert all(
        [v for k, v in w.params if k == "reporters"] == ["argus", *TEAM] for w in open_listing
    )


async def test_a_team_case_made_without_a_post_is_an_alarm_never_adopted() -> None:
    r = team_rig()
    kid = r.kibana.create(by=LEAD, tags=TAGS)  # no post: a stray key, a manual case
    await r.cycle()
    assert kinds(r) == [Kind.UNEXPLAINED_ARGUS_CASE]
    assert kid not in r.store.mirror
    assert (await r.lane.kibana_lane()).paused
    stray = r.kibana.create(by=EVIDENCE, tags=("ACME-IR-2026-1026-09", "incident"))
    await r.cycle()
    assert stray not in r.store.mirror, "any ARGUS identity's case is looked at"


async def test_the_case_is_found_before_the_poster_recorded_its_id() -> None:
    """The create landed and the run ended: the post has the sent open step, no Kibana id."""
    r = team_rig()
    kid, _ = await team_case(r)  # post with kibana_case_id None
    assert r.store.posts[r.store.mirror[kid].case_id].kibana_case_id is None


async def test_arguss_own_retitle_and_comments_are_explained_and_a_persons_are_not_argus() -> None:
    r = team_rig()
    kid, _ = await team_case(r, sent("comment", EVIDENCE), sent("title", LEAD))
    r.kibana.comment(kid, EVIDENCE, "Evidence.")
    r.kibana.set_field(kid, LEAD, "title", "[IR] Amadey, corrected")
    await r.cycle()
    assert kinds(r) == []
    assert r.store.mirror[kid].title == "[IR] Amadey, corrected"
    assert r.store.mirror[kid].unmanaged == frozenset(), "ARGUS's own retitle is not a person's"
    r.kibana.comment(kid, HUNTER, "a comment the hunter was never sent to write")
    await r.cycle()
    assert kinds(r) == [Kind.UNEXPLAINED_ARGUS_ACTION]
    assert set((await r.lane.kibana_lane()).paused) == {
        c.value for c in (WriteClass.W1, WriteClass.W2, WriteClass.W3, WriteClass.WA)
    }


async def test_a_persons_title_edit_is_in_the_mirror_within_one_cycle() -> None:
    r = team_rig()
    kid, _ = await team_case(r)
    r.kibana.set_field(kid, PERSON, "title", "Amadey, confirmed by Anita")
    record = await r.cycle()
    mirror_ = r.store.mirror[kid]
    assert (mirror_.title, "title" in mirror_.unmanaged) == ("Amadey, confirmed by Anita", True)
    assert kinds(r) == [Kind.PERSON_EDITED]
    [(_, found)] = r.store.findings.values()
    assert (found.details["field"], found.details["by"]) == ("title", PERSON)
    assert found.lag_s is not None
    assert found.lag_s <= 600 + 120, "one cycle (10 minutes) and the lane's waits"
    assert record.changed == 1
    assert not (await r.lane.kibana_lane()).paused, "ARGUS pauses nothing for a person's edit"


async def test_a_persons_close_and_reopen_are_findings_and_nothing_is_reverted() -> None:
    r = team_rig()
    kid, _ = await team_case(r)
    r.kibana.set_status(kid, PERSON, "closed")
    await r.cycle()
    assert r.store.mirror[kid].status == "closed"
    assert kinds(r) == [Kind.CLOSED_IN_KIBANA]
    r.kibana.set_status(kid, PERSON, "open")
    await r.cycle()
    assert r.store.mirror[kid].status == "open"
    assert kinds(r) == [Kind.CLOSED_IN_KIBANA, Kind.REOPENED_IN_KIBANA]
    assert all(w.method == "GET" for w in r.kibana.requests)
    assert not (await r.lane.kibana_lane()).paused


async def test_a_persons_comment_and_tag_on_a_team_case_are_theirs() -> None:
    r = team_rig()
    kid, _ = await team_case(r)
    r.kibana.comment(kid, PERSON, "Verdict: true positive")
    r.kibana.add_tags(kid, PERSON, "phishing")
    await r.cycle()
    assert kinds(r) == [Kind.PERSON_COMMENTED, Kind.PERSON_EDITED]
    assert r.store.mirror[kid].paused_reason is None


async def test_a_deleted_team_case_is_confirmed_by_a_get_and_recorded() -> None:
    r = team_rig()
    kid, case = await team_case(r)
    other_kid, _ = await team_case(r, incident="ACME-IR-2026-1026-02")
    r.kibana.delete(kid)
    record = await r.cycle()
    mirror_ = r.store.mirror[kid]
    assert mirror_.deleted_at is not None
    assert mirror_.case_id == case
    assert r.store.mirror[other_kid].deleted_at is None, "only the deleted one"
    assert kinds(r) == [Kind.DELETED_IN_KIBANA]
    assert record.detail["deleted"] == 1
    gets = [w.path for w in r.kibana.requests if w.path.endswith(f"/cases/{kid}")]
    assert gets, "a missing id alone is never a deletion: cases.get said 404"
    await r.cycle()
    assert kinds(r) == [Kind.DELETED_IN_KIBANA], "found once"


async def test_a_team_case_hidden_from_one_listing_is_not_deleted() -> None:
    r = team_rig()
    kid, _ = await team_case(r)
    r.kibana.hidden.add(kid)  # Kibana's refresh lag: the id is missing from the find
    await r.cycle()
    assert r.store.mirror[kid].deleted_at is None
    assert kinds(r) == []


async def test_the_team_s_cases_are_invisible_when_the_team_is_left_out() -> None:
    r = rig()  # SyncConfig without a team: the read-back of before
    case = uuid.uuid4()
    r.store.posts[case] = TeamPost(case, INCIDENT, None, 1, LEAD)
    r.kibana.create(by=LEAD, tags=TAGS)
    await r.cycle()
    assert r.store.mirror == {}
    assert kinds(r) == []


async def test_a_case_by_a_team_user_holding_known_alerts_is_no_persons_case() -> None:
    """Hourly discovery finds the cases that hold alerts ARGUS knows; one made by an ARGUS
    identity is not "a person's" (before the team was read, every posted case was)."""
    r = team_rig()
    stray = r.kibana.create(by=EVIDENCE, tags=("ACME-IR-2026-1026-09",))
    r.kibana.attach(stray, EVIDENCE, "alert-7")
    r.store.alerts = [(r.clock.now, "alert-7")]
    await r.cycle(advance=timedelta(hours=1, minutes=1))
    assert Kind.PEOPLE_CASE not in kinds(r)
    assert r.store.people == {}
    person = r.kibana.create(by=PERSON, tags=("mine",))
    r.kibana.attach(person, PERSON, "alert-7")
    await r.cycle(advance=timedelta(hours=1, minutes=1))
    assert Kind.PEOPLE_CASE in kinds(r), "a person's case holding the alert still is"


async def test_the_alert_diff_leaves_the_team_s_cases_alone() -> None:
    """People triage a team incident's alerts in Kibana: no alarm for a status change there."""
    r = team_rig()
    kid, _ = await team_case(r, sent("attach", LEAD))
    r.kibana.attach(kid, LEAD, "alert-1")
    r.kibana.alert_status("alert-1", "open", by=None)
    await r.cycle(advance=timedelta(hours=1, minutes=1))
    r.kibana.alert_status("alert-1", "closed", by=None)  # the internal route: no user
    await r.cycle(advance=timedelta(hours=1, minutes=1))
    assert Kind.ALERT_CHANGE_UNEXPLAINED not in kinds(r)
    assert not (await r.lane.kibana_lane()).paused
    assert all(kid not in (w.body or b"").decode() for w in r.kibana.es_requests)


async def test_the_alert_diff_still_watches_the_service_user_s_cases() -> None:
    r = team_rig()
    own = uuid.uuid4()
    r.sent(own, SentWrite("create", frozenset(), 1), SentWrite("attach", frozenset(), 1))
    mine = r.kibana.create(argus_case=own)
    await r.cycle()
    r.kibana.attach(mine, "argus", "alert-2")
    r.kibana.alert_status("alert-2", "open", by=None)
    await r.cycle(advance=timedelta(hours=1, minutes=1))
    r.kibana.alert_status("alert-2", "closed", by=None)
    await r.cycle(advance=timedelta(hours=1, minutes=1))
    assert Kind.ALERT_CHANGE_UNEXPLAINED in kinds(r)


async def test_the_closed_probe_counts_the_team_s_closed_cases_with_the_rest() -> None:
    r = team_rig()
    kid, _ = await team_case(r)
    r.kibana.set_status(kid, PERSON, "closed")
    record = await r.cycle()
    assert record.detail["closed"] == [1, 1], "the probe's total and the mirror's closed count"
    r.kibana.delete(kid)
    record = await r.cycle()
    assert r.store.mirror[kid].deleted_at is not None
    assert kinds(r) == [Kind.CLOSED_IN_KIBANA, Kind.DELETED_IN_KIBANA]


# --------------------------------------------------------------------------- the status line


def line(**kw: Any) -> str:
    base: dict[str, Any] = {
        "kibana_case_id": "k-1",
        "deleted_at": None,
        "read_at": datetime(2026, 10, 30, 12, 5, tzinfo=UTC),
        "kibana_status": "open",
        "unmanaged": [],
        "paused_reason": None,
    }
    base.update(kw)
    return team_cli._read_back(SimpleNamespace(**base))


def test_the_status_command_says_what_the_read_back_saw() -> None:
    assert line() == "read back: Kibana status open, read 2026-10-30 12:05 UTC"
    assert "not in Kibana yet" in line(kibana_case_id=None)
    assert "not read yet" in line(read_at=None)
    assert "a person changed description, title" in line(unmanaged=["title", "description"])
    gone = line(deleted_at=datetime(2026, 10, 30, 13, 0, tzinfo=UTC))
    assert "DELETED in Kibana (found 2026-10-30 13:00 UTC)" in gone
    assert "nothing more is posted" in gone


def test_the_posters_candidates_leave_out_a_case_deleted_in_kibana() -> None:
    """The query itself runs in tests/integration/caseteam/test_readback.py; here its shape: the
    deleted-in-Kibana check stands before the three ways a case qualifies, which all sit inside
    one bracket."""
    from argus.caseteam import store

    sql = str(store._CANDIDATES)
    assert sql.count("(") == sql.count(")")
    assert sql.count(store.KIBANA_DELETED) == 1
    where = sql.index("WHERE NOT " + store.KIBANA_DELETED + " AND (")
    assert where < sql.index(" ORDER BY EXISTS"), "the outer ORDER BY, not the subqueries'"
    assert "k.deleted_at IS NOT NULL" in store.KIBANA_DELETED

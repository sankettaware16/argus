"""The Kibana lane's templates (Q-D2): the only requests ARGUS can make to Kibana.

A template names its endpoint (``paths.KEndpoint``), the key that sends it (Kibana's reader,
the cases writer or the alert writer), its write classes (none: a read), a cost estimate (a
Kibana call is charged max(round trip, estimate), plan §7.8), its parameter model, the URL
parameters it may carry and the check of its answer. Writes build their body from a strict
model (``models.py``); the validator re-reads the exact bytes against it before sending.

Reads: ``kibana.status``, ``cases.find``, ``cases.get``, ``cases.user_actions``,
``cases.comments``, ``cases.configure`` and the technical-preview ``cases.alerts`` and
``alerts.cases`` (optional: Q-D3 relies on ``kibana.alert.case_ids`` and user actions first).
Writes: ``cases.create``, ``cases.comment``, ``cases.attach_alerts`` (W1), ``cases.update``
(W2), ``cases.close`` (W3), ``alerts.status`` (WA). A comment belongs to the class of the
change it explains (W1, W2 or W3), which the write's context names.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import timedelta
from enum import StrEnum
from typing import Annotated, Any, ClassVar, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from argus.gateway.kibana import models, upload
from argus.gateway.kibana.paths import KEndpoint, Target
from argus.gateway.kibana.writes import WriteClass, WriteUnits
from argus.gateway.templates import CostClass

TIMEOUT = timedelta(seconds=15)  # plan §5 Q-D2; kibana.timeout sets it (KibanaGateway)
MAX_PAGE_DEPTH = 10_000  # Kibana refuses paging past 10,000 documents


class KeyRole(StrEnum):
    """Which of ARGUS's Kibana keys sends a request (DQ3 (a))."""

    READER = "reader"  # Cases Read only
    CASES = "cases"  # the cases writer (W1-W3)
    ALERTS = "alerts"  # the alert writer (WA)
    TEAM = "team"  # the case team's six users (AR8): the key is picked by the request's author


class Params(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class NoParams(Params):
    pass


@dataclass(frozen=True)
class KSpec:
    name: str
    version: int
    endpoint: KEndpoint
    key: KeyRole
    classes: frozenset[WriteClass]
    estimate_ms: int
    url_params: frozenset[str]
    body_model: type[BaseModel] | None
    preview: bool
    cost: CostClass = CostClass.LIGHT

    @property
    def write(self) -> bool:
        return bool(self.classes)


@dataclass(frozen=True)
class KPlan:
    """A template's request before the gateway turns it into a path and bytes."""

    spec: KSpec
    target: Target = field(default_factory=Target)
    url_params: tuple[tuple[str, str], ...] = ()
    body: BaseModel | None = None
    units: WriteUnits | None = None  # writes only
    as_user: str | None = None  # the case team: whose key sends it (KeyRole.TEAM only)
    raw_body: bytes | None = None  # a request that is not JSON (a file): the exact bytes


class KibanaTemplate(ABC):
    name: ClassVar[str]
    version: ClassVar[int]
    endpoint: ClassVar[KEndpoint]
    key: ClassVar[KeyRole] = KeyRole.READER
    classes: ClassVar[frozenset[WriteClass]] = frozenset()
    estimate_ms: ClassVar[int] = 50
    params_model: ClassVar[type[BaseModel]] = NoParams
    url_param_names: ClassVar[frozenset[str]] = frozenset()
    body_model: ClassVar[type[BaseModel] | None] = None
    preview: ClassVar[bool] = False
    # Every Kibana call is light for admission (its estimate is reserved from the lane); it is
    # charged max(round trip, estimate_ms) afterwards (plan §7.8). None is heavy.
    cost: ClassVar[CostClass] = CostClass.LIGHT

    @classmethod
    def spec(cls) -> KSpec:
        return KSpec(
            cls.name,
            cls.version,
            cls.endpoint,
            cls.key,
            cls.classes,
            cls.estimate_ms,
            cls.url_param_names,
            cls.body_model,
            cls.preview,
            cls.cost,
        )

    def plan(self, params: BaseModel) -> KPlan:
        if type(params) is not self.params_model:
            raise TypeError(f"{self.name} takes {self.params_model.__name__}")
        return self.build(params)

    def build(self, params: BaseModel) -> KPlan:
        return KPlan(self.spec())

    @abstractmethod
    def check(self, params: BaseModel, answer: Any, author: str | None) -> Any:
        """The answer, if it is what this request must produce; else AnswerMismatchError."""

    @classmethod
    def opaque_id(cls, component: str) -> str:
        return f"argus-{component}/{cls.name}@{cls.version}"


KREGISTRY: dict[str, type[KibanaTemplate]] = {}


def kregister(template: type[KibanaTemplate]) -> type[KibanaTemplate]:
    if template.name in KREGISTRY and KREGISTRY[template.name] is not template:
        raise ValueError(f"Kibana template {template.name} is registered twice")
    if not isinstance(template.version, int) or template.version < 1:
        raise ValueError(f"Kibana template {template.name} needs a positive version")
    if template.classes and template.body_model is None:
        raise ValueError(f"the write {template.name} needs a body model")
    if not template.classes and template.body_model is not None:
        raise ValueError(f"the read {template.name} sends no body")
    if template.cost is not CostClass.LIGHT:
        raise ValueError(f"the Kibana template {template.name} is light (plan §7.8)")
    KREGISTRY[template.name] = template
    return template


CaseId = Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{1,64}$")]
AlertId = Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{1,128}$")]
TagFilter = Annotated[str, Field(pattern=r"^[A-Za-z0-9:_.@-]{1,256}$")]
Reporter = Annotated[str, Field(pattern=r"^[A-Za-z0-9_.@-]{1,64}$")]  # a Kibana username
MAX_REPORTERS = 16  # a find names ARGUS's identities: the service user and the case team's
Reporters = (
    Reporter | Annotated[tuple[Reporter, ...], Field(min_length=1, max_length=MAX_REPORTERS)]
)  # one username, or several (a case by any of them)


def _paging(page: int, per_page: int) -> None:
    if page * per_page > MAX_PAGE_DEPTH:
        raise ValueError(f"Kibana pages through at most {MAX_PAGE_DEPTH} documents")


# --------------------------------------------------------------------------- reads


@kregister
class KibanaStatus(KibanaTemplate):
    """Kibana's version and overall level: before every write run (the pinned version)."""

    name = "kibana.status"
    version = 1
    endpoint = KEndpoint.STATUS

    def check(self, params: BaseModel, answer: Any, author: str | None) -> tuple[str, str]:
        return models.check_status(answer)


@kregister
class KibanaSpaces(KibanaTemplate):
    """The Kibana spaces (``argus discover``): which space holds the Security alerts."""

    name = "kibana.spaces"
    version = 1
    endpoint = KEndpoint.SPACES

    def check(self, params: BaseModel, answer: Any, author: str | None) -> list[dict[str, str]]:
        return models.check_named(answer, "space")


@kregister
class KibanaFeatures(KibanaTemplate):
    """Kibana's features (``argus discover``): the ids of the Security and Cases features, which
    the capability map names (``argus.site.feature_ids`` picks them)."""

    name = "kibana.features"
    version = 1
    endpoint = KEndpoint.FEATURES
    estimate_ms = 100

    def check(self, params: BaseModel, answer: Any, author: str | None) -> list[dict[str, str]]:
        return models.check_named(answer, "feature")


class FindParams(Params):
    tags: tuple[TagFilter, ...] = Field(default=(), max_length=5)
    reporters: Reporters | None = None
    status: Literal["open", "in-progress", "closed"] | None = None
    sort_field: Literal["updatedAt", "createdAt"] = "updatedAt"
    sort_order: Literal["asc", "desc"] = "asc"
    page: int = Field(default=1, ge=1, le=10_000)
    per_page: int = Field(default=20, ge=1, le=100)

    @model_validator(mode="after")
    def _deep(self) -> FindParams:
        _paging(self.page, self.per_page)
        return self


@kregister
class CasesFind(KibanaTemplate):
    name = "cases.find"
    version = 1
    endpoint = KEndpoint.CASES_FIND
    estimate_ms = 100
    params_model = FindParams
    url_param_names = frozenset(
        {"owner", "tags", "reporters", "status", "sortField", "sortOrder", "page", "perPage"}
    )

    def build(self, params: BaseModel) -> KPlan:
        assert isinstance(params, FindParams)
        url: list[tuple[str, str]] = [("owner", models.OWNER)]
        url += [("tags", tag) for tag in params.tags]
        if params.reporters is not None:  # a repeated key: Kibana matches any of the usernames
            names = (params.reporters,) if isinstance(params.reporters, str) else params.reporters
            url += [("reporters", name) for name in dict.fromkeys(names)]
        if params.status is not None:
            url.append(("status", params.status))
        url += [
            ("sortField", params.sort_field),
            ("sortOrder", params.sort_order),
            ("page", str(params.page)),
            ("perPage", str(params.per_page)),
        ]
        return KPlan(self.spec(), url_params=tuple(url))

    def check(self, params: BaseModel, answer: Any, author: str | None) -> Any:
        page = models.check_page(answer, "cases")
        for case in page["cases"]:
            models.check_case(case)
        return page


class CaseParams(Params):
    case_id: CaseId


@kregister
class CaseGet(KibanaTemplate):
    name = "cases.get"
    version = 1
    endpoint = KEndpoint.CASE_GET
    params_model = CaseParams

    def build(self, params: BaseModel) -> KPlan:
        assert isinstance(params, CaseParams)
        return KPlan(self.spec(), Target(case_id=params.case_id))

    def check(self, params: BaseModel, answer: Any, author: str | None) -> Any:
        assert isinstance(params, CaseParams)
        return models.check_case(answer, case_id=params.case_id)


class CasePageParams(Params):
    case_id: CaseId
    page: int = Field(default=1, ge=1, le=10_000)
    per_page: int = Field(default=100, ge=1, le=100)
    sort_order: Literal["asc", "desc"] = "asc"

    @model_validator(mode="after")
    def _deep(self) -> CasePageParams:
        _paging(self.page, self.per_page)
        return self


@kregister
class CaseUserActions(KibanaTemplate):
    """Who changed what on a case, oldest first (Q-D3's change detection)."""

    name = "cases.user_actions"
    version = 1
    endpoint = KEndpoint.CASE_USER_ACTIONS
    estimate_ms = 100
    params_model = CasePageParams
    url_param_names = frozenset({"page", "perPage", "sortOrder"})

    def build(self, params: BaseModel) -> KPlan:
        assert isinstance(params, CasePageParams)
        url = (
            ("page", str(params.page)),
            ("perPage", str(params.per_page)),
            ("sortOrder", params.sort_order),
        )
        return KPlan(self.spec(), Target(case_id=params.case_id), url)

    def check(self, params: BaseModel, answer: Any, author: str | None) -> Any:
        return models.check_page(answer, "userActions", per_page="perPage")


@kregister
class CaseComments(KibanaTemplate):
    name = "cases.comments"
    version = 1
    endpoint = KEndpoint.CASE_COMMENTS
    estimate_ms = 100
    params_model = CasePageParams
    url_param_names = frozenset({"page", "perPage", "sortOrder"})

    def build(self, params: BaseModel) -> KPlan:
        assert isinstance(params, CasePageParams)
        url = (
            ("page", str(params.page)),
            ("perPage", str(params.per_page)),
            ("sortOrder", params.sort_order),
        )
        return KPlan(self.spec(), Target(case_id=params.case_id), url)

    def check(self, params: BaseModel, answer: Any, author: str | None) -> Any:
        return models.check_page(answer, "comments")


@kregister
class CasesConfigure(KibanaTemplate):
    """The case configuration (read only): a required custom field without a default would
    reject every create, so a write run reads it first (plan §2)."""

    name = "cases.configure"
    version = 1
    endpoint = KEndpoint.CASES_CONFIGURE
    url_param_names = frozenset({"owner"})

    def build(self, params: BaseModel) -> KPlan:
        return KPlan(self.spec(), url_params=(("owner", models.OWNER),))

    def check(self, params: BaseModel, answer: Any, author: str | None) -> Any:
        return models.check_list(answer)

    @staticmethod
    def blocks_creates(answer: list[Any]) -> bool:
        """True if a required custom field has no default value."""
        for config in answer:
            fields = config.get("customFields") if isinstance(config, Mapping) else None
            for item in fields if isinstance(fields, list) else []:
                if (
                    isinstance(item, Mapping)
                    and item.get("required")
                    and (item.get("defaultValue") in (None, ""))
                ):
                    return True
        return False


@kregister
class CaseAlerts(KibanaTemplate):
    """The alerts attached to a case (technical preview: optional)."""

    name = "cases.alerts"
    version = 1
    endpoint = KEndpoint.CASE_ALERTS
    params_model = CaseParams
    preview = True

    def build(self, params: BaseModel) -> KPlan:
        assert isinstance(params, CaseParams)
        return KPlan(self.spec(), Target(case_id=params.case_id))

    def check(self, params: BaseModel, answer: Any, author: str | None) -> Any:
        return models.check_list(answer)


class AlertParams(Params):
    alert_id: AlertId


@kregister
class AlertCases(KibanaTemplate):
    """The cases an alert is attached to (technical preview: optional)."""

    name = "alerts.cases"
    version = 1
    endpoint = KEndpoint.ALERT_CASES
    params_model = AlertParams
    url_param_names = frozenset({"owner"})
    preview = True

    def build(self, params: BaseModel) -> KPlan:
        assert isinstance(params, AlertParams)
        return KPlan(self.spec(), Target(alert_id=params.alert_id), (("owner", models.OWNER),))

    def check(self, params: BaseModel, answer: Any, author: str | None) -> Any:
        return models.check_list(answer)


# --------------------------------------------------------------------------- writes

CASE_WRITE = WriteUnits(case_write=True)


@kregister
class CreateCase(KibanaTemplate):
    name = "cases.create"
    version = 1
    endpoint = KEndpoint.CASE_CREATE
    key = KeyRole.CASES
    classes = frozenset({WriteClass.W1})
    estimate_ms = 100
    params_model = models.CaseCreate
    body_model = models.CaseCreate

    def build(self, params: BaseModel) -> KPlan:
        return KPlan(self.spec(), body=params, units=CASE_WRITE)

    def check(self, params: BaseModel, answer: Any, author: str | None) -> Any:
        assert isinstance(params, models.CaseCreate)
        return models.check_created(answer, params, author)


class CommentParams(Params):
    case_id: CaseId
    comment: str = Field(min_length=1, max_length=models.MAX_TEXT)


@kregister
class CommentOnCase(KibanaTemplate):
    name = "cases.comment"
    version = 1
    endpoint = KEndpoint.CASE_COMMENT
    key = KeyRole.CASES
    classes = frozenset({WriteClass.W1, WriteClass.W2, WriteClass.W3})
    estimate_ms = 100
    params_model = CommentParams
    body_model = models.UserComment

    def build(self, params: BaseModel) -> KPlan:
        assert isinstance(params, CommentParams)
        body = models.UserComment(comment=params.comment)
        return KPlan(self.spec(), Target(case_id=params.case_id), body=body, units=CASE_WRITE)

    def check(self, params: BaseModel, answer: Any, author: str | None) -> Any:
        assert isinstance(params, CommentParams)
        return models.check_commented(answer, params.case_id, author)


class AttachParams(Params):
    case_id: CaseId
    alerts: tuple[tuple[AlertId, str], ...] = Field(
        min_length=1, max_length=models.MAX_ALERTS_PER_CALL
    )  # (alert id, its concrete index)


@kregister
class AttachAlerts(KibanaTemplate):
    """Attaches alerts: Kibana's internal user then writes each alert's ``case_ids``, so every
    alert counts as an alert mutation (plan §7.1)."""

    name = "cases.attach_alerts"
    version = 1
    endpoint = KEndpoint.CASE_COMMENT
    key = KeyRole.CASES
    classes = frozenset({WriteClass.W1})
    estimate_ms = 150
    params_model = AttachParams
    body_model = models.AlertAttachment

    def build(self, params: BaseModel) -> KPlan:
        assert isinstance(params, AttachParams)
        body = models.AlertAttachment(
            alertId=tuple(a for a, _ in params.alerts), index=tuple(i for _, i in params.alerts)
        )
        units = WriteUnits(case_write=True, alerts=len(params.alerts))
        return KPlan(self.spec(), Target(case_id=params.case_id), body=body, units=units)

    def check(self, params: BaseModel, answer: Any, author: str | None) -> Any:
        assert isinstance(params, AttachParams)
        body = self.build(params).body
        assert isinstance(body, models.AlertAttachment)
        return models.check_attached(answer, params.case_id, body, author)


@kregister
class UpdateCase(KibanaTemplate):
    name = "cases.update"
    version = 1
    endpoint = KEndpoint.CASES_UPDATE
    key = KeyRole.CASES
    classes = frozenset({WriteClass.W2})
    estimate_ms = 100
    params_model = models.UpdatePatch
    body_model = models.UpdatePatch

    def build(self, params: BaseModel) -> KPlan:
        return KPlan(self.spec(), body=params, units=CASE_WRITE)

    def check(self, params: BaseModel, answer: Any, author: str | None) -> Any:
        assert isinstance(params, models.CasesPatch)
        return models.check_patched(answer, params, author)


@kregister
class CloseCase(KibanaTemplate):
    name = "cases.close"
    version = 1
    endpoint = KEndpoint.CASES_UPDATE
    key = KeyRole.CASES
    classes = frozenset({WriteClass.W3})
    estimate_ms = 100
    params_model = models.ClosePatch
    body_model = models.ClosePatch

    def build(self, params: BaseModel) -> KPlan:
        return KPlan(self.spec(), body=params, units=CASE_WRITE)

    def check(self, params: BaseModel, answer: Any, author: str | None) -> Any:
        assert isinstance(params, models.CasesPatch)
        return models.check_patched(answer, params, author)


@kregister
class SetAlertStatus(KibanaTemplate):
    """WA (Q-D5 builds its sender): alert status by ids, through Kibana's route."""

    name = "alerts.status"
    version = 1
    endpoint = KEndpoint.ALERTS_STATUS
    key = KeyRole.ALERTS
    classes = frozenset({WriteClass.WA})
    estimate_ms = 150
    params_model = models.AlertStatusChange
    body_model = models.AlertStatusChange

    def build(self, params: BaseModel) -> KPlan:
        assert isinstance(params, models.AlertStatusChange)
        units = WriteUnits(case_write=False, alerts=len(params.signal_ids))
        return KPlan(self.spec(), body=params, units=units)

    def check(self, params: BaseModel, answer: Any, author: str | None) -> Any:
        assert isinstance(params, models.AlertStatusChange)
        return models.check_alert_status(answer, params)


# --------------------------------------------------------------------------- the case team (AR8)
# Writes of class WC, sent as one of the six service users (D-158): the opening and the alerts
# only by the lead, the files only by the reporter, a comment by whoever owns the part. The
# validator holds each template to its users (``validator.TEAM_ONLY``).

TEAM = frozenset({WriteClass.WC})
TeamUser = models.TeamUser


@kregister
class TeamCreateCase(KibanaTemplate):
    name = "team.create"
    version = 1
    endpoint = KEndpoint.CASE_CREATE
    key = KeyRole.TEAM
    classes = TEAM
    estimate_ms = 100
    params_model = models.TeamCaseCreate
    body_model = models.TeamCaseCreate

    def build(self, params: BaseModel) -> KPlan:
        return KPlan(self.spec(), body=params, units=CASE_WRITE, as_user=models.TEAM_LEAD)

    def check(self, params: BaseModel, answer: Any, author: str | None) -> Any:
        assert isinstance(params, models.TeamCaseCreate)
        return models.check_team_created(answer, params)


class TeamCommentParams(Params):
    case_id: CaseId
    author: TeamUser
    comment: str = Field(min_length=1, max_length=models.MAX_TEXT)


@kregister
class TeamComment(KibanaTemplate):
    name = "team.comment"
    version = 1
    endpoint = KEndpoint.CASE_COMMENT
    key = KeyRole.TEAM
    classes = TEAM
    estimate_ms = 100
    params_model = TeamCommentParams
    body_model = models.UserComment

    def build(self, params: BaseModel) -> KPlan:
        assert isinstance(params, TeamCommentParams)
        body = models.UserComment(comment=params.comment)
        return KPlan(
            self.spec(), Target(case_id=params.case_id), body=body, units=CASE_WRITE,
            as_user=params.author,
        )  # fmt: skip

    def check(self, params: BaseModel, answer: Any, author: str | None) -> Any:
        assert isinstance(params, TeamCommentParams)
        return models.check_team_commented(answer, params.case_id, params.comment, params.author)


@kregister
class TeamEditCase(KibanaTemplate):
    """The lead corrects the case it opened: a new title and/or description, against the version
    the poster just read (D-236). Kibana answers the updated case."""

    name = "team.edit_case"
    version = 1
    endpoint = KEndpoint.CASES_UPDATE
    key = KeyRole.TEAM
    classes = TEAM
    estimate_ms = 100
    params_model = models.TeamCasePatch
    body_model = models.TeamCasePatch

    def build(self, params: BaseModel) -> KPlan:
        return KPlan(self.spec(), body=params, units=CASE_WRITE, as_user=models.TEAM_LEAD)

    def check(self, params: BaseModel, answer: Any, author: str | None) -> Any:
        assert isinstance(params, models.TeamCasePatch)
        return models.check_team_patched(answer, params)


class TeamCommentEditParams(Params):
    case_id: CaseId
    author: TeamUser
    comment_id: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{1,64}$")]
    version: Annotated[str, Field(pattern=r"^[A-Za-z0-9_=+/-]{1,200}$")]
    comment: str = Field(min_length=1, max_length=models.MAX_TEXT)


@kregister
class TeamEditComment(KibanaTemplate):
    """A user corrects the comment they wrote, against the comment's version (D-236). Kibana
    answers the whole case."""

    name = "team.edit_comment"
    version = 1
    endpoint = KEndpoint.CASE_COMMENT_EDIT
    key = KeyRole.TEAM
    classes = TEAM
    estimate_ms = 100
    params_model = TeamCommentEditParams
    body_model = models.TeamCommentPatch

    def _body(self, params: TeamCommentEditParams) -> models.TeamCommentPatch:
        return models.TeamCommentPatch(
            id=params.comment_id, version=params.version, comment=params.comment
        )

    def build(self, params: BaseModel) -> KPlan:
        assert isinstance(params, TeamCommentEditParams)
        return KPlan(
            self.spec(), Target(case_id=params.case_id), body=self._body(params),
            units=CASE_WRITE, as_user=params.author,
        )  # fmt: skip

    def check(self, params: BaseModel, answer: Any, author: str | None) -> Any:
        assert isinstance(params, TeamCommentEditParams)
        return models.check_team_comment_edited(
            answer, params.case_id, self._body(params), params.author
        )


class TeamAttachParams(Params):
    case_id: CaseId
    alerts: tuple[tuple[AlertId, str], ...] = Field(
        min_length=1, max_length=models.MAX_TEAM_ALERTS_PER_CALL
    )  # (alert id, its concrete index)
    expect_total: int = Field(ge=1, le=10_000)  # alerts the case holds once this call has landed


@kregister
class TeamAttachAlerts(KibanaTemplate):
    """The lead attaches the incident's alerts (an attach writes each alert's ``case_ids``)."""

    name = "team.attach_alerts"
    version = 1
    endpoint = KEndpoint.CASE_COMMENT
    key = KeyRole.TEAM
    classes = TEAM
    estimate_ms = 150
    params_model = TeamAttachParams
    body_model = models.TeamAlertAttachment

    def build(self, params: BaseModel) -> KPlan:
        assert isinstance(params, TeamAttachParams)
        body = models.TeamAlertAttachment(
            alertId=tuple(a for a, _ in params.alerts), index=tuple(i for _, i in params.alerts)
        )
        units = WriteUnits(case_write=True, alerts=len(params.alerts))
        return KPlan(
            self.spec(), Target(case_id=params.case_id), body=body, units=units,
            as_user=models.TEAM_LEAD,
        )  # fmt: skip

    def check(self, params: BaseModel, answer: Any, author: str | None) -> Any:
        assert isinstance(params, TeamAttachParams)
        body = self.build(params).body
        assert isinstance(body, models.AlertAttachment)
        return models.check_team_attached(answer, params.case_id, body, params.expect_total)


@kregister
class TeamAlertTags(KibanaTemplate):
    """The lead tags the incident's alerts with its ID (``workflow_tags``); a tag is added to a
    set, so sending it twice changes nothing."""

    name = "team.alert_tags"
    version = 1
    endpoint = KEndpoint.ALERTS_TAGS
    key = KeyRole.TEAM
    classes = TEAM
    estimate_ms = 150
    params_model = models.AlertTagChange
    body_model = models.AlertTagChange

    def build(self, params: BaseModel) -> KPlan:
        assert isinstance(params, models.AlertTagChange)
        units = WriteUnits(case_write=False, alerts=len(params.ids))
        return KPlan(self.spec(), body=params, units=units, as_user=models.TEAM_LEAD)

    def check(self, params: BaseModel, answer: Any, author: str | None) -> Any:
        assert isinstance(params, models.AlertTagChange)
        return models.check_alert_tags(answer, params)


class TeamFileParams(Params):
    case_id: CaseId
    file: upload.FileUpload


@kregister
class TeamAttachFile(KibanaTemplate):
    """The reporter uploads a file to the case's Files tab (a file is an attachment: W1's rules)."""

    name = "team.file"
    version = 1
    endpoint = KEndpoint.CASE_FILES
    key = KeyRole.TEAM
    classes = TEAM
    estimate_ms = 300
    params_model = TeamFileParams
    body_model = upload.FileUpload

    def build(self, params: BaseModel) -> KPlan:
        assert isinstance(params, TeamFileParams)
        return KPlan(
            self.spec(), Target(case_id=params.case_id), body=params.file, units=CASE_WRITE,
            as_user="argus-reporter", raw_body=upload.encode(params.file),
        )  # fmt: skip

    def check(self, params: BaseModel, answer: Any, author: str | None) -> Any:
        assert isinstance(params, TeamFileParams)
        return models.check_team_file(answer, params.case_id, params.file.full_name)

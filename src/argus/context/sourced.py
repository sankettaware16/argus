"""Parameters of a request that reads one family of logs of a role (P4-D1 review F3).

A site may have several families of one role (two proxies, two web servers). The evidence
templates read the family the *rule* reads (``site.family_of_rule``), so the parameters carry
its name. The name is written only where it is a choice, that is, when the site has two or more
families of the role (``site.source_param``): otherwise ``source`` is None and left out of the
parameters' JSON, so a one-family site's requests, their content addresses (``task_key``) and
the params stored with their evidence are exactly what they always were.
"""

from __future__ import annotations

from typing import Any, ClassVar

from pydantic import SerializerFunctionWrapHandler, field_validator, model_serializer

from argus.gateway.templates import Params
from argus.site import Role, active


class SourcedParams(Params):
    ROLE: ClassVar[Role]

    source: str | None = None
    """The family (its name) the request reads; None: the first family of the role."""

    @field_validator("source")
    @classmethod
    def _a_family_of_the_role(cls, value: str | None) -> str | None:
        if value is not None:
            family = active().family(value)
            if family is None or family.role is not cls.ROLE:
                raise ValueError(f"{value[:40]!r} is not a {cls.ROLE.value} family of this site")
        return value

    @model_serializer(mode="wrap")
    def _without_the_default(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        data: dict[str, Any] = handler(self)
        if data.get("source") is None:
            data.pop("source", None)
        return data

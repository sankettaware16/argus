"""``config/grouping.yaml``: per-rule group-key fields where a rule declares none (plan §7.1).

The key fields of an alert come from, in order: the rule's declared
``alert_suppression.group_by``, a threshold rule's ``threshold.field``, this file, and finally
``[source.ip, destination.ip]``. R6 adds its bucket settings here.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError

from argus.config.errors import ConfigError
from argus.config.sources import read_yaml_file

DEFAULT_GROUPING_PATH = Path("config/grouping.yaml")
GENERIC_KEY_FIELDS = ("source.ip", "destination.ip")
MAX_KEY_FIELDS = 16

FieldName = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_@][A-Za-z0-9_@.\-]{0,255}$")]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class RuleGrouping(_Strict):
    key_fields: tuple[FieldName, ...] = Field(min_length=1, max_length=MAX_KEY_FIELDS)


class GroupingConfig(_Strict):
    version: int = Field(default=1, ge=1, le=1)
    rules: dict[str, RuleGrouping] = Field(default_factory=dict)


def load_grouping(path: Path = DEFAULT_GROUPING_PATH) -> GroupingConfig:
    """Read and validate the grouping file; a missing file means no per-rule settings."""
    if not path.exists():
        return GroupingConfig()
    data, _ = read_yaml_file(path)
    try:
        return GroupingConfig.model_validate(data)
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(str(part) for part in error['loc']) or '(top level)'}: {error['msg']}"
            for error in exc.errors(include_input=False)
        )
        raise ConfigError(f"invalid grouping file {path}: {problems}") from None

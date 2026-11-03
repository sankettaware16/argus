"""Live Kibana charts inside a case comment: the ``!{lens{...}}`` text the cases' Markdown plugin
turns into a Lens visualisation, built and checked here.

Kibana 8.19's plugin matches the prefix ``!{lens``, then scans **brace depth** over the rest of
the paragraph (every ``{`` and ``}``, whatever the quotes), ``JSON.parse``\\s what it collected
and takes one more ``}``; a block that is not ``}``-balanced or not JSON fails to render.
:func:`scan` does exactly that. A chart is **self-contained** (an ad hoc data view over the
alerts index) and searches **only the case's alerts**, by a filter on the incident ID tag. Every
string in a block is plain (:data:`SAFE`), so the brace scan is exact and the guardian can let a
checked block through."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Final

from argus.incident.discover import stamp

PREFIX: Final = "!{lens"
TAG_FIELD: Final = "kibana.alert.workflow_tags"
RULE_FIELD: Final = "kibana.alert.rule.name"
TIME_FIELD: Final = "@timestamp"
ALERTS_PREFIX: Final = ".alerts-security.alerts-"
DATA_VIEW: Final = "argus-incident-alerts"  # the ad hoc data view's id in every block
PAD: Final = timedelta(hours=1)  # the range: first alert minus this to last alert plus this
SAFE: Final = re.compile(r"[A-Za-z0-9 _@.:+/()$-]{0,200}")
SPACE: Final = re.compile(r"[A-Za-z0-9_-]{1,100}")  # a Kibana space's id
_INDEX = re.compile(r"\.alerts-security\.alerts-[A-Za-z0-9_-]{1,100}")
_STAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z")
_ID = re.compile(r"[A-Za-z0-9_-]{1,40}")
TYPES: Final = ("lnsXY", "lnsDatatable", "lnsPie")
IP_FIELDS: Final = frozenset({"source.ip", "destination.ip", "client.ip", "host.ip"})


@dataclass(frozen=True)
class Scope:
    """What a case's charts are over: the space's alerts index, the incident ID, and the time of
    its first and last alert."""

    space: str
    incident_id: str
    first: datetime
    last: datetime

    @property
    def index(self) -> str:
        return f"{ALERTS_PREFIX}{self.space}"

    @property
    def time_range(self) -> dict[str, str]:
        return {
            "from": stamp(self.first - PAD),
            "to": stamp(self.last + PAD),
            "mode": "absolute",
        }


def _filters(scope: Scope) -> list[dict[str, Any]]:
    """The one filter every chart carries: this incident's tag."""
    return [
        {
            "meta": {
                "alias": None,
                "disabled": False,
                "negate": False,
                "key": TAG_FIELD,
                "field": TAG_FIELD,
                "type": "phrase",
                "params": {"query": scope.incident_id},
                "index": DATA_VIEW,
            },
            "query": {"match_phrase": {TAG_FIELD: scope.incident_id}},
            "$state": {"store": "appState"},
        }
    ]


def _data_view(scope: Scope) -> dict[str, Any]:
    return {
        DATA_VIEW: {
            "id": DATA_VIEW,
            "title": scope.index,
            "timeFieldName": TIME_FIELD,
            "sourceFilters": [],
            "fieldFormats": {},
            "runtimeFieldMap": {},
            "fieldAttrs": {},
            "allowNoIndex": False,
            "name": "ARGUS incident alerts",
        }
    }


def _count() -> dict[str, Any]:
    return {
        "label": "Count of records",
        "dataType": "number",
        "operationType": "count",
        "isBucketed": False,
        "scale": "ratio",
        "sourceField": "___records___",
        "params": {"emptyAsNull": True},
    }


def _over_time() -> dict[str, Any]:
    return {
        "label": TIME_FIELD,
        "dataType": "date",
        "operationType": "date_histogram",
        "sourceField": TIME_FIELD,
        "isBucketed": True,
        "scale": "interval",
        "params": {"interval": "auto", "includeEmptyRows": True, "dropPartials": False},
    }


def _terms(field: str, size: int, by: str) -> dict[str, Any]:
    return {
        "label": f"Top {size} values of {field}",
        "dataType": "ip" if field in IP_FIELDS else "string",
        "operationType": "terms",
        "scale": "ordinal",
        "sourceField": field,
        "isBucketed": True,
        "params": {
            "size": size,
            "orderBy": {"type": "column", "columnId": by},
            "orderDirection": "desc",
            "otherBucket": True,
            "missingBucket": False,
            "parentFormat": {"id": "terms"},
            "include": [],
            "exclude": [],
            "includeIsRegex": False,
            "excludeIsRegex": False,
        },
    }


def _attributes(
    scope: Scope,
    title: str,
    kind: str,
    columns: Mapping[str, Mapping[str, Any]],
    order: Sequence[str],
    visualization: Mapping[str, Any],
) -> dict[str, Any]:
    """A Lens saved object's attributes with one layer, no saved references."""
    return {
        "title": title,
        "description": "",
        "type": "lens",
        "visualizationType": kind,
        "references": [],
        "state": {
            "visualization": dict(visualization),
            "query": {"query": "", "language": "kuery"},
            "filters": _filters(scope),
            "datasourceStates": {
                "formBased": {
                    "layers": {
                        "layer1": {
                            "columns": {k: dict(v) for k, v in columns.items()},
                            "columnOrder": list(order),
                            "incompleteColumns": {},
                            "sampling": 1,
                        }
                    }
                }
            },
            "internalReferences": [
                {
                    "type": "index-pattern",
                    "id": DATA_VIEW,
                    "name": "indexpattern-datasource-layer-layer1",
                }
            ],
            "adHocDataViews": _data_view(scope),
        },
    }


def _xy(layer: Mapping[str, Any], series: str) -> dict[str, Any]:
    return {
        "legend": {"isVisible": True, "position": "right"},
        "valueLabels": "hide",
        "fittingFunction": "None",
        "axisTitlesVisibilitySettings": {"x": False, "yLeft": False, "yRight": False},
        "tickLabelsVisibilitySettings": {"x": True, "yLeft": True, "yRight": True},
        "labelsOrientation": {"x": 0, "yLeft": 0, "yRight": 0},
        "gridlinesVisibilitySettings": {"x": True, "yLeft": True, "yRight": True},
        "preferredSeriesType": series,
        "layers": [dict(layer)],
    }


def alerts_over_time(scope: Scope) -> dict[str, Any]:
    """Alerts over time, stacked by rule: Security's own "alerts over time" (``lnsXY``,
    ``bar_stacked``: a date histogram on ``@timestamp``, the count of records, a terms split on
    the rule's name)."""
    layer = {
        "layerId": "layer1",
        "layerType": "data",
        "seriesType": "bar_stacked",
        "accessors": ["c-count"],
        "xAccessor": "c-time",
        "splitAccessor": "c-rule",
        "position": "top",
        "showGridlines": False,
    }
    return _attributes(
        scope,
        "Alerts over time by rule",
        "lnsXY",
        {"c-time": _over_time(), "c-count": _count(), "c-rule": _terms(RULE_FIELD, 10, "c-count")},
        ["c-rule", "c-time", "c-count"],
        _xy(layer, "bar_stacked"),
    )


def top_values(scope: Scope, title: str, field: str, size: int = 10) -> dict[str, Any]:
    """The commonest values of ``field`` among the case's alerts, as horizontal bars."""
    layer = {
        "layerId": "layer1",
        "layerType": "data",
        "seriesType": "bar_horizontal",
        "accessors": ["c-count"],
        "xAccessor": "c-top",
        "position": "top",
        "showGridlines": False,
    }
    visualization = _xy(layer, "bar_horizontal")
    visualization["legend"] = {"isVisible": False, "position": "right"}
    return _attributes(
        scope,
        title,
        "lnsXY",
        {"c-top": _terms(field, size, "c-count"), "c-count": _count()},
        ["c-top", "c-count"],
        visualization,
    )


def rules_table(scope: Scope, size: int = 20) -> dict[str, Any]:
    """The rules that raised the case's alerts, with their counts, as a table."""
    visualization = {
        "layerId": "layer1",
        "layerType": "data",
        "columns": [
            {"columnId": "c-rule", "isTransposed": False},
            {"columnId": "c-count", "isTransposed": False},
        ],
    }
    return _attributes(
        scope,
        "Rules that raised the alerts",
        "lnsDatatable",
        {"c-rule": _terms(RULE_FIELD, size, "c-count"), "c-count": _count()},
        ["c-rule", "c-count"],
        visualization,
    )


def block(scope: Scope, attributes: Mapping[str, Any]) -> str:
    """The text of one embedded chart: ``!{lens{"timeRange":...,"attributes":...}}``, one line."""
    body = json.dumps(
        {"timeRange": scope.time_range, "attributes": dict(attributes)},
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )
    return f"{PREFIX}{body}}}"


def scan(text: str) -> list[str]:
    """The JSON of every ``!{lens`` block in ``text``, found as Kibana's parser finds them: from
    the prefix, count ``{`` and ``}`` (quotes do not matter) until a ``}`` closes more than was
    opened; what was collected is the configuration, and that ``}`` ends the block. Raises
    ``ValueError`` for a block that never closes. The result is not parsed."""
    found: list[str] = []
    start = text.find(PREFIX)
    while start >= 0:
        depth, i, n = 0, start + len(PREFIX), len(text)
        collected: list[str] = []
        while i < n:
            ch = text[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == -1:
                    break
            collected.append(ch)
            i += 1
        else:
            raise ValueError("a lens block is not closed")
        found.append("".join(collected))
        start = text.find(PREFIX, i + 1)
    return found


def _strings(node: Any, problems: list[str]) -> None:
    if isinstance(node, str):
        if not SAFE.fullmatch(node):
            problems.append("a lens block holds a string with a character it may not")
    elif isinstance(node, dict):
        for key, value in node.items():
            _strings(key, problems)
            _strings(value, problems)
    elif isinstance(node, list):
        for item in node:
            _strings(item, problems)
    elif not (node is None or isinstance(node, bool | int | float)):
        problems.append("a lens block holds something that is not JSON")


def problems(line: str) -> list[str]:
    """What is wrong with ``line`` as an embedded chart (empty: it is one of ARGUS's own kind).
    The line must be exactly one block that parses; hold a plain string everywhere; name one
    ad hoc data view over a ``.alerts-security.alerts-*`` index and no other; and filter on the
    incident's tag. Values from a log or a person cannot get in: nothing but plain strings do."""
    try:
        parts = scan(line)
    except ValueError as exc:
        return [str(exc)]
    if len(parts) != 1 or len(PREFIX) + len(parts[0]) + 1 != len(line):
        return ["a lens block must be alone on its line"]
    try:
        config = json.loads(parts[0])
    except ValueError:
        return ["a lens block is not JSON"]
    out: list[str] = []
    _strings(config, out)
    if out:
        return list(dict.fromkeys(out))
    if not isinstance(config, dict) or set(config) != {"timeRange", "attributes"}:
        return ["a lens block holds a time range and attributes, nothing else"]
    out += _time(config["timeRange"])
    out += _attributes_problems(config["attributes"])
    return out


def _time(value: Any) -> list[str]:
    if (
        not isinstance(value, dict)
        or set(value) != {"from", "to", "mode"}
        or value["mode"] != "absolute"
        or not all(isinstance(value[k], str) and _STAMP.fullmatch(value[k]) for k in ("from", "to"))
    ):
        return ["a lens block's time range is not an absolute range"]
    return []


def _attributes_problems(attrs: Any) -> list[str]:
    if not isinstance(attrs, dict) or attrs.get("visualizationType") not in TYPES:
        return ["a lens block is not one of the chart kinds ARGUS draws"]
    state = attrs.get("state")
    if attrs.get("references") != [] or not isinstance(state, dict):
        return ["a lens block must be self-contained (no saved references)"]
    views = state.get("adHocDataViews")
    if not isinstance(views, dict) or len(views) != 1:
        return ["a lens block names exactly one ad hoc data view"]
    (name, view), *_ = views.items()
    if (
        not isinstance(view, dict)
        or not _ID.fullmatch(name)
        or view.get("id") != name
        or not _INDEX.fullmatch(str(view.get("title")))
    ):
        return ["a lens block may read only a space's alerts index"]
    tags = [
        f
        for f in state.get("filters") or []
        if isinstance(f, dict) and (f.get("meta") or {}).get("key") == TAG_FIELD
    ]
    if len(tags) != 1 or (tags[0].get("meta") or {}).get("negate") is not False:
        return ["a lens block must filter on the incident's tag"]
    if (tags[0].get("meta") or {}).get("disabled") is not False:
        return ["a lens block's incident filter is switched off"]
    return []

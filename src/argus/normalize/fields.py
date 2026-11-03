"""Reading fields from an alert's ``_source`` the way Elasticsearch indexes them.

Kibana writes alert documents in mixed shapes: the ``kibana.*`` fields are dotted keys
(``"kibana.alert.uuid"``), source-event fields of query alerts are nested objects
(``{"source": {"ip": ...}}``), ES|QL rows are dotted again, and any mixture
(``{"source.geo": {"country_name": ...}}``) is legal. Elasticsearch treats every split of a
dotted path alike, traverses arrays of objects and flattens arrays of values; a field is the
union of everything found. :func:`values` does the same, so every adapter reads a field in one
way whatever shape the document has.
"""

from __future__ import annotations

from collections.abc import Mapping
from functools import lru_cache
from typing import Any

KEYWORD_SUFFIX = ".keyword"
_END = object()


@lru_cache(maxsize=1024)
def _segments(path: str) -> tuple[tuple[str, ...], tuple[tuple[str, ...], ...]]:
    """The path's parts and, for each start part, the dotted keys it can begin with."""
    parts = tuple(path.split("."))
    keys = tuple(
        tuple(".".join(parts[start:end]) for end in range(start + 1, len(parts) + 1))
        for start in range(len(parts))
    )
    return parts, keys


def _flatten(value: Any, out: list[Any]) -> None:
    """Append the leaf values of ``value``: nested arrays flattened, nulls dropped."""
    if not isinstance(value, list):
        if value is not None:
            out.append(value)
        return
    stack: list[Any] = [iter(value)]
    while stack:
        item = next(stack[-1], _END)
        if item is _END:
            stack.pop()
        elif isinstance(item, list):
            stack.append(iter(item))
        elif item is not None:
            out.append(item)


def _collect(doc: Mapping[str, Any], path: str) -> list[Any]:
    parts, keys = _segments(path)
    out: list[Any] = []
    # Work items (value, next part); iterative, so neither deep arrays nor long paths recurse.
    stack: list[tuple[Any, int]] = [(doc, 0)]
    while stack:
        node, start = stack.pop()
        if start == len(parts):
            _flatten(node, out)
        elif isinstance(node, list):
            stack.extend((item, start) for item in reversed(node))
        elif isinstance(node, dict):
            # Reversed, so the shortest key (the nested form) is visited first.
            for offset in range(len(keys[start]) - 1, -1, -1):
                key = keys[start][offset]
                if key in node:
                    stack.append((node[key], start + offset + 1))
    return out


def values(doc: Mapping[str, Any], path: str) -> list[Any]:
    """Every value of the field ``path`` (nulls dropped, arrays flattened, in document order).

    A ``.keyword`` multi-field (``url.domain.keyword``) is not a ``_source`` path: when nothing
    is found under it, its parent field is read instead.
    """
    found = _collect(doc, path)
    if not found and path.endswith(KEYWORD_SUFFIX) and len(path) > len(KEYWORD_SUFFIX):
        found = _collect(doc, path[: -len(KEYWORD_SUFFIX)])
    return found


def field_kind_name(path: str) -> str:
    """The field name without a ``.keyword`` multi-field suffix."""
    if path.endswith(KEYWORD_SUFFIX) and len(path) > len(KEYWORD_SUFFIX):
        return path[: -len(KEYWORD_SUFFIX)]
    return path


def leaf_values(doc: Mapping[str, Any]) -> dict[str, list[Any]]:
    """Every field of the document with its values, keyed by full dotted path: the same for any
    nesting of the same fields (arrays of objects traversed, nulls and empty containers dropped,
    as Elasticsearch indexes them)."""
    out: dict[str, list[Any]] = {}
    stack: list[tuple[str, Any]] = [("", doc)]
    while stack:
        path, node = stack.pop()
        if isinstance(node, dict):
            for key in reversed(list(node)):
                stack.append((f"{path}.{key}" if path else key, node[key]))
        elif isinstance(node, list):
            stack.extend((path, item) for item in reversed(node))
        elif node is not None:
            out.setdefault(path, []).append(node)
    return out

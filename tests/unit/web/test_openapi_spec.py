"""Q-A1: the committed ``/api/v1`` contract (docs/api/openapi-v1.json) is exactly what the code
builds, and the contract keeps its own rules: every operation named, every error an
``ErrorOut``, every change behind the session and its CSRF token, no sign-in in the API."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from argus.web import openapi

pytestmark = pytest.mark.unit
ROOT = Path(__file__).resolve().parents[3]
SPEC = ROOT / "docs" / "api" / "openapi-v1.json"


def exporter() -> Any:
    path = ROOT / "scripts" / "export_openapi.py"
    spec = importlib.util.spec_from_file_location("export_openapi", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def built() -> dict[str, Any]:
    import json

    text: str = exporter().current()
    found: dict[str, Any] = json.loads(text)
    return found


def test_the_committed_spec_is_what_the_code_builds() -> None:
    assert SPEC.read_text(encoding="utf-8") == exporter().current(), (
        "docs/api/openapi-v1.json is not current: run uv run python scripts/export_openapi.py"
    )


def test_the_export_script_checks() -> None:
    script = str(ROOT / "scripts" / "export_openapi.py")
    done = subprocess.run(  # noqa: S603 - our own script
        [sys.executable, script, "--check"],
        capture_output=True,
        text=True,
        check=False,
        cwd=ROOT,
    )
    assert done.returncode == 0, done.stderr


def test_every_operation_is_named_and_documented(built: dict[str, Any]) -> None:
    ids = []
    for path, operations in built["paths"].items():
        assert path.startswith("/api/v1/"), path
        for method, op in operations.items():
            ids.append(op["operationId"])
            assert op["operationId"][0].islower()
            assert "_" not in op["operationId"]
            assert op.get("summary"), (method, path)
            assert op.get("description"), (method, path)
            assert op.get("tags"), (method, path)
    # P4-F added confirmCase and dismissCase; UI v2 (spec §2.3) its 13 additions; E5 getToday
    assert len(ids) == len(set(ids)) == 81


def test_every_schema_has_its_own_plain_name(built: dict[str, Any]) -> None:
    """Two models of one name made FastAPI name both by their module path, renaming a published
    schema (``ConfirmIn``, the body of ``/proposals/confirm``) in the spec and the client."""
    names = list(built["components"]["schemas"])
    assert [n for n in names if "__" in n or n.startswith("argus")] == []
    confirm = built["paths"]["/api/v1/proposals/confirm"]["post"]["requestBody"]
    assert confirm["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/ConfirmIn"
    }
    case = built["paths"]["/api/v1/cases/{case_id}/confirm"]["post"]["requestBody"]
    assert case["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/CaseConfirmIn"
    }


def test_every_error_is_error_out(built: dict[str, Any]) -> None:
    error = {"$ref": "#/components/schemas/ErrorOut"}
    for path, operations in built["paths"].items():
        for method, op in operations.items():
            for status, answer in op["responses"].items():
                if status.startswith(("4", "5")):
                    schema = answer["content"]["application/json"]["schema"]
                    assert schema == error, (method, path, status)
            assert {"401", "403"} <= set(op["responses"]), (method, path)
    out = built["components"]["schemas"]["ErrorOut"]
    assert out["required"] == ["detail", "code"]
    assert out["additionalProperties"] is False
    assert "HTTPValidationError" not in built["components"]["schemas"]


def test_changes_need_the_session_and_its_csrf_token(built: dict[str, Any]) -> None:
    schemes = built["components"]["securitySchemes"]
    assert schemes["session"] == {
        "type": "apiKey", "in": "cookie", "name": "argus_session",
        "description": schemes["session"]["description"]}  # fmt: skip
    assert (schemes["csrf"]["in"], schemes["csrf"]["name"]) == ("header", "X-CSRF-Token")
    for operations in built["paths"].values():
        for method, op in operations.items():
            want = [{"session": [], "csrf": []}] if method in openapi.CHANGES else [{"session": []}]
            assert op["security"] == want


def test_no_password_passes_through_the_api(built: dict[str, Any]) -> None:
    assert not [p for p in built["paths"] if "login" in p or "signin" in p or "stepup" in p]
    text = repr(built["components"]["schemas"]).lower()
    assert "password" not in text


def test_bodies_refuse_unknown_fields(built: dict[str, Any]) -> None:
    for name, schema in built["components"]["schemas"].items():
        if schema.get("type") == "object" and "properties" in schema:
            assert schema.get("additionalProperties") is False, name


def test_the_classic_spec_is_unchanged() -> None:
    from sqlalchemy.ext.asyncio import create_async_engine

    from argus.web.app import create_app

    engine = create_async_engine("postgresql+psycopg://x@127.0.0.1:1/x")  # never connected
    app = create_app(engine)
    classic = app.openapi()
    assert not [p for p in classic["paths"] if p.startswith("/api/v1")]
    assert (classic["info"]["title"], classic["info"]["version"]) == ("ARGUS Inbox", "0.1.0")


def test_parameters_are_left_out_never_null(built: dict[str, Any]) -> None:
    """A query string cannot say null: optional parameters have no null branch (Schemathesis
    would otherwise send a null branch's mutations, which serialize to valid strings)."""
    for operations in built["paths"].values():
        for op in operations.values():
            for parameter in op.get("parameters", []):
                assert "null" not in repr(parameter["schema"]), parameter
    assert openapi._without_null({"anyOf": [{"type": "string"}, {"type": "null"}],
                                  "title": "T"}) == {"type": "string", "title": "T"}  # fmt: skip
    both = {"anyOf": [{"type": "string"}, {"const": ""}, {"type": "null"}]}
    assert openapi._without_null(both) == {"anyOf": [{"type": "string"}, {"const": ""}]}
    plain = {"type": "integer"}
    assert openapi._without_null(plain) is plain

"""A PostgreSQL password verifier (D-029: what `argus db bootstrap` sends) never reaches logs."""

from __future__ import annotations

import pytest

from argus.observability.redaction import MASK, redact_text

# Synthetic: the shape of a SCRAM-SHA-256 verifier, not one for any real password.
VERIFIER = (
    "SCRAM-SHA-256$4096:c2FsdHNhbHRzYWx0c2E=$"
    "c3RvcmVka2V5c3RvcmVka2V5c3RvcmVka2V5c3Q+/0=:c2VydmVya2V5c2VydmVya2V5c2VydmVya2V5c2U="
)


@pytest.mark.parametrize(
    "template",
    [
        "{v}",
        "ALTER ROLE \"argus_app\" WITH LOGIN PASSWORD '{v}'",
        "[SQL: CREATE ROLE argus_app WITH LOGIN PASSWORD '{v}']",
        'rolpassword="{v}"',
    ],
)
def test_scram_verifiers_are_masked(template: str) -> None:
    out = redact_text(template.format(v=VERIFIER))
    assert "c3RvcmVk" not in out
    assert "c2VydmVy" not in out
    assert "SCRAM-SHA-256$" + MASK in out or MASK in out


def test_mentions_of_the_mechanism_stay_readable() -> None:
    text = "password_encryption = scram-sha-256; SCRAM-SHA-256 is the default since PostgreSQL 14"
    assert redact_text(text) == text

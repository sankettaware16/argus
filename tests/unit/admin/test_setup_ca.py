"""A CA certificate for the first-time setup (D-330): pasted, uploaded, or a file on this server
(an Elastic stack on the same machine); refused with the reason, never with the file's content."""

from __future__ import annotations

from pathlib import Path

import pytest

from argus.admin import jobs

pytestmark = pytest.mark.unit
PEM = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
NOT_A_CERTIFICATE = "-----BEGIN " + "PRIVATE KEY-----\nsecret\n"  # split: no key block in git


def test_a_ca_file_on_this_server_is_read(tmp_path: Path) -> None:
    ca = tmp_path / "ca.crt"
    ca.write_text(PEM)
    assert jobs.ca_from_path(str(ca), "siem") == PEM


@pytest.mark.parametrize(
    ("make", "why"),
    [
        (lambda p: "relative/ca.crt", "whole path"),
        (lambda p: str(p / "missing.crt"), "not a certificate file"),
        (lambda p: str(p), "not a certificate file"),  # a directory
        (lambda p: (p / "big.crt").write_text("x" * 70_000) and str(p / "big.crt"),
         "not a certificate file"),
        (lambda p: (p / "key.pem").write_text(NOT_A_CERTIFICATE)
         and str(p / "key.pem"), "holds no PEM certificate"),
    ],
)  # fmt: skip
def test_anything_else_is_refused_without_its_content(tmp_path: Path, make: object,
                                                       why: str) -> None:  # fmt: skip
    with pytest.raises(jobs.JobError, match=why) as caught:
        jobs.ca_from_path(make(tmp_path), "siem")  # type: ignore[operator]
    assert "secret" not in str(caught.value)


def test_the_setup_web_may_name_these_answers() -> None:
    assert {"siem.ca_pem", "kibana.ca_pem", "siem.ca_path", "kibana.ca_path"} <= jobs.ANSWERS
    assert "siem.ca_file" not in jobs.ANSWERS  # a file for init is argus-admin's to name

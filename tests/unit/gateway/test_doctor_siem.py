"""``argus doctor``'s the SIEM check: the pinned CA and the key's presence, no request sent."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import SecretStr

from argus.config.settings import Settings, SiemSettings
from argus.doctor import siem_check

pytestmark = pytest.mark.unit

CA = Path(__file__).parent / "data" / "test-ca.crt"


async def check(ca_file: Path, key: str | None) -> dict[str, tuple[bool, str]]:
    siem = SiemSettings(ca_file=ca_file, api_key=None if key is None else SecretStr(key))
    results = await siem_check(Settings.model_construct(siem=siem))
    return {r.name: (r.ok, r.detail) for r in results}


async def test_not_set_up_yet_passes(tmp_path: Path) -> None:
    """No key and no CA is a checkout where the SIEM is not set up yet, not a failure."""
    out = await check(tmp_path / "missing.crt", None)
    assert out["the SIEM CA"] == (True, "not pinned yet (D-033)")
    assert out["the SIEM key"][0]


async def test_a_key_without_its_ca_fails(tmp_path: Path) -> None:
    out = await check(tmp_path / "missing.crt", "k3y")
    assert not out["the SIEM CA"][0]
    assert "does not exist" in out["the SIEM CA"][1]


async def test_a_ca_that_is_not_a_certificate_fails_even_without_a_key(tmp_path: Path) -> None:
    junk = tmp_path / "junk.crt"
    junk.write_text("not a certificate")
    assert not (await check(junk, None))["the SIEM CA"][0]


async def test_a_pinned_ca_is_summarised() -> None:
    out = await check(CA, "k3y")
    assert out["the SIEM CA"][0] or "renew the pin" in out["the SIEM CA"][1]
    assert out["the SIEM key"] == (True, "configured (`argus siem selftest` checks it)")

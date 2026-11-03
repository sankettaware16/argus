"""The privacy view without an imported asset map (P4-D3): an empty map stands in only while
nothing could leave the machine; with a model's or an outside service's key it fails closed."""

from __future__ import annotations

from pathlib import Path

import pytest

from argus.assets.store import NoAssetMapError, map_for_privacy

pytestmark = pytest.mark.unit


def test_no_key_and_no_map_is_an_empty_map(tmp_path: Path) -> None:
    found = map_for_privacy(tmp_path / "none.yaml", model_keys=False, outside_keys=False)
    assert found.entries == ()


@pytest.mark.parametrize(("model", "outside"), [(True, False), (False, True), (True, True)])
def test_a_key_without_a_map_fails_closed(tmp_path: Path, model: bool, outside: bool) -> None:
    with pytest.raises(NoAssetMapError, match="argus assets import"):
        map_for_privacy(tmp_path / "none.yaml", model_keys=model, outside_keys=outside)

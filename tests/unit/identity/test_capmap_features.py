"""The capability map over Kibana's feature ids (P4-D1): the ids are the site's, not constants."""

from __future__ import annotations

import pytest

from argus import site
from argus.identity import capmap
from argus.identity.capmap import Targets, needs_for, request_body
from argus.site import KibanaFeatures, SiteSettings, feature_ids

pytestmark = pytest.mark.unit


def test_the_defaults_are_the_ids_the_map_was_written_for() -> None:
    t = Targets()
    assert (t.security_feature, t.cases_feature) == ("siemV2", "securitySolutionCasesV3")
    assert t.needs == capmap.NEEDS == needs_for("siemV2", "securitySolutionCasesV3")
    assert (t.space, t.log_patterns) == (
        "acme-soc",
        ("acme-logs-*",),
    )  # the active (ACME) site


def test_another_kibanas_ids_change_the_actions_asked_about() -> None:
    t = Targets(security_feature="siemV3", cases_feature="securitySolutionCasesV4")
    asked = request_body(t)["application"][0]["privileges"]
    assert "ui:siemV3/show" in asked
    assert "ui:siemV2/show" not in asked
    assert "ui:securitySolutionCasesV4/case_reopen" in asked
    assert not any("CasesV3" in a for a in asked)
    # the server-side actions do not carry a feature id
    assert "cases:securitySolution/createCase" in asked


def test_the_targets_take_the_sites_feature_ids() -> None:
    discovered = feature_ids([{"id": "siemV3"}, {"id": "securitySolutionCasesV4"}])
    assert discovered == KibanaFeatures(security="siemV3", cases="securitySolutionCasesV4")
    with site.using(SiteSettings(space="soc", kibana_features=discovered)):
        t = Targets()
        assert (t.space, t.security_feature, t.cases_feature) == (
            "soc",
            "siemV3",
            "securitySolutionCasesV4",
        )
        assert t.log_patterns == ()  # no log family configured: no logs are asked about


def test_a_map_for_other_ids_reads_the_answer_it_asked_for() -> None:
    t = Targets(
        space="soc", log_patterns=("logs-*",), security_feature="siemV3", cases_feature="c4"
    )
    body = request_body(t)
    held = {
        "cluster": dict.fromkeys(body["cluster"], False),
        "index": {
            entry["names"][0]: dict.fromkeys(entry["privileges"], True) for entry in body["index"]
        },
        "application": {
            capmap.KIBANA_APP: {
                "space:soc": dict.fromkeys(body["application"][0]["privileges"], True)
            },
            capmap.ARGUS_APP: {"*": dict.fromkeys(body["application"][1]["privileges"], False)},
        },
    }
    privileges = capmap.read(held, t)
    assert {c.value for c in privileges.capabilities} >= {"view", "manage_cases", "reopen"}
    # the same answer, read against the default ids, lacks the actions it was never asked about
    with pytest.raises(capmap.IncompleteAnswerError):
        capmap.read(held, Targets(space="soc", log_patterns=("logs-*",)))

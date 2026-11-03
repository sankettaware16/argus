"""The responder's web facts from the records a case stores (D-240, D-245): a 2xx answer in a stored
``web.followups`` answer to a path the case is about (an alert of the case attacked it, or a stored
path check asked about it), or in an alert that records its own path and status, makes the family
of its path, unless a stored path-outcome check decided the path was the catch-all page or
refused."""

from __future__ import annotations

from typing import Any

import pytest

from argus.responder import catalogue as cat
from argus.responder import facts as fct

pytestmark = pytest.mark.unit
C = cat.load()


def keys(facts: fct.Facts) -> list[str]:
    return [f.key for f in fct.match(C, facts)]


def followup(path: str, status: int = 200) -> dict[str, Any]:
    hit = {"url": {"path": path}, "http": {"response": {"status_code": status}}}
    return {"total": 1, "rows": [{"_source": hit}], "aggregations": None}


def alert_for(*paths: str) -> dict[str, Any]:
    """An alert that names the paths it attacked (and records no answer of its own)."""
    return {"url.path": list(paths)}


def test_a_stored_followup_with_a_2xx_answer_makes_the_family_of_its_path() -> None:
    """Case 1: the path-outcome check is off (it needs a site), but the client's successful
    answers after the alert are stored: a config file the alerts attacked and answered 2xx is a
    served file."""
    answered = fct.answered_by_followups(followup("/.env"))
    assert answered == ["/.env"]
    facts = fct.from_parts([], [alert_for("/.env")], [], answered)
    assert facts.present == {"sensitive_file_served"}
    assert keys(facts) == ["exposed_file"]
    assert fct.required_paths(facts, C.family("exposed_file")) == {"/.env"}
    attack = fct.answered_by_followups(followup("/wp-admin/x"))
    assert keys(fct.from_parts([], [alert_for("/wp-admin/x")], [], attack)) == ["web_attack"]


def test_an_answer_that_is_not_a_success_or_not_a_path_of_a_kind_is_no_fact() -> None:
    assert fct.answered_by_followups(followup("/.env", 404)) == []
    about = [alert_for("/index.html", "/static/app.js")]
    assert fct.from_parts([], about, [], ["/index.html", "/static/app.js"]).present == frozenset()
    for odd in (None, {}, {"rows": "x"}, {"rows": [None, 3, {"_source": 1}]}):
        assert fct.answered_by_followups(odd) == []


def test_a_path_a_stored_check_decided_was_not_served_never_counts() -> None:
    """A catch-all page answers 2xx to everything: a path the path-outcome check decided was the
    catch-all (or refused) is not a served file, whatever a followup row says."""
    about = [alert_for("/.env")]
    assert fct.from_parts([], about, [], ["/.env"], denied=["//.env"]).present == frozenset()
    other = fct.from_parts([], about, [], ["/.env"], denied=["/other"])
    assert "sensitive_file_served" in other.present


def test_an_alert_that_records_one_path_and_a_2xx_status_is_an_answer() -> None:
    one = {"url.path": ["/.git/config"], "http.response.status_code": [200]}
    assert fct.answered_by_alert(one) == ["/.git/config"]
    assert "sensitive_file_served" in fct.from_parts([], [one], []).present
    nested = {"url": {"path": "/.env"}, "http": {"response": {"status_code": 200}}}
    assert fct.answered_by_alert(nested) == ["/.env"]
    many = {"url.path": ["/.env", "/a"], "http.response.status_code": [200, 404]}
    assert fct.answered_by_alert(many) == []  # which one was answered cannot be told
    assert fct.answered_by_alert({"url.path": ["/.env"], "http.response.status_code": [404]}) == []
    assert fct.answered_by_alert({"url.path": ["/.env"]}) == []


# --------------------------------------------------------------------------- the case's own paths


@pytest.mark.parametrize(
    "path",
    [
        "/en/administration/office-of-the-registrar",  # "administration" is not an attack
        "/wp-content/uploads/2020/logo.png",
        "/wp-admin/admin-ajax.php",
        "/administrator/index.php",
        "/files/backup.old.pdf",
        "/docs/config.php.txt",
        "/static/app.ini.js",
    ],
)
def test_a_clients_2xx_answer_to_a_page_the_case_is_not_about_is_no_fact(path: str) -> None:
    """The review of AR9 (F4): any 2xx path of the client was tested against the categories, so a
    crawler's public pages raised "Fix or restrict" and "Change every secret". Only a path the
    case's alerts attacked or a stored path check asked about can."""
    benign = fct.from_parts([], [alert_for("/.env")], [], [path])
    assert benign.present == frozenset()
    assert keys(benign) == []
    assert fct.from_parts([], [], [], [path]).present == frozenset()  # and no alert at all


def test_a_followups_answer_is_compared_with_the_alerts_paths_as_the_server_serves_them() -> None:
    for spelled in ("/%2eenv", "//.env", "/a/../.env", "/./.env"):
        facts = fct.from_parts([], [alert_for(spelled)], [], ["/.env"])
        assert "sensitive_file_served" in facts.present, spelled
    elsewhere = fct.from_parts([], [alert_for("/%2eenv")], [], ["/other/.env"])
    assert "sensitive_file_served" in elsewhere.present  # a served .env counts anywhere (D-287)
    other = fct.from_parts([], [alert_for("/%2eenv")], [], ["/other/page"])
    assert other.present == frozenset()


def test_a_path_a_stored_check_asked_about_counts_even_if_no_alert_names_it() -> None:
    answered = ["/wp-admin/admin-ajax.php"]  # a fuzzy kind: needs the case to be about it
    assert fct.from_parts([], [], [], answered).present == frozenset()
    asked = fct.from_parts([], [], [], answered, asked=answered)
    assert keys(asked) == ["web_attack"]
    assert keys(fct.from_parts([], [], [], ["/.env"])) == ["exposed_file"]  # D-287


def test_the_served_file_alert_of_case_one_still_matches_without_any_followup() -> None:
    one = {"url.path": ["/.git/config"], "http.response.status_code": [200]}
    assert keys(fct.from_parts([], [one], [])) == ["exposed_file"]
    assert fct.attacked_paths([one, alert_for("/a/../b")], ["/c"]) == {"/.git/config", "/b", "/c"}


def test_a_served_secrets_file_counts_without_an_alert_path() -> None:
    # case 1 (2 Nov): threshold alerts record no url.path; the client's 2xx answers to /.env,
    # web.config and wp-config.php are served secrets on their own (D-287)
    from argus.responder.facts import from_parts, sensitive_file

    served = ["/search/.env", "/web.config", "/wp-config.php", "/"]
    facts = from_parts([], [], [], answered=served)
    assert "sensitive_file_served" in facts.present
    assert all(sensitive_file(p) for p in served[:3])
    assert not sensitive_file("/")
    benign = [
        "/en/administration/office-of-the-registrar", "/wp-content/uploads/2020/logo.png",
        "/wp-admin/admin-ajax.php", "/administrator/index.php", "/files/backup.old.pdf",
        "/docs/config.php.txt", "/static/app.ini.js",
    ]  # fmt: skip
    assert not any(sensitive_file(p) for p in benign)
    assert from_parts([], [], [], answered=benign).present == frozenset()
    assert sensitive_file("/.git/config")
    assert sensitive_file("/db/dump.sql")

"""§12 #13: a create can land after ARGUS's timeout and after its first lookups (plan §7.1,
"Unknown outcomes"), so a timed-out create is "ambiguous", never "failed", and is never sent
again automatically. Live only: timing cannot be replayed.

Through the delaying proxy (tests/kibana/proxy.py):

* the request reaches Kibana after the client gave up: the first lookup finds nothing, a later
  one finds the case, made by ``argus`` and found by its ``argus:case:<uuid>`` tag and by
  ``reporters=argus``;
* the request reaches Kibana at once but its answer is held: the case is made while the
  client sees only a timeout, so a timeout says nothing about whether the write happened;
* the connection to Kibana is dropped once the request is being handled, before any byte of
  the answer arrived: Kibana's handler keeps running and the case is made with nobody to
  tell. (Dropped within the same instant as
  the request, before Kibana routes it, the request is abandoned: seen on the tier, not pinned
  here, as it is a race of milliseconds; ARGUS's 15 s timeout is never that early.)
"""

from __future__ import annotations

import time
import uuid
from typing import Any

import httpx
import pytest

from tests.kibana import kit
from tests.kibana.proxy import DelayingProxy
from tests.kibana.tier import S, Tier, tier_script

WRITER = "key:argus-cases-writer"
CLIENT_TIMEOUT = 1.5  # stands in for ARGUS's 15 s
DELAY = 6.0  # well past the client's timeout and the first lookup, also on a busy machine


def _proxy(kt: Tier, **kw: Any) -> DelayingProxy:
    paths = kt.settings.paths
    url = httpx.URL(kt.settings.kibana_url)
    return DelayingProxy(
        url.host,
        url.port or 443,
        paths.kibana_tls / "kibana.crt",
        paths.kibana_tls / "kibana.key",
        paths.ca_crt,
        **kw,
    )


def _create_through(kt: Tier, proxy: DelayingProxy, body: dict[str, Any]) -> None:
    """Send the create through the proxy as ARGUS's writer key; it must time out."""
    with httpx.Client(
        base_url=f"https://127.0.0.1:{proxy.port}",
        verify=tier_script.tls_context(kt.settings.paths.ca_crt),
        trust_env=False,
        timeout=CLIENT_TIMEOUT,
    ) as client:
        authorization = kt.authorization(WRITER)
        assert authorization is not None
        with pytest.raises(httpx.ReadTimeout):
            client.post(
                f"{S}/api/cases",
                json=body,
                headers={"Authorization": authorization, "kbn-xsrf": "argus-tier-test"},
            )


def _lookup(kt: Tier, tag: str, **params: str) -> list[dict[str, Any]]:
    """ARGUS's lookups for an ambiguous create (unrecorded): by its tag."""
    response = kt.send(
        "kibana",
        "key:argus-kibana-reader",
        "GET",
        f"{S}/api/cases/_find",
        params=(("tags", tag), ("perPage", "10"), *params.items()),
    )
    assert response.status_code == 200, response.text
    cases: list[dict[str, Any]] = response.json()["cases"]
    return cases


def _body(kt: Tier, title: str) -> tuple[str, dict[str, Any]]:
    tag = f"argus:case:{uuid.uuid4()}"
    return tag, kit.case_body(kt, title, tags=["argus", tag])


def test_a_create_lands_after_the_timeout_and_the_first_lookup(live_kt: Tier) -> None:
    kt = live_kt
    tag, body = _body(kt, "lands late")
    with _proxy(kt, request_delay=DELAY) as proxy:
        _create_through(kt, proxy, body)
        assert not proxy.forwarded.is_set()  # nothing has reached Kibana yet
        assert _lookup(kt, tag) == []  # so the first lookup finds nothing
        assert proxy.answered.wait(DELAY + 30)
    found = _lookup(kt, tag)
    assert [c["created_by"]["username"] for c in found] == ["argus"]
    assert [c["id"] for c in _lookup(kt, tag, reporters="argus")] == [found[0]["id"]]
    accepted = next(t for t, what in proxy.events if what == "accepted")
    forwarded = next(t for t, what in proxy.events if what == "forwarded")
    assert forwarded - accepted >= DELAY  # it landed after the client had given up


def test_a_create_can_land_before_the_timeout_fires(live_kt: Tier) -> None:
    kt = live_kt
    tag, body = _body(kt, "answer held")
    with _proxy(kt, response_delay=DELAY) as proxy:
        _create_through(kt, proxy, body)
        assert proxy.answered.wait(DELAY)  # Kibana answered; the client never heard it
        assert [c["created_by"]["username"] for c in _lookup(kt, tag)] == ["argus"]
    answered = next(t for t, what in proxy.events if what == "answered")
    passed_on = [t for t, what in proxy.events if what in ("answer passed on", "client gone")]
    assert passed_on
    assert passed_on[0] - answered >= DELAY  # the answer was held past the client's timeout


DROP_AFTER = 0.5  # creates take about 1 s on the tier; some answer sooner
DROP_TRIES = 4


def test_kibana_finishes_a_create_whose_connection_was_dropped(live_kt: Tier) -> None:
    """Only a drop before any byte of Kibana's answer arrived shows a handler that ran on with
    nobody to answer (review F6: a try whose answer had begun proved nothing); such a try is
    repeated."""
    kt = live_kt
    for attempt in range(DROP_TRIES):
        tag, body = _body(kt, f"nobody to answer {attempt}")
        with _proxy(kt, drop_after_send=DROP_AFTER) as proxy:
            _create_through(kt, proxy, body)
            assert proxy.forwarded.is_set()
            assert not proxy.answered.is_set()
        if proxy.dropped_unanswered.is_set():
            break
        assert proxy.answered_before_drop.is_set()
    else:
        pytest.fail(
            f"Kibana answered within {DROP_AFTER} s in all {DROP_TRIES} tries: no connection "
            "was dropped while it handled the create"
        )
    deadline = time.monotonic() + 30
    while not _lookup(kt, tag) and time.monotonic() < deadline:
        time.sleep(0.5)
    assert [c["created_by"]["username"] for c in _lookup(kt, tag)] == ["argus"]

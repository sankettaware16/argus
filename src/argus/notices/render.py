"""The words of a notice (Q-H4): a subject and a body built from **fixed text and numbers only**.

A notice names its kind, a severity, a count and one link, and nothing else: never a host name,
an address, a user name, a rule name or any other value from the logs or the case (the readers
of an e-mail may not be allowed to see them, and e-mail is not private). The link is ARGUS's own
(``<web address>/go/case/<uuid>`` and the like, built by :func:`link` from a checked web address
and an id); what is behind it is shown to people who sign in.

:func:`render` takes an :class:`~argus.notices.model.Intent` (kind, reason, severity, count and
where the link leads): there is no argument a hostile value could travel in.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from argus.notices.model import WAITING_HOURS, Intent, Kind, Target, worst
from argus.site import Words

BASE = re.compile(r"https?://[a-z0-9][a-z0-9.-]{0,252}(?::[0-9]{1,5})?")

# Plain words for RAs and TAs: what happened, in one sentence, and what the count counts.
SUBJECT: Mapping[str, str] = Words(
    {
        "case_active": "A confirmed case is still active",
        "after_closure": "Activity after a case was closed",
        "closure_waiting": "A closure has been waiting for approval",
        "ioc_hit": "{A_own:host} reached a known-bad address",
        "outage": "ARGUS cannot watch everything",
    }
)
HEADLINE: Mapping[str, str] = Words(
    {
        "case_active": "A case that was confirmed as a real incident is still showing activity.",
        "after_closure": "A case that was closed as fixed has shown new activity.",
        "closure_waiting": (
            "A request to close a case has waited for approval for more than"
            f" {WAITING_HOURS} hours."
        ),
        "ioc_hit": (
            "{A_own:host} was seen reaching an address that a threat list marks as bad with high"
            " confidence."
        ),
        "outage": (
            "Part of ARGUS, or the SIEM it reads, has not been working for more than an hour, so"
            " alerts may be going unwatched."
        ),
    }
)
COUNT: dict[Kind, tuple[str, str]] = {  # (one, many): what the number counts
    "case_active": ("Activity seen on {n} day since the verdict or containment.",
                    "Activity seen on {n} days since the verdict or containment."),
    "after_closure": ("Noted {n} time.", "Noted {n} times."),
    "closure_waiting": ("Waiting for {n} hour.", "Waiting for {n} hours."),
    "ioc_hit": ("{n} high-confidence listed address or name.",
                "{n} high-confidence listed addresses or names."),
    "outage": ("For about {n} hour so far.", "For about {n} hours so far."),
}  # fmt: skip
REMINDER = "This is a reminder: it is still waiting for a person to look at it."
ENDED_SUBJECT = "The earlier outage is over"
ENDED_HEADLINE = "The problem reported earlier has cleared."  # another may still go on
ENDED_COUNT = ("It lasted about {n} hour.", "It lasted about {n} hours.")
MORE_SUBJECT = "{n} more notices"
MORE_HEADLINE = "{n} more things need a look. They are not listed one by one, to keep this calm."
MORE_COUNT = ("{n} more notice.", "{n} more notices.")
TEST_SUBJECT = "ARGUS test notice"
TEST_BODY = "This is a test message from ARGUS: if you can read it, notices can reach you."
FOOTER = (
    "This is an automatic notice from ARGUS. It names nothing on purpose: the link shows the"
    " details to people who may see them.\n"
    "To stop these messages, ask the person who runs ARGUS to switch notices off."
)


@dataclass(frozen=True)
class Rendered:
    subject: str
    body: str
    link: str


def link(base: str, target: Target) -> str:
    """ARGUS's own address for where a notice leads. ``base`` is a scheme, a host name and an
    optional port (the settings check it); the id is a UUID."""
    if BASE.fullmatch(base) is None:
        raise ValueError("the web address for links is a scheme and a host name only")
    match target.page:
        case "case":
            return f"{base}/go/case/{_id(target)}"
        case "investigation":
            return f"{base}/go/investigation/{_id(target)}"
        case "health":
            return f"{base}/health"
        case _:
            return f"{base}/"


def _id(target: Target) -> uuid.UUID:
    if target.id is None:
        raise ValueError("this page needs an id")
    return uuid.UUID(str(target.id))


def _plural(pair: tuple[str, str], n: int) -> str:
    return (pair[0] if n == 1 else pair[1]).format(n=n)


def _severity(severity: str) -> str:
    return severity.capitalize()


def _body(headline: str, severity: str | None, count: str, where: str, reminder: bool) -> str:
    parts = [REMINDER, ""] if reminder else []
    parts += [headline, ""]
    if severity is not None:
        parts.append(f"Severity: {_severity(severity)}")
    parts += [count, "", "Open it in ARGUS:", where, "", FOOTER]
    return "\n".join(parts) + "\n"


def render(intent: Intent, base: str) -> Rendered:
    """The subject and body of one notice."""
    where = link(base, intent.target)
    n = max(0, int(intent.count))
    if intent.reason == "ended":
        subject = f"[ARGUS] {ENDED_SUBJECT}"
        return Rendered(
            subject, _body(ENDED_HEADLINE, None, _plural(ENDED_COUNT, n), where, False), where
        )
    still = "Still waiting: " if intent.reason == "reminder" else ""
    subject = f"[ARGUS {_severity(intent.severity)}] {still}{SUBJECT[intent.kind]}"
    body = _body(
        HEADLINE[intent.kind],
        intent.severity,
        _plural(COUNT[intent.kind], n),
        where,
        intent.reason == "reminder",
    )
    return Rendered(subject, body, where)


def render_more(folded: Sequence[Intent], base: str) -> Rendered:
    """The one notice that tells the rest ("N more") when an hour could not take them all."""
    n = len(folded)
    if n == 0:
        raise ValueError("nothing was folded")
    where = link(base, Target("home"))
    severity = worst(folded)
    subject = f"[ARGUS {_severity(severity)}] {MORE_SUBJECT.format(n=n)}"
    body = _body(MORE_HEADLINE.format(n=n), severity, _plural(MORE_COUNT, n), where, False)
    return Rendered(subject, body, where)


def render_test() -> Rendered:
    return Rendered(TEST_SUBJECT, TEST_BODY + "\n", "")

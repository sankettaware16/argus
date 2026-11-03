"""The case team's vocabulary: the seven authors, a post's steps and its plan.

A **post** is everything ARGUS writes to one Kibana incident case; it goes in **generations**:
generation 1 opens the case (the lead), each later one is an "Update" round after the report got a
newer version. A generation is a fixed, ordered list of :class:`Step`: one request (a case, alerts,
tags, a comment, a file) by one author, with the hash of its exact text or bytes. The plan's hash
binds a person's approval to exactly what will be written. Nothing here sends anything."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Final, Literal

Kind = Literal["open", "attach", "tag", "comment", "file", "retitle", "redescribe", "edit_comment"]
StepState = Literal[
    "planned",
    "sending",
    "sent",
    "verified",
    "ambiguous",
    "resend",
    "failed",
    "skipped",
    "held",
    "superseded",
]
OPEN_STATES: Final = frozenset({"planned", "sending", "sent", "ambiguous", "resend", "held"})
# Steps that correct what was posted: they set a value, so they are read-then-set and may
# be done again after a doubt; the lead's two are the case's title and description.
EDIT_KINDS: Final = frozenset({"retitle", "redescribe", "edit_comment"})
DONE_STATES: Final = frozenset({"verified", "skipped", "superseded"})


class Author(StrEnum):
    """The Kibana users; the value is the Kibana username."""

    LEAD = "argus-lead"
    EVIDENCE = "argus-evidence"
    INTEL = "argus-intel"
    RESPONDER = "argus-responder"
    HUNTER = "argus-hunter"
    REPORTER = "argus-reporter"
    VISUALISER = "argus-visualiser"  # the seventh, optional (no key: its step is skipped)


# The order of a case: the lead opens, then evidence (the visualiser's glance follows the
# evidence comment), intel when needed, the responder, the hunter, the reporter and, last,
# the lead's verdict.
ORDER: Final = (
    Author.LEAD,
    Author.EVIDENCE,
    Author.VISUALISER,
    Author.INTEL,
    Author.RESPONDER,
    Author.HUNTER,
    Author.REPORTER,
)
# The part of a case each author owns (``Step.part``).
PART_AUTHOR: Final[dict[str, Author]] = {
    "evidence": Author.EVIDENCE,
    "devices": Author.EVIDENCE,
    "glance": Author.VISUALISER,
    "intel": Author.INTEL,
    "actions": Author.RESPONDER,
    "queries": Author.HUNTER,
    "files": Author.REPORTER,
    "verdict": Author.LEAD,
}
VERDICT_ENDING: Final = "Confirm or reject in a comment."
# why an edit was left alone: a person changed it in Kibana; kept as the step's reason
PERSON_EDIT: Final = "a person changed it in Kibana, so ARGUS leaves it"


def text_hash(text: str) -> str:
    """The whole text's hash: what an edit compares Kibana's text with (the text ARGUS last
    posted), so a person's change is told from ARGUS's own."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Step:
    """One request of a post."""

    key: str  # unique within the generation: open, attach:1, tag:1, comment:evidence:1, file:pdf
    kind: Kind
    author: Author
    part: str  # open, alerts, tags, evidence, glance, devices, intel, actions, queries, ...
    text: str | None = None  # a comment's whole text
    payload: dict[str, Any] = field(default_factory=dict)  # what the kind needs besides the text
    units: tuple[str, ...] = ()  # hashes of the content units a comment holds (for later updates)
    request_hash: str = ""  # the exact request's hash (``validator.request_hash`` with the author)

    def with_hash(self, request_hash: str) -> Step:
        return Step(
            self.key,
            self.kind,
            self.author,
            self.part,
            self.text,
            self.payload,
            self.units,
            request_hash,
        )

    def describe(self) -> str:
        """One line for a person: who does what."""
        what = {
            "open": "opens the case",
            "attach": f"attaches {len(self.payload.get('alerts', ()))} alerts",
            "tag": f"tags {len(self.payload.get('ids', ()))} alerts",
            "comment": f"comments ({self.part})",
            "file": f"uploads {self.payload.get('filename', 'a file')}",
            "retitle": "corrects the case's title",
            "redescribe": "corrects the case's description",
            "edit_comment": f"corrects its comment ({self.part})",
        }[self.kind]
        return f"{self.author.value} {what}"


@dataclass(frozen=True)
class Plan:
    """A generation's steps in the order they are sent, and the hash that binds an approval (the
    generation's number is where it is stored, not what it says: it is not in the hash)."""

    incident_id: str
    case_id: str  # the ARGUS case
    gen: int
    report_version: int
    steps: tuple[Step, ...]
    kibana_case_id: str | None = None  # known once the case is open (updates)

    @property
    def plan_hash(self) -> str:
        body = [
            self.incident_id,
            self.case_id,
            self.report_version,
            [[s.key, s.author.value, s.request_hash] for s in self.steps],
        ]
        return hashlib.sha256(
            json.dumps(body, separators=(",", ":"), ensure_ascii=True).encode()
        ).hexdigest()

    def authors(self) -> list[str]:
        seen: list[str] = []
        for s in self.steps:
            if s.author.value not in seen:
                seen.append(s.author.value)
        return seen


def unit_hash(unit: str) -> str:
    return hashlib.sha256(unit.encode("utf-8")).hexdigest()[:16]

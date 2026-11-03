"""What is refused before any request is sent.

Names: Elasticsearch's reserved users, ARGUS's service accounts and anything that is not a name
Elasticsearch could hold (compared ignoring case). Passwords: fewer than 10 or more than 1,024
characters. Nothing here looks at the SIEM, so a refusal costs no request and no lane budget.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from pydantic import SecretStr

# Elasticsearch's reserved users (the reserved realm), refused whatever ELK would answer.
RESERVED = frozenset(
    {
        "elastic",
        "kibana",
        "kibana_system",
        "logstash_system",
        "beats_system",
        "apm_system",
        "remote_monitoring_user",
    }
)
SERVICE = frozenset({"argus"})  # ARGUS's own identity
MIN_PASSWORD = 10
MAX_PASSWORD = 1_024
MAX_NAME = 507  # Elasticsearch's limit for a native username


class Reason:
    """Why a sign-in was refused before any request (fixed codes, for the audit trail)."""

    RESERVED = "reserved_name"
    SERVICE = "service_name"
    NOT_A_NAME = "not_a_name"
    SHORT_PASSWORD = "short_password"  # noqa: S105 - a reason code, not a password
    LONG_PASSWORD = "long_password"  # noqa: S105 - a reason code, not a password
    NOT_A_PASSWORD = "not_a_password"  # noqa: S105 - a reason code, not a password


@dataclass(frozen=True, slots=True)
class Credential:
    """A person's own ELK username and password, as typed. The password is a ``SecretStr``,
    so no repr, log line or exception shows it; ARGUS never stores this object."""

    username: str
    password: SecretStr = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.password, SecretStr):
            raise TypeError("the password is a SecretStr")


def is_elk_name(username: str) -> bool:
    """A name Elasticsearch could hold and a Basic credential can carry: 1-507 printable
    ASCII characters, no leading or trailing space, no ``:``."""
    return (
        0 < len(username) <= MAX_NAME
        and all(" " <= c <= "~" for c in username)
        and username == username.strip()
        and ":" not in username
    )


@dataclass(frozen=True)
class NamePolicy:
    """The names refused before any request: the reserved ones, ARGUS's own and ``extra``
    (``kibana.service_user``, ``identity.refused_names``)."""

    extra: frozenset[str] = frozenset()

    @classmethod
    def of(cls, names: Iterable[str]) -> NamePolicy:
        return cls(frozenset(name.casefold() for name in names))

    def refusal(self, username: str) -> str | None:
        """The reason ``username`` is refused, or None."""
        if not is_elk_name(username):
            return Reason.NOT_A_NAME
        folded = username.casefold()
        if folded in RESERVED:
            return Reason.RESERVED
        if folded in SERVICE or folded in self.extra:
            return Reason.SERVICE
        return None


def password_refusal(password: SecretStr) -> str | None:
    """The reason the password is refused before it is sent, or None."""
    length = len(password.get_secret_value())
    if length < MIN_PASSWORD:
        return Reason.SHORT_PASSWORD
    if length > MAX_PASSWORD:
        return Reason.LONG_PASSWORD
    try:  # a Basic header carries UTF-8: a text that cannot encode (lone surrogates) is
        password.get_secret_value().encode("utf-8")  # no password
    except UnicodeEncodeError:
        return Reason.NOT_A_PASSWORD
    return None


def refusal(credential: Credential, policy: NamePolicy) -> str | None:
    """The first reason this credential is refused before any request, or None."""
    return policy.refusal(credential.username) or password_refusal(credential.password)

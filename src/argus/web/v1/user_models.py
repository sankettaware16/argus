"""The models of ``/api/v1/admin/users`` (P4-H, D-327)."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from pydantic import Field, model_validator

from argus.web.v1.models import CapabilityName, Flag, In, Out

RoleKey = Literal["viewer", "analyst", "lead", "admin"]


class RoleOut(Out):
    key: RoleKey
    label: str
    about: str
    capabilities: list[CapabilityName]


class AccountOut(Out):
    id: int
    username: str
    display_name: str
    disabled: bool
    capabilities: list[CapabilityName]
    role: Literal["viewer", "analyst", "lead", "admin", "custom", "elk"]
    """The role these capabilities are; ``elk``: ELK decides (its roles, at each sign-in)."""
    managed_in_elk: bool
    break_glass: bool
    created_at: datetime
    last_seen_at: datetime | None
    open_sessions: int
    link_open: bool
    """A one-time link to set a password is waiting to be used."""


class AccountsOut(Out):
    users: list[AccountOut]
    roles: list[RoleOut]


class AccountRoleIn(In):
    """A role, or a set of capabilities (each brings what it needs); not both."""

    role: RoleKey | None = None
    capabilities: Annotated[list[CapabilityName] | None, Field(max_length=8)] = None

    @model_validator(mode="after")
    def _one(self) -> AccountRoleIn:
        if (self.role is None) == (self.capabilities is None):
            raise ValueError("give a role or capabilities, not both")
        return self


class AccountNewIn(AccountRoleIn):
    username: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_.-]{1,31}$")]
    display_name: Annotated[str, Field(min_length=1, max_length=100, pattern=r"^[^\x00-\x1f]+$")]


class AccountAccessIn(In):
    disabled: Flag


class AccountLinkOut(Out):
    user: AccountOut
    link: str
    """The path to give the person (``/welcome?token=…``), shown once: only its hash is kept."""
    expires_at: datetime

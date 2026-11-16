"""``/api/v1/admin/users``: users and roles in the app (P4-H, D-327).

An administrator lists every account with what it may do, makes a local account (a role or a
set of capabilities) and gets a one-time link for its person to set their own password, changes
an account's capabilities, makes a new link for a forgotten password, switches an account off
or on, and ends its sessions. Making an account, changing capabilities and making a link go
through ``argus_user_*`` in the database, which checks the administrator's own session and a
password confirmed in the last five minutes there, whatever the web says. An account that signs
in through ELK takes its capabilities from ELK, and the break-glass account is the CLI's.
"""

from __future__ import annotations

import secrets
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Path, Request
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, IntegrityError

from argus.cases.approvals import ApprovalError
from argus.web import auth, deps
from argus.web.capabilities import NEEDS, Capability, ordered
from argus.web.deps import Conn, Refusal, Surface, need
from argus.web.v1 import user_models as m

ADMIN = need(Capability.ADMIN, Surface.V1)
ADMIN_CHANGE = need(Capability.ADMIN, Surface.V1, csrf=True)
Admin = Annotated[auth.Reviewer, Depends(ADMIN)]
AdminChange = Annotated[auth.Reviewer, Depends(ADMIN_CHANGE)]
UserId = Annotated[int, Path(ge=1, le=2**53)]
LINK_VALID = timedelta(hours=72)
C = Capability

ROLES: tuple[m.RoleOut, ...] = (
    m.RoleOut(key="viewer", label="Viewer", capabilities=[C.VIEW.value],
              about="Reads incidents, reports and Today; changes nothing."),
    m.RoleOut(key="analyst", label="Analyst (TA/RA)",
              capabilities=[c.value for c in ordered({C.VIEW, C.SEE_LOGS, C.REVIEW, C.ANSWER_GOLD,
                                                      C.MANAGE_CASES})],
              about="Works the queue: reads the logs, reviews, confirms and dismisses incidents."),
    m.RoleOut(key="lead", label="Lead",
              capabilities=[c.value for c in ordered({C.VIEW, C.SEE_LOGS, C.REVIEW, C.ANSWER_GOLD,
                                                      C.MANAGE_CASES, C.REOPEN, C.APPROVE})],
              about="An analyst who also approves closures and Kibana posts, and reopens cases."),
    m.RoleOut(key="admin", label="Administrator",
              capabilities=[c.value for c in ordered(set(Capability))],
              about="Everything, and ARGUS's settings and accounts."),
)  # fmt: skip
_LIST = text(
    "SELECT u.id, u.username, u.display_name, u.realm, u.kind, u.disabled, u.capabilities,"
    " u.created_at, (SELECT max(s.last_seen_at) FROM user_sessions s WHERE s.user_id = u.id)"
    " AS last_seen_at, (SELECT count(*) FROM user_sessions s WHERE s.user_id = u.id AND"
    " s.ended_at IS NULL AND s.expires_at > now()) AS sessions, EXISTS (SELECT 1 FROM user_links"
    " l WHERE l.user_id = u.id AND l.used_at IS NULL AND l.expires_at > now()) AS link_open"
    " FROM users u WHERE u.kind <> 'service' ORDER BY u.disabled, lower(u.display_name), u.id"
)


def _refuse(status: int, code: str, detail: str) -> Refusal:
    return Refusal(status, code, detail, Surface.V1)


def role_of(capabilities: list[str]) -> str:
    have = set(capabilities)
    for role in ROLES:
        if set(role.capabilities) == have:
            return role.key
    return "custom"


def capabilities_of(body: m.AccountRoleIn) -> list[str]:
    if body.role is not None:
        return [str(c) for c in next(r.capabilities for r in ROLES if r.key == body.role)]
    chosen = {Capability(c) for c in body.capabilities or []}
    for c in list(chosen):
        chosen |= NEEDS[c]
    if not chosen:
        raise _refuse(422, "invalid", "Choose a role or at least one capability.")
    return [c.value for c in ordered(chosen)]


def _link(request: Request, token: str) -> str:
    return f"/welcome?token={token}"


def _from_db(exc: DBAPIError) -> Refusal:
    found = ApprovalError.from_db(exc)
    if found is None:
        raise exc
    words = {401: "unauthenticated", 403: "forbidden", 404: "not_found", 409: "conflict"}
    status = 409 if found.status == 410 else found.status
    code = found.code or words.get(status, "invalid")
    return _refuse(status, code, found.message.capitalize() + ".")


def install(
    router: APIRouter,
    *,
    clock: Callable[[], datetime],
    errors: Callable[..., dict[int | str, dict[str, Any]]],
) -> None:
    change = errors(400, 401, 403, 404, 409, 422)

    def token_of(request: Request) -> str:
        found = deps.session_token(request)
        assert found is not None
        return found

    async def one(conn: Any, user_id: int) -> m.AccountOut:
        rows = [r for r in await conn.execute(_LIST) if r.id == user_id]
        if not rows:
            raise _refuse(404, "not_found", "No such account.")
        return _out(rows[0])

    @router.get("/admin/users", tags=["admin"], operation_id="listUsers",
                responses=errors(401, 403))  # fmt: skip
    async def list_users(me: Admin, conn: Conn) -> m.AccountsOut:
        """Every person's account, what it may do, and the roles to choose from."""
        return m.AccountsOut(users=[_out(r) for r in await conn.execute(_LIST)], roles=list(ROLES))

    @router.post("/admin/users", tags=["admin"], operation_id="createUser", status_code=201,
                 responses=change)  # fmt: skip
    async def create_user(body: m.AccountNewIn, request: Request, me: AdminChange,
                          conn: Conn) -> m.AccountLinkOut:  # fmt: skip
        """A local account and the one-time link its person opens to set their password."""
        caps = capabilities_of(body)
        token = secrets.token_urlsafe(32)
        expires = clock() + LINK_VALID
        try:
            made = await conn.scalar(
                text("SELECT argus_user_create(:s, :u, :d, :c, :h, :e)"),
                {"s": token_of(request), "u": body.username, "d": body.display_name, "c": caps,
                 "h": auth.token_hash(token), "e": expires},
            )  # fmt: skip
        except IntegrityError:
            raise _refuse(409, "conflict", "That name is taken: choose another.") from None
        except DBAPIError as exc:
            raise _from_db(exc) from None
        await auth.audit(conn, actor=f"user:{me.username}", action="user.create",
                         target_type="user", target_id=str(made),
                         details={"username": body.username, "capabilities": caps})  # fmt: skip
        return m.AccountLinkOut(user=await one(conn, int(made)), link=_link(request, token),
                             expires_at=expires)  # fmt: skip

    @router.put("/admin/users/{user_id}/capabilities", tags=["admin"],
                operation_id="setUserCapabilities", responses=change)  # fmt: skip
    async def set_capabilities(user_id: UserId, body: m.AccountRoleIn, request: Request,
                               me: AdminChange, conn: Conn) -> m.AccountOut:  # fmt: skip
        """Change what an account may do; its open sessions see it at their next request."""
        caps = capabilities_of(body)
        try:
            await conn.execute(text("SELECT argus_user_capabilities(:s, :u, :c)"),
                               {"s": token_of(request), "u": user_id, "c": caps})  # fmt: skip
        except DBAPIError as exc:
            raise _from_db(exc) from None
        await auth.audit(conn, actor=f"user:{me.username}", action="user.capabilities",
                         target_type="user", target_id=str(user_id),
                         details={"capabilities": caps})  # fmt: skip
        return await one(conn, user_id)

    @router.post("/admin/users/{user_id}/link", tags=["admin"], operation_id="makeUserLink",
                 responses=change)  # fmt: skip
    async def make_link(user_id: UserId, request: Request, me: AdminChange,
                        conn: Conn) -> m.AccountLinkOut:  # fmt: skip
        """A new one-time link for this person to set a new password (older links end)."""
        token = secrets.token_urlsafe(32)
        expires = clock() + LINK_VALID
        try:
            await conn.execute(text("SELECT argus_user_link(:s, :u, :h, :e)"),
                               {"s": token_of(request), "u": user_id,
                                "h": auth.token_hash(token), "e": expires})  # fmt: skip
        except DBAPIError as exc:
            raise _from_db(exc) from None
        await auth.audit(conn, actor=f"user:{me.username}", action="user.link",
                         target_type="user", target_id=str(user_id))  # fmt: skip
        return m.AccountLinkOut(user=await one(conn, user_id), link=_link(request, token),
                             expires_at=expires)  # fmt: skip

    @router.put("/admin/users/{user_id}/access", tags=["admin"], operation_id="setUserAccess",
                responses=change)  # fmt: skip
    async def set_access(user_id: UserId, body: m.AccountAccessIn, me: AdminChange,
                         conn: Conn) -> m.AccountOut:  # fmt: skip
        """Switch an account off (every session ends at once) or on again."""
        now = clock()
        if me.stepped_up_at is None or now - me.stepped_up_at > timedelta(minutes=5):
            raise _refuse(403, "step_up_required",
                          "Confirm your password again (within five minutes) first.")  # fmt: skip
        target = await one(conn, user_id)
        if target.break_glass:
            raise _refuse(409, "conflict", "The break-glass account is switched on and off by"
                          " its own command (argus break-glass).")  # fmt: skip
        if user_id == me.user_id and body.disabled:
            raise _refuse(409, "conflict", "You cannot switch your own account off.")
        await conn.execute(text("UPDATE users SET disabled = :d WHERE id = :u"),
                           {"d": body.disabled, "u": user_id})  # fmt: skip
        if body.disabled:
            await conn.execute(
                text("UPDATE user_sessions SET ended_at = :t, ended_why = 'disabled'"
                     " WHERE user_id = :u AND ended_at IS NULL"),
                {"t": now, "u": user_id},
            )  # fmt: skip
        await auth.audit(conn, actor=f"user:{me.username}",
                         action="user.disable" if body.disabled else "user.enable",
                         target_type="user", target_id=str(user_id))  # fmt: skip
        return await one(conn, user_id)

    @router.post("/admin/users/{user_id}/sessions/end", tags=["admin"],
                 operation_id="endUserSessions", responses=change)  # fmt: skip
    async def end_sessions(user_id: UserId, me: AdminChange, conn: Conn) -> m.AccountOut:
        """End every open session of this account (they sign in again)."""
        await one(conn, user_id)
        await conn.execute(
            text("UPDATE user_sessions SET ended_at = :t, ended_why = 'ended_by_admin'"
                 " WHERE user_id = :u AND ended_at IS NULL AND user_id <> :me"),
            {"t": clock(), "u": user_id, "me": me.user_id},
        )  # fmt: skip
        await auth.audit(conn, actor=f"user:{me.username}", action="user.sessions_end",
                         target_type="user", target_id=str(user_id))  # fmt: skip
        return await one(conn, user_id)


def _out(r: Any) -> m.AccountOut:
    known = {x.value for x in Capability}
    caps = [c.value for c in ordered({Capability(c) for c in r.capabilities if c in known})]
    elk = r.realm != "local"
    return m.AccountOut.model_validate(
        {
            "id": r.id,
            "username": r.username,
            "display_name": r.display_name,
            "disabled": r.disabled,
            "capabilities": caps,
            "role": "elk" if elk else role_of(caps),
            "managed_in_elk": elk,
            "break_glass": r.kind == "break_glass",
            "created_at": r.created_at,
            "last_seen_at": r.last_seen_at,
            "open_sessions": int(r.sessions),
            "link_open": bool(r.link_open),
        }
    )

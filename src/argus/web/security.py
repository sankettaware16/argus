"""The web app's request rules (Phase 3 plan §7.2, §7.5; Q-A1).

- **Where a state change may come from:** any method but GET, HEAD and OPTIONS needs proof
  that this origin's own page sent it: an ``Origin`` header equal to the origin the browser
  addressed, or, without one, ``Sec-Fetch-Site: same-origin``. A request that says neither
  is refused (it was let through before Q-A1); so is any ``Sec-Fetch-Site`` but
  ``same-origin``. Non-browser clients send ``Origin`` themselves.
- **The API is for this origin only:** a request to ``/api/`` that a browser marks as coming
  from another site (``Sec-Fetch-Site: cross-site`` or ``same-site``) is refused whatever its
  method (Fetch Metadata resource isolation). Navigations to pages may come from anywhere
  (deep links from Kibana).
- **Background requests** (``X-Argus-Background: 1``: the cost bar, the app's polls) are
  served but never keep a session alive.
- **Where sign-in may send the browser back to:** ``safe_next`` keeps a same-origin path of
  printable ASCII to a page, and turns anything else into ``/``.
- **Login CSRF:** the sign-in form carries a random token that must equal the one in a
  short-lived, HttpOnly, SameSite=Strict cookie set with the form (``__Host-`` under TLS).
"""

from __future__ import annotations

import re
import secrets
from collections.abc import Mapping
from datetime import timedelta
from urllib.parse import urlsplit

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
BACKGROUND_HEADER = "x-argus-background"
NEXT_MAX = 2048
SIGNIN_TTL = timedelta(minutes=15)  # how long a sign-in form stays usable
# Paths sign-in never sends the browser back to: the API, files, and the sign-in pages.
_NOT_NEXT = frozenset({"api", "static", "signin", "stepup", "login", "logout"})


def session_cookie(tls: bool) -> str:
    """The session cookie's name: ``__Host-`` under TLS, so no other host or path can set it."""
    return "__Host-argus_session" if tls else "argus_session"


def signin_cookie(tls: bool) -> str:
    return "__Host-argus_signin" if tls else "argus_signin"


def device_cookie(tls: bool) -> str:
    """The device cookie's name: it marks a browser that signed in well once (plan §7.2)."""
    return "__Host-argus_device" if tls else "argus_device"


def own_origin(scheme: str, host: str) -> str:
    """The origin a browser addressed: the scheme and the Host header (already checked
    against the allowed host names)."""
    return f"{scheme}://{host}".lower()


def refusal(method: str, path: str, headers: Mapping[str, str], origin: str) -> str | None:
    """Why this request may not go on (a short reason), or None when it may."""
    site = headers.get("sec-fetch-site")
    if (path == "/api" or path.startswith("/api/")) and site in ("cross-site", "same-site"):
        return "the API answers this site's own pages only"
    if method.upper() in SAFE_METHODS:
        return None
    if site is not None and site != "same-origin":
        return "cross-origin request refused"
    sent = headers.get("origin")
    if sent is not None:
        return None if sent.lower() == origin else "cross-origin request refused"
    if site == "same-origin":
        return None
    return "a change needs a request from this site's own page (no Origin header)"


def is_background(headers: Mapping[str, str]) -> bool:
    return headers.get(BACKGROUND_HEADER) == "1"


def safe_next(value: str | None) -> str:
    """Where to send the browser after signing in: ``value`` when it is a path on this site
    to a page, else ``/``."""
    if not value or len(value) > NEXT_MAX:
        return "/"
    if any(not 0x21 <= ord(char) <= 0x7E for char in value) or "\\" in value:
        return "/"  # control characters, spaces (browsers drop tabs: "/\t/x" is "//x"), Unicode
    if not value.startswith("/") or value.startswith("//"):
        return "/"
    parts = urlsplit(value)
    if parts.scheme or parts.netloc:
        return "/"
    first = parts.path.split("/", 2)[1]
    if first in _NOT_NEXT:
        return "/"
    return value


_SIGNIN_TOKEN = re.compile(r"[A-Za-z0-9_-]{43}")  # what new_signin_token makes


def new_signin_token() -> str:
    return secrets.token_urlsafe(32)


def reused_signin_token(cookie: str | None) -> str:
    """The sign-in token for a form: the browser's current one when its cookie holds one of
    our shape (it expires with the cookie, SIGNIN_TTL after the last form was shown, and is
    deleted by a successful sign-in), else a new one."""
    return cookie if cookie is not None and _SIGNIN_TOKEN.fullmatch(cookie) else new_signin_token()


def signin_token_ok(cookie: str | None, field: str | None) -> bool:
    """The sign-in form's token equals its cookie's (both present and of a sane size)."""
    if not cookie or not field or len(cookie) > 100 or len(field) > 100:
        return False
    # surrogatepass keeps the encoding one-to-one: "replace" made every lone surrogate a "?"
    return secrets.compare_digest(
        cookie.encode("utf-8", "surrogatepass"), field.encode("utf-8", "surrogatepass")
    )


CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self';"
    " object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
)
# The sign-in and step-up pages run no script at all, so no compromised dependency can fake a
# password prompt there (plan §7.5): the same policy with scripts and connections switched off.
CSP_NO_SCRIPT = CSP.replace("script-src 'self'", "script-src 'none'; connect-src 'none'")

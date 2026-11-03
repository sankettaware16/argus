"""Secret redaction for anything that leaves the process as text (logs, audit details, errors).

Three layers: **key names** (values under keys like ``password`` or ``api_key``, in mappings, named
tuples, dataclasses and pydantic models), **registered secret values** (exact secrets loaded from
config, in their escaped forms too) and **shapes** (URL userinfo, ``Authorization`` schemes,
``key=value`` pairs, cookies, PEM keys, well-known provider key formats). Redaction must never
raise and never return the original secret. Log and alert text is attacker-controlled, so every
text rule runs in linear time: no nested quantifiers, possessive ones where it must not backtrack.
"""

from __future__ import annotations

import collections
import contextlib
import dataclasses
import enum
import json
import re
import threading
from collections.abc import Callable, Mapping, Sequence
from datetime import date, datetime, time
from decimal import Decimal
from pathlib import PurePath
from typing import Any, TypeGuard
from urllib.parse import quote, quote_plus
from uuid import UUID

from pydantic import BaseModel

MASK = "***"

# Words that make a key secret (regex fragments, each starting with a letter). A key name must
# end with one, after a separator or a camelCase hump; in text the word must come right before
# "=" or ":".
_SECRET_WORD_LIST = (
    *("password", "passwd", "passphrase", "pgpassword", "pwd", "secret", "token", "authorization"),
    *(r"session[_\-]?id", r"api[_\-]?key", r"access[_\-]?key", r"secret[_\-]?key"),
    *(r"private[_\-]?key", r"client[_\-]?secret"),
)
# Words that are secret as key names but also ordinary prose ("auth: failed for user bob",
# "credentials: none configured"). In text they need "=", a quoted key, a pair or a quoted value.
_PROSE_WORD_LIST = ("auth", "credentials?")
# Secret words written with a space are prose words in text ("session id: 12345 closed"). They
# are for text only: a key name has its whitespace turned into "_" before it is matched, so
# _SENSITIVE_KEY leaves them out and matches the key "api key" as api_key.
_SPACED_WORD_LIST = (
    *("session id", "api key", "access key", "secret key"),
    *("private key", "client secret"),
)
_COOKIE_WORD_LIST = (r"set[_\- ]?cookie", "cookie")
_SCHEME_LIST = ("ApiKey", "Bearer", "Basic", "Token")
_SECRET_WORDS = "|".join(_SECRET_WORD_LIST)
_PROSE_WORDS = "|".join(_PROSE_WORD_LIST + _SPACED_WORD_LIST)
_COOKIE_WORDS = "|".join(_COOKIE_WORD_LIST)
_SCHEMES = "|".join(_SCHEME_LIST)
_KEY_WORDS = "|".join(_SECRET_WORD_LIST + _PROSE_WORD_LIST + _COOKIE_WORD_LIST)


def _first_letter_of(words: tuple[str, ...]) -> str:
    """A lookahead for the first letters of ``words``.

    The regex engine tries a pattern at every position; this cheap test rejects most of them
    before the alternation of words is tried (about 3x faster on ordinary log text).
    """
    letters = {word[0].lower() for word in words}
    if not all(letter.isalpha() for letter in letters):
        raise ValueError("every word must start with a letter")
    return "(?=[" + "".join(sorted(letters | {letter.upper() for letter in letters})) + "])"


# A key name ends with a secret word that starts the key, follows a separator, or starts at a
# camelCase hump ("accessToken", "userAPIToken"; "OAuth" is one word). The word itself is
# matched in any case, so a hump inside it does not split it ("passWord", "newPassWord").
# Key names have their whitespace turned into "_" first, so "api key" matches api[_\-]?key.
_SENSITIVE_KEY = re.compile(
    r"(?:^|[_\-.]|(?-i:(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z]{2})(?=[A-Z][a-z])))"
    rf"(?:{_KEY_WORDS})$",
    re.IGNORECASE,
)

# In text, a key word starts after a non-alphanumeric ("db_password", "X-Api-Key") or a
# lower-to-upper camelCase hump ("accessToken"), never mid-word ("csrftoken", "max_tokens").
_WORD_START = r"(?:(?<![A-Za-z0-9])|(?-i:(?<=[a-z0-9])(?=[A-Z])))"
# A secret or prose word; the group "strict" tells which (prose words assign differently).
_SECRET_NAME = (
    _first_letter_of(_SECRET_WORD_LIST + _PROSE_WORD_LIST + _SPACED_WORD_LIST)
    + _WORD_START
    + f"(?:(?P<strict>{_SECRET_WORDS})|{_PROSE_WORDS})"
)
_COOKIE_NAME = _first_letter_of(_COOKIE_WORD_LIST) + _WORD_START + f"(?:{_COOKIE_WORDS})"
# Only the full header name ("Authorization", "Proxy-Authorization") makes any value a credential.
_AUTH_NAME = "(?=[Aa])" + _WORD_START + "authorization"

# Quoted strings on one line, escaped quotes included: "...", '...' (also with the b/r/u prefix
# of a Python repr such as b'...'), and \"...\" (a JSON string inside a JSON string).
_ANY_QUOTED = (
    r"(?:[bru]{0,2}(?:\"(?:[^\"\\\n]|\\.)*+\"|'(?:[^'\\\n]|\\.)*+')"
    r"|\\\"(?:[^\"\\\n]|\\[^\"\n])*+\\\")"
)
# The same for a masked value, which must not be empty; the groups keep its prefix and quotes.
_QUOTED = (
    r"(?:(?P<pfx>[bru]{0,2})(?:(?P<dq>\")(?:[^\"\\\n]|\\.)++\"|(?P<sq>')(?:[^'\\\n]|\\.)++')"
    r"|(?P<eq>\\\")(?:[^\"\\\n]|\\[^\"\n])++\\\")"
)
# A list or tuple value ({"Authorization": ["Basic ..."]}, authorization: ['...'], ('tok',)):
# quoted items or bare scalars separated by commas. The whole list is masked; its brackets stay.
_ITEM = rf"(?:{_ANY_QUOTED}|[^\s,\[\]()\"'\\]++)"
_BARE = r"[^\s&\"',;}]"  # an unquoted value stops at whitespace and & " ' , ; }
# The list must end the value (closing brackets of an enclosing structure may follow), or it
# was only the start of an unquoted value: password=(29G]pMwdD is not the list (29G].
_LIST = (
    rf"(?P<lb>[\[(])"
    rf"(?P<items>\s*+(?:{_ITEM}(?:\s*+,\s*+{_ITEM})*+\s*+,?\s*+)?)"
    rf"(?P<rb>[\])])(?![\])]*+[^\s&\"',;}}\])])"
)
# An unquoted value, after the opening brackets and quote of a list or string that the
# alternatives above could not parse (unterminated); a known auth scheme before it stays.
_UNQUOTED = (
    rf"(?P<ob>(?:[\[(][ \t]*+)*+)(?P<oq>[\"']?)"
    rf"(?P<scheme>(?:{_SCHEMES})[ \t]++)?{_BARE}++"
)
_VALUE = rf"(?:{_LIST}|{_QUOTED}|{_UNQUOTED})"
_COOKIE_PAIRS = r"(?:;[ \t]*+[^\s&\"',;}=]++=[^\s&\"',;}]*+)*+"  # "; name=value" repeated

# The word ends the key; then an optional closing quote of a quoted key (escaped in JSON that
# was itself put in a JSON string), and "=" or ":".
_KEY_QUOTE = r"(?:\\?\"|')?"
_ASSIGN = rf"(?![A-Za-z0-9]){_KEY_QUOTE}\s*+[=:]\s*+"
# Prose words: "=", a quoted key, ":" before a quoted value (or a list of them), or ":" before a
# known auth scheme ("auth: Basic <credential>", "X-Auth: Bearer <token>"): a scheme word after
# the key is unambiguous, while "auth: failed for user bob" stays readable.
_PROSE_ASSIGN = (
    r"(?![A-Za-z0-9])(?:(?:\\?\"|')\s*+[=:]\s*+|\s*+=\s*+"
    r"|\s*+:\s*+(?=(?:[\[(]\s*+)?(?:[bru]{0,2}[\"']|\\\"))"
    rf"|\s*+:\s*+(?=(?:{_SCHEMES})[ \t]))"
)
# A ('name', 'value') pair: raw ASGI headers [(b'authorization', b'Bearer ...')], header and
# query parameter lists, JSON [["Authorization", "Basic ..."]]. Its value is masked when the
# name is a sensitive key name, as in a mapping. Only a pair, not a longer tuple of names.
_PAIR = (
    r"(?P<key>[\[(][ \t]*+[bu]?"
    r"(?:\"(?P<kd>[^\"\\\n]{1,64})\"|'(?P<ks>[^'\\\n]{1,64})'|\\\"(?P<ke>[^\"\\\n]{1,64})\\\")"
    rf"[ \t]*+,[ \t]*+){_QUOTED}(?=[ \t]*+[\])])"
)

# A credential after an auth scheme outside a header. Prose has scheme words followed by words
# ("Basic licence.", "Token refreshed", "Bearer token.", "Basic read-only access", "Token
# ExpiredSignatureError"), so the credential must look like one: a digit or one of + / = _ ~,
# two "." or "-" between letters (a JWT has two dots), or 32+ characters. A trailing full stop
# or one hyphen is prose. A letters-only credential is kept in prose; in a header, a pair or a
# key=value it is masked.
_CREDENTIAL = r"[A-Za-z0-9+/=._~\-]"
_LOOKS_LIKE_CREDENTIAL = (
    rf"(?={_CREDENTIAL}*?[0-9+/=_~]|[A-Za-z]*+[.\-][A-Za-z]++[.\-][A-Za-z]|{_CREDENTIAL}{{32}})"
)
# A '"' followed by one of these closes a quoted string ({"url":"http://h:9200","to":"a@b"},
# href="...">, f("...")); any other '"' may be part of a URL password.
_URL_QUOTE = r"\"(?![,:;)\]}>])"


def _masked_assignment(match: re.Match[str]) -> str:
    """Keep the key, the quotes, the brackets and a known auth scheme; mask the value."""
    found = match.groupdict()
    if found.get("lb"):
        if not found["items"].strip():  # an empty list holds no secret
            return match[0]
        return f"{found['key']}{found['lb']}{MASK}{found['rb']}"
    quote_char = found.get("dq") or found.get("sq") or found.get("eq")
    if quote_char:
        return f"{found['key']}{found['pfx'] or ''}{quote_char}{MASK}{quote_char}"
    opening = (found.get("ob") or "") + (found.get("oq") or "")
    return f"{found['key']}{opening}{found.get('scheme') or ''}{MASK}"


def _masked_pair(match: re.Match[str]) -> str:
    """Mask the value of a ('name', 'value') pair whose name is a sensitive key name."""
    name = match["kd"] or match["ks"] or match["ke"]
    return _masked_assignment(match) if is_sensitive_key(name) else match[0]


_Replacement = str | Callable[[re.Match[str]], str]

# (pattern, replacement) — replacements keep enough context to debug without the secret.
_TEXT_RULES: tuple[tuple[re.Pattern[str], _Replacement], ...] = (
    (
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----.*?"
            r"(?:-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----|\Z)",
            re.DOTALL,
        ),
        "-----PRIVATE KEY " + MASK + "-----",
    ),
    # A PostgreSQL password verifier (what `argus db bootstrap` sends instead of the password):
    # SCRAM-SHA-256$<iterations>:<salt>$<StoredKey>:<ServerKey>, all base64.
    (
        re.compile(r"\bSCRAM-SHA-256\$[0-9]++:[A-Za-z0-9+/=]++\$[A-Za-z0-9+/=:]++"),
        "SCRAM-SHA-256$" + MASK,
    ),
    # scheme://user:pw@host -> scheme://user:***@host; the user may be empty (redis://:pw@).
    # The password runs to the last "@" before the first "/", "?" or "#" (as urllib splits it), or,
    # when it holds an unencoded "/", "?" or "#", to the first "@" unless the ":" is followed by a
    # port and a "/" before that "@". Whitespace ends the URL, and so does a '"' that closes a
    # quoted string (_URL_QUOTE); any other character can be in the password. A password with a '"'
    # right before one of , : ; ) ] } > ends the URL at that quote and is masked only up to an "@"
    # before it. A match starts at a "://" and stops before the next one, so the rule is linear.
    (
        re.compile(
            rf"(?<=[A-Za-z0-9+.\-])(?P<pre>://[^:/\[\]\s\"]*+:)"
            rf"(?:(?:[^/?#\s\"]|{_URL_QUOTE})+(?=@)"
            rf"|(?!\d++(?:/|[?#][^@\s/]*+/))(?:(?!://)(?:[^@\s\"]|{_URL_QUOTE}))++(?=@))"
        ),
        r"\g<pre>" + MASK,
    ),
    # "Bearer <credential>" anywhere, the scheme in any case (RFC 7235).
    (
        re.compile(
            rf"{_first_letter_of(_SCHEME_LIST)}\b(?P<scheme>(?i:{_SCHEMES}))\s++"
            rf"{_LOOKS_LIKE_CREDENTIAL}{_CREDENTIAL}{{6,}}"
        ),
        r"\g<scheme> " + MASK,
    ),
    # "Authorization: <scheme> <credentials>": any value is a credential here, also in a list.
    # A known scheme stays visible; after any other first word the next word is masked too, as
    # the first one may be an unknown scheme ("SSWS <token>").
    (
        re.compile(
            rf"(?P<key>{_AUTH_NAME}(?![A-Za-z0-9]){_KEY_QUOTE}[ \t]*+:[ \t]*+)"
            rf"(?:{_LIST}|{_QUOTED}|{_UNQUOTED}(?(scheme)|(?:[ \t]++{_BARE}++)?+))",
            re.IGNORECASE,
        ),
        _masked_assignment,
    ),
    (re.compile(_PAIR), _masked_pair),
    # Cookie: a=1; b=2 — every pair (Set-Cookie attributes without "=" end the value).
    (
        re.compile(
            rf"(?P<key>{_COOKIE_NAME}{_ASSIGN})"
            rf"(?:{_QUOTED}|(?P<oq>[\"']?){_BARE}+{_COOKIE_PAIRS})",
            re.IGNORECASE,
        ),
        _masked_assignment,
    ),
    # password=xxx, ARGUS_DATABASE__PASSWORD=xxx, "accessToken": "xxx", api_key: xxx,
    # "access_token": ["xxx"] (query strings, .env lines, JSON-ish text); a quoted value is
    # masked to its closing quote, a list to its closing bracket. Also auth=xxx,
    # "credentials": "xxx", api key="xxx", but not "auth: failed for user bob".
    (
        re.compile(
            rf"(?P<key>{_SECRET_NAME}(?(strict){_ASSIGN}|{_PROSE_ASSIGN})){_VALUE}",
            re.IGNORECASE,
        ),
        _masked_assignment,
    ),
    # Well-known provider key formats.
    (re.compile(r"\bgsk_[A-Za-z0-9]{20,}"), "gsk_" + MASK),  # Groq
    (re.compile(r"\bsk-or-v1-[A-Za-z0-9]{20,}"), "sk-or-v1-" + MASK),  # OpenRouter
    (re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}"), "sk-" + MASK),  # OpenAI-style
    (re.compile(r"\bAIza[0-9A-Za-z_\-]{30,}"), "AIza" + MASK),  # Google API key
    (re.compile(r"\bAQ\.[A-Za-z0-9_\-]{20,}"), "AQ." + MASK),  # Google AI Studio key
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}"), "gh_" + MASK),  # GitHub
    (re.compile(r"\bxox[abposr]-[A-Za-z0-9\-]{10,}"), "xox-" + MASK),  # Slack
)

_MIN_REGISTERED_SECRET_LEN = 6
_MAX_DEPTH = 12
# Defence in depth: the shape rules see at most this much of one string (registered secrets are
# masked in the whole string first), so even a pathological input costs bounded time.
_MAX_TEXT_CHARS = 1 << 20
_FAILED = "<redaction-failed>"

_registry_lock = threading.Lock()
_registered: tuple[str, ...] = ()  # longest first


def register_secret(value: str | None) -> None:
    """Mask this exact value wherever it appears from now on (e.g. a password from config).

    Its escaped forms are masked too: inside a repr, ``ascii()``/``%a`` output, a bytes repr or
    a JSON string a backslash, quote or non-ASCII character is escaped, and inside a URL the
    value is percent-encoded.
    """
    global _registered
    if not value or len(value) < _MIN_REGISTERED_SECRET_LEN:
        return
    forms = {
        value,
        repr(value)[1:-1],
        ascii(value)[1:-1],
        repr(value.encode("utf-8", "surrogatepass"))[2:-1],
        json.dumps(value)[1:-1],
        json.dumps(value, ensure_ascii=False)[1:-1],
    }
    with contextlib.suppress(UnicodeEncodeError):  # lone surrogates have no URL form
        forms |= {quote(value, safe=""), quote_plus(value, safe="")}
    with _registry_lock:
        _registered = tuple(sorted(set(_registered) | forms, key=len, reverse=True))


def clear_registered_secrets() -> None:
    """Testing helper."""
    global _registered
    with _registry_lock:
        _registered = ()


def is_sensitive_key(key: object) -> bool:
    """Whether values under this mapping key or field name are secrets.

    Matches ``password``, ``db_password``, ``accessToken``, ``passWord``, ``newPassWord``,
    ``X-Api-Key``, ``PGPASSWORD``, ``ARGUS_DATABASE__PASSWORD``; not ``token_count``,
    ``max_tokens``, ``author``, ``password_policy``. Bytes keys (raw HTTP headers) are decoded
    first.
    """
    if isinstance(key, bytes | bytearray):
        key = bytes(key).decode("utf-8", errors="replace")
    if not isinstance(key, str):
        return False
    return _SENSITIVE_KEY.search("_".join(key.split())) is not None


def redact_text(text: str) -> str:
    """Mask registered secrets and credential shapes in ``text``.

    Text longer than 1 MiB is truncated (after registered secrets are masked in all of it).
    """
    # Longest first, so a secret that contains another registered secret is fully masked.
    # Repeat until gone: masking can splice text into a new occurrence (secret "a***", text
    # "aa***"). Every pass shortens the text (secrets are longer than MASK), so this terminates.
    for secret in _registered:
        while secret in text:
            text = text.replace(secret, MASK)
    if len(text) > _MAX_TEXT_CHARS:
        text = f"{text[:_MAX_TEXT_CHARS]}...<{len(text) - _MAX_TEXT_CHARS} chars truncated>"
    for pattern, replacement in _TEXT_RULES:
        text = pattern.sub(replacement, text)
    return text


def redact(value: Any) -> Any:
    """Return a redacted copy of ``value`` (dicts, lists, tuples, sets, strings, bytes, objects).

    A part that cannot be read (a mapping that raises while iterated, a broken ``__repr__``) is
    replaced on its own; the rest of the value is kept.
    """
    try:
        return _redact(value, 0, set())
    except Exception:  # never let redaction break the caller, never leak on failure
        return _FAILED


def distinct_keys(keys: Sequence[tuple[object, Any]]) -> list[Any]:
    """Output keys for a mapping's ``(original key, key as shown)`` pairs, without collisions.

    Showing keys as text can make two of them equal (``{b"a": 1, "a": 2}``, ``{1: x, "1": y}``), and
    a dict would keep only the last. A key keeps its text unless an earlier key took that name (str
    keys keep theirs whenever they can); a renamed key gets its original type appended, numbered if
    that is taken too: ``"1 (int)"``, ``"a (bytes)"``, ``"1 (int 2)"``.
    """
    reserved = {shown for original, shown in keys if isinstance(original, str)}
    taken: set[Any] = set()
    counts: dict[str, int] = {}
    result: list[Any] = []
    for original, shown in keys:
        name = shown
        if name in taken or (not isinstance(original, str) and name in reserved):
            name = _renamed(str(shown), type(original).__name__, (taken, reserved), counts)
        taken.add(name)
        result.append(name)
    return result


def _renamed(text: str, label: str, used: tuple[set[Any], set[Any]], counts: dict[str, int]) -> str:
    """``text (label)``, or ``text (label 2)``... if that is used too.

    ``counts`` remembers where the numbering of each base name stopped, so a mapping with many
    colliding keys is still renamed in linear time.
    """
    base = f"{text} ({label}"
    count = counts.get(base, 1)
    while True:
        name = f"{base})" if count == 1 else f"{base} {count})"
        count += 1
        if not any(name in names for names in used):
            counts[base] = count
            return name


def _redact(value: Any, depth: int, seen: set[int]) -> Any:
    try:
        return _redact_value(value, depth, seen)
    except Exception:
        return _FAILED


def _redact_value(value: Any, depth: int, seen: set[int]) -> Any:
    if value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, bytes | bytearray):
        return redact_text(bytes(value).decode("utf-8", errors="replace"))
    if isinstance(value, datetime | date | time):
        return value.isoformat()
    if isinstance(value, enum.Enum):
        return _redact(value.value, depth, seen)
    if isinstance(value, UUID | Decimal | PurePath):
        return redact_text(str(value))
    if depth >= _MAX_DEPTH:
        return "<max-depth>"
    if id(value) in seen:
        return "<cycle>"
    seen.add(id(value))
    try:
        fields = _shown_fields(value)
        if fields is not None:
            if isinstance(value, tuple):  # a named tuple stays a sequence (a JSON array)
                return tuple(_field_value(name, item, depth, seen) for name, item in fields)
            shown = [
                f"{redact_text(name)}={_field_value(name, item, depth, seen)!r}"
                for name, item in fields
            ]
            return f"{redact_text(type(value).__name__)}({', '.join(shown)})"
        if isinstance(value, Mapping):
            entries = list(value.items())
            keys = distinct_keys([(key, _redact_key(key)) for key, _ in entries])
            return {
                shown_key: _field_value(key, item, depth, seen)
                for shown_key, (key, item) in zip(keys, entries, strict=True)
            }
        if isinstance(value, list | tuple | set | frozenset) and not _is_named_tuple(value):
            items = [_redact(item, depth + 1, seen) for item in value]
            return tuple(items) if isinstance(value, tuple) else items
    finally:
        seen.discard(id(value))
    # Any other object, and a named tuple with its own __repr__: redact its text form
    # (SecretStr renders as '**********' already).
    try:
        rendered = (
            f"{type(value).__name__}: {value}" if isinstance(value, BaseException) else repr(value)
        )
    except Exception:
        return "<unrepresentable>"
    return redact_text(rendered)


def _field_value(name: object, item: Any, depth: int, seen: set[int]) -> Any:
    """The redacted value of a mapping entry or field: masked under a sensitive name."""
    return MASK if is_sensitive_key(name) and item is not None else _redact(item, depth + 1, seen)


def _redact_key(key: object) -> object:
    """Mapping keys are text too: str and bytes keys are redacted, other keys are kept as is."""
    if isinstance(key, bytes | bytearray):
        key = bytes(key).decode("utf-8", errors="replace")
    return redact_text(key) if isinstance(key, str) else key


# ------------------------------------------------------------------ generated reprs


def _repr_identity(function: object) -> tuple[object, object]:
    """What tells a generated ``__repr__`` apart: its code and the file of what it wraps.

    Every dataclass's generated repr is the same wrapper around a function compiled from a
    string; a hand-written ``__repr__`` (even one wrapped by ``reprlib.recursive_repr``) is not.
    """
    wrapped = getattr(function, "__wrapped__", None)
    return getattr(function, "__code__", None), getattr(
        getattr(wrapped, "__code__", None), "co_filename", None
    )


@dataclasses.dataclass
class _DataclassReprProbe:
    pass


_DATACLASS_REPR = _repr_identity(vars(_DataclassReprProbe)["__repr__"])
_NAMED_TUPLE_REPR_CODE = getattr(
    collections.namedtuple("_NamedTupleReprProbe", "x").__repr__, "__code__", None
)


def _repr_owner(cls: type) -> type:
    """The class in ``cls``'s MRO whose ``__repr__`` its instances use."""
    return next(klass for klass in cls.__mro__ if "__repr__" in vars(klass))


def _is_named_tuple(value: object) -> TypeGuard[tuple[Any, ...]]:
    return isinstance(value, tuple) and isinstance(getattr(type(value), "_fields", None), tuple)


def _shown_fields(value: object) -> list[tuple[str, Any]] | None:
    """The fields that the generated repr of a dataclass, pydantic model or named tuple shows.

    None for any other value, and for a class with its own ``__repr__``: what that repr shows
    is up to the class (it may hide a value), so such a value is redacted through its repr.
    Redacting a generated repr's text alone would skip the key-name rule.
    """
    if isinstance(value, BaseModel):
        cls = type(value)
        if cls.__repr__ is BaseModel.__repr__ and cls.__repr_str__ is BaseModel.__repr_str__:
            return [(name, item) for name, item in value.__repr_args__() if name is not None]
        return None
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        # The generated repr shows the fields of the class it was generated for, which can be
        # a base class of a dataclass declared with repr=False.
        owner: Any = _repr_owner(type(value))
        if _DATACLASS_REPR[0] is None or "__dataclass_fields__" not in vars(owner):
            return None
        if _repr_identity(vars(owner)["__repr__"]) != _DATACLASS_REPR:
            return None
        return [(f.name, getattr(value, f.name)) for f in dataclasses.fields(owner) if f.repr]
    if _is_named_tuple(value):
        owner = _repr_owner(type(value))
        names = vars(owner).get("_fields")
        code = getattr(vars(owner)["__repr__"], "__code__", None)
        if (
            _NAMED_TUPLE_REPR_CODE is not None
            and code is _NAMED_TUPLE_REPR_CODE
            and isinstance(names, tuple)
            and len(names) == len(value)
            and all(isinstance(name, str) for name in names)
        ):
            return list(zip(names, value, strict=True))
    return None

"""Network guard for the ARGUS test suite and for every Python process it starts.

One copy runs per process: tests/conftest.py loads it into pytest, and tests/_guard/sitecustomize.py
loads it into each Python child process (the harness puts tests/_guard first on PYTHONPATH and
describes the guard in the PYTEST_ARGUS_NETGUARD variable).

While the guard is active:

* Sockets may only reach loopback addresses (127.0.0.0/8, ::1) and Unix-domain sockets, and never
  a production host, nor a production port on loopback: 18443 is the local LLM's reverse tunnel
  on the ARGUS machine (D-108, Q-G1), so no test can reach the real model machine through it.
  The guard sees the ``socket.connect`` (also ``connect_ex``), ``socket.sendto`` and
  ``socket.sendmsg`` audit events, so UDP datagrams and TCP Fast Open are covered as well as
  ``_socket`` objects and asyncio. bytes/bytearray hosts and numeric encodings
  are read the way the C library reads them; a host the guard cannot read or resolve is refused.
* psycopg connections are checked before libpq, which opens its own sockets without any audit
  event, gets to run (``psycopg.connect``, ``Connection.connect``, ``AsyncConnection.connect``):
  the server must be on this machine, not on port 18443 (the local LLM's tunnel), and the
  database must not be a protected one (the developer's own). Whatever stops a psycopg
  connection is raised without the connection parameters in any frame, since they hold the
  password.
* A process whose command line names a production host, or port 18443 (``host:18443``,
  ``-p 18443``, or ``18443`` as an argument of its own beside a name or address of this machine,
  as in ``nc 127.0.0.1 18443``), is not started: a tripwire for curl, ssh, nc and the like. It
  cannot see a host that a non-Python program reads from its own configuration.

A guard inherited switched on from the parent process is locked on: nothing in the child, such as
a nested pytest run given --run-live, can switch it off. The same holds for a pytest run nested in
a guarded test of this process (pytest.main() in a test): every pytest run configured here is
recorded in this module (begin_run/end_run), which all copies of tests/conftest.py share.

A refused attempt raises NetworkAccessBlockedError (ProductionAccessBlockedError for a production
host) before anything is sent. Not covered: C code that opens its own sockets (libcurl,
libuv/uvloop, ctypes calls to connect()), non-Python child processes beyond the command-line
tripwire, and Python children started with -I, -E or -S or with an environment that drops
PYTHONPATH. Only an OS-level control (a network namespace or a firewall rule) closes those.

Keep this module importable by any Python 3.10+: a child process may run another interpreter.
"""

from __future__ import annotations

import ipaddress
import itertools
import json
import os
import re
import socket
import string
import sys
import unicodedata
import urllib.parse
from collections.abc import Callable, Iterable, Iterator, Mapping
from importlib.abc import MetaPathFinder
from importlib.machinery import ModuleSpec
from pathlib import Path
from types import ModuleType
from typing import Any, NamedTuple

# The production SIEM's hosts are read from the checkout's configuration (configured_hosts,
# D-294), never written here: this file names no installation's host.
_ROOT = Path(__file__).resolve().parent.parent.parent
_URL_SETTINGS = ("ARGUS_SIEM__URL", "ARGUS_KIBANA__URL", "ARGUS_INCIDENT__KIBANA_URL")
_URL = re.compile(r"\b[A-Za-z][A-Za-z0-9+.-]*://[^\s'\"<>]+")
_IPV4_TEXT = re.compile(r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?![\d./])")  # a network (/8) is no host
# Loopback ports that lead to production: the local LLM's tunnel (D-108). Tests use their own.
PRODUCTION_PORTS = frozenset({18443})
_PORT_IN_COMMAND = re.compile(r"(?:[:/]|\bport[= ]?|-p ?)(18443)(?![0-9])", re.IGNORECASE)
# The port as an argument of its own after a host (`nc 127.0.0.1 18443`): refused when the
# command also names this machine; the number alone (`echo 18443`) is not.
_COMMAND_TOKENS = re.compile(r"[\s'\"=,;]+")
_UNSPECIFIED = "0.0.0.0"  # noqa: S104 - a bind address (units.web.host), never a host to reach
_LOOPBACK_NAMES = frozenset({"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"})
ENV_VAR = "PYTEST_ARGUS_NETGUARD"  # the pytest process describes the guard to its children here

# locked: the guard was inherited switched on from the parent process and cannot be switched off.
STATE = {"active": False, "installed": False, "locked": False}

Hosts = Callable[[], frozenset[str]]
Databases = Callable[[], frozenset[tuple[str, int]]]  # (database name, server port) pairs
Resolver = Callable[..., Any]

_AF_UNIX = getattr(socket, "AF_UNIX", None)
_INET_FAMILIES = (socket.AF_INET, socket.AF_INET6)
_SOCKET_EVENTS = frozenset({"socket.connect", "socket.sendto", "socket.sendmsg"})
_COMMAND_ARGS = {  # audit event -> positions of the program and its arguments in the event args
    "subprocess.Popen": (0, 1),  # executable, args, cwd, env
    "os.system": (0,),  # command
    "os.exec": (0, 1),  # path, args, env
    "os.posix_spawn": (0, 1),  # path, argv, env
    "os.spawn": (1, 2),  # mode, path, args, env
    "pty.spawn": (0,),  # argv
}
# Connection parameters that decide where libpq connects and to which database.
_LIBPQ_TARGET_KEYS = ("host", "hostaddr", "port", "service", "dbname", "user")
_LIBPQ_DEFAULT_PORT = 5432
_PID = os.getpid()


def _default_production_hosts() -> frozenset[str]:
    return PRODUCTION_HOSTS


def _no_databases() -> frozenset[tuple[str, int]]:
    return frozenset()


_production_hosts: Hosts = _default_production_hosts
_protected_databases: Databases = _no_databases
# What the parent process described (install_from_environment). Kept apart from the callables
# above, which a nested pytest run's conftest replaces with its own.
_inherited_hosts: frozenset[str] = frozenset()
_inherited_databases: frozenset[tuple[str, int]] = frozenset()


class _Run(NamedTuple):
    """A pytest run configured in this process, and what it changed, to restore when it ends."""

    owner: object  # the run's pytest.Config
    environment: dict[str, str | None]  # _RUN_VARIABLES before the run
    active: bool
    locked: bool
    production_hosts: Hosts  # the callables before the run: an enclosing run's, say
    protected_databases: Databases


# The variables through which Python children get the guard (tests/conftest.py sets both).
_RUN_VARIABLES = ("PYTHONPATH", ENV_VAR)
# Every pytest run configured in this process, innermost last: an in-process nested run
# (pytest.main() in a test) adds one, whichever copy of tests/conftest.py it loads.
_RUNS: list[_Run] = []


def _hosts() -> frozenset[str]:
    hosts = _production_hosts() | _inherited_hosts
    for run in _RUNS:  # a nested run keeps what the runs around it protect
        hosts |= run.production_hosts()
    return hosts


def _databases() -> frozenset[tuple[str, int]]:
    databases = _protected_databases() | _inherited_databases
    for run in _RUNS:
        databases |= run.protected_databases()
    return databases


class NetworkAccessBlockedError(PermissionError):
    """A test tried to reach something other than loopback or a Unix-domain socket.

    Subclasses ``OSError`` (via PermissionError) so standard-library connection code treats it
    like any refused connection and closes its sockets.
    """


class ProductionAccessBlockedError(NetworkAccessBlockedError):
    """A test tried to reach the production SIEM; only live tests with --run-live may."""


# --------------------------------------------------------------------------- addresses


def _ip(text: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def _normalise(host: str) -> str:
    """Canonical IP literal (IPv4-mapped IPv6 as IPv4, zone dropped); a name is returned as is."""
    ip = _ip(host.split("%", 1)[0])
    if ip is None:
        return host
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return str(ip.ipv4_mapped)
    return str(ip)


def _host_text(host: object) -> str | None:
    """A host as sockets accept it (str, or ASCII bytes/bytearray); None for anything else."""
    if isinstance(host, str):
        return host
    if isinstance(host, (bytes, bytearray)):
        try:
            return bytes(host).decode("ascii")
        except UnicodeDecodeError:
            return None
    return None


def _addresses(host: str, resolve: Resolver) -> list[str] | None:
    """Every address ``host`` stands for, normalised; None if it cannot be resolved."""
    literal = _normalise(host)
    if _ip(literal) is not None:
        return [literal]
    try:  # also turns numeric forms such as '0xa.0x14.0x3c.0xb' into the address libc uses
        infos = resolve(host, None)
    except (OSError, ValueError):  # gaierror; UnicodeError for a name IDNA cannot encode
        return None
    return [_normalise(str(info[4][0])) for info in infos]


def _production_hit(
    host: str, hosts: frozenset[str], resolve: Resolver
) -> tuple[str | None, list[str] | None]:
    """The production host ``host`` points at (None if none), and every address it stands for."""
    literal = _normalise(host)
    if literal in hosts:
        return literal, [literal]
    addresses = _addresses(host, resolve)
    return next((ip for ip in addresses or () if ip in hosts), None), addresses


def _is_loopback(address: str) -> bool:
    ip = _ip(address)
    return ip is not None and ip.is_loopback


def _without_comment(line: str) -> str:
    return line.split(" #", 1)[0] if not line.lstrip().startswith("#") else ""


def _url_host(url: str) -> str | None:
    try:
        host = urllib.parse.urlsplit(url.strip().strip("'\"")).hostname
    except ValueError:
        return None
    return host or None


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def configured_hosts(root: Path = _ROOT, environ: Mapping[str, str] = os.environ) -> frozenset[str]:
    """The hosts of the production SIEM as the checkout at ``root`` configures them: every URL's
    host and every IPv4 address in config/local.yaml (the installation's own values, D-294; not a
    network written with its /prefix, nor the web unit's bind-all address, D-295), the
    URL hosts of config/argus.yaml, and siem.url, kibana.url and incident.kibana_url as .env and
    the environment set them (ARGUS_SIEM__URL, ...). Loopback hosts are left out: tests run their
    own servers there. Read as text, so any Python can run it; a file that is missing adds nothing.
    """
    found: set[str] = set()
    local = "\n".join(map(_without_comment, _read(root / "config" / "local.yaml").splitlines()))
    found.update(filter(None, (_url_host(url) for url in _URL.findall(local))))
    found.update(_IPV4_TEXT.findall(local))
    shipped = "\n".join(map(_without_comment, _read(root / "config" / "argus.yaml").splitlines()))
    found.update(filter(None, (_url_host(url) for url in _URL.findall(shipped))))
    values = [value for name, value in environ.items() if name.upper() in _URL_SETTINGS]
    for line in _read(root / ".env").splitlines():
        name, sep, value = line.strip().removeprefix("export ").partition("=")
        if sep and name.strip().upper() in _URL_SETTINGS:
            values.append(_without_comment(value))
    found.update(filter(None, (_url_host(value) for value in values)))
    return frozenset(
        _normalise(host)
        for host in found
        if not _is_loopback(host) and host not in _LOOPBACK_NAMES and host != _UNSPECIFIED
    )


PRODUCTION_HOSTS = configured_hosts()


def production_target(
    address: object, hosts: Iterable[str] = PRODUCTION_HOSTS, resolve: Resolver = socket.getaddrinfo
) -> str | None:
    """The production host a socket address such as ``(host, port)`` points at, or None."""
    if not isinstance(address, tuple) or not address:
        return None
    host = _host_text(address[0])
    if host is None:
        return None
    return _production_hit(host, frozenset(hosts), resolve)[0]


def check_host(host: object, hosts: Iterable[str], resolve: Resolver = socket.getaddrinfo) -> None:
    """Raise unless a connection to ``host`` stays on loopback and off production."""
    text = _host_text(host)
    if text is None:
        raise NetworkAccessBlockedError(
            f"test tried to connect to host {host!r}, which the network guard cannot read"
        )
    hit, addresses = _production_hit(text, frozenset(hosts), resolve)
    if hit is not None:
        raise ProductionAccessBlockedError(
            f"test tried to reach the production SIEM ({hit}); only live tests "
            "(tests/live/, run with --run-live) may"
        )
    if not addresses or not all(_is_loopback(ip) for ip in addresses):
        raise NetworkAccessBlockedError(
            f"test tried to reach {text!r}, which is not a loopback address; tests may only use "
            "127.0.0.0/8, ::1 and Unix sockets (live tests in tests/live/, run with --run-live, "
            "are exempt)"
        )


def check_libpq_target(host: str, hostaddr: str, hosts: Iterable[str]) -> None:
    """Raise unless libpq, given these ``host``/``hostaddr`` values, stays on this machine.

    libpq connects to each ``hostaddr`` entry, or to the ``host`` entry beside an empty one; an
    empty host, or one starting with '/' or '@', is a Unix-domain socket.
    """
    names = host.split(",") if host else []
    addrs = hostaddr.split(",") if hostaddr else []
    if names and addrs and len(names) != len(addrs):
        targets = names + addrs  # libpq refuses the mismatch; check every value anyway
    else:
        targets = [addr or name for addr, name in itertools.zip_longest(addrs, names, fillvalue="")]
    for target in (t.strip() for t in targets):
        if target and not target.startswith(("/", "@")):
            check_host(target, hosts)


# --------------------------------------------------------------------------- command lines

_TOKEN_SEPARATOR = re.compile(r"[^0-9A-Za-z.]+")
# Splits text into runs of hex digits, dots and ':'. A run with two or more ':' is an IPv6
# literal such as ::ffff:a14:3c0b, or not. Splitting reads each character once; a regex for the
# runs would re-scan a long one from each of its positions (quadratic) unless its quantifiers were
# possessive, which Python 3.10 cannot compile.
_IPV6_SEPARATOR = re.compile(r"[^0-9A-Fa-f.:]+")
# Unicode's Default_Ignorable_Code_Point characters: IDNA drops those it allows from a host name
# (soft hyphen, zero-width space and joiners, word joiner, BOM, variation selectors, ...).
_IGNORABLE = re.compile(
    "[\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180b-\u180f\u200b-\u200f\u202a-\u202e"
    "\u2060-\u206f\u3164\ufe00-\ufe0f\ufeff\uffa0\ufff0-\ufff8\U0001bca0-\U0001bca3"
    "\U0001d173-\U0001d17a\U000e0000-\U000e0fff]+"
)
# The full stops IDNA reads as '.': ideographic, fullwidth and halfwidth ideographic.
_FULL_STOPS = str.maketrans(dict.fromkeys("\u3002\uff0e\uff61", "."))
# Where a host name stands on a command line: at the start of a word, after user@, '=', a quote,
# a comma, a semicolon or ':' (curl --connect-to ::host:port), after a URL's //, in bash's
# /dev/tcp/<host>/<port>, or glued to a one-letter option (ssh -J<host>).
_HOST_POSITION = r"(?:^|[\s@'\"=,;:]|//|/dev/(?:tcp|udp)/|(?:^|\s)-[A-Za-z])"


def _strings(value: object) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, (bytes, bytearray)):
        yield bytes(value).decode("utf-8", "replace")
    elif isinstance(value, os.PathLike):
        yield from _strings(os.fspath(value))
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _strings(item)


def _c_ipv4(text: str) -> str | None:
    """The IPv4 address the C library reads ``text`` as (inet_aton), or None."""
    if not text[:1].isdigit():
        return None
    try:
        return socket.inet_ntoa(socket.inet_aton(text))
    except (OSError, ValueError):
        return None


def _numeric_addresses(text: str) -> Iterator[str]:
    """Addresses ``text`` spells as numbers other than a plain dotted quad, normalised.

    IPv4 forms are read the way the C library reads them (integer, hex, octal and short dotted
    forms of 10.20.60.11: 169098251, 0xa143c0b, 012.024.074.013, 10.1326091), and IPv6 literals
    by ``ipaddress`` (an IPv4-mapped one such as ::ffff:a14:3c0b counts as its IPv4 address).
    """
    for token in _TOKEN_SEPARATOR.split(text):
        for candidate in {token, token.lstrip(string.ascii_letters)}:  # -h169098251: glued value
            address = _c_ipv4(candidate)
            if address is not None:
                yield address
    for run in _IPV6_SEPARATOR.split(text):
        if run.count(":") >= 2 and _ip(run) is not None:
            yield _normalise(run)


def _as_host_text(text: str) -> str:
    """``text`` as curl reads a URL's host before it resolves it, in time linear in its length.

    Percent-escapes are decoded once, then IDNA's mapping is applied as far as it can make an
    address: NFKC compatibility forms (fullwidth digits and letters, circled numbers), the
    ideographic full stops as '.', and default-ignorable characters dropped.
    """
    if text.isascii() and "%" not in text:
        return text
    mapped = unicodedata.normalize("NFKC", urllib.parse.unquote(text)).translate(_FULL_STOPS)
    return _IGNORABLE.sub("", mapped)


def _named_host(text: str, targets: set[str], names: set[str]) -> str | None:
    for address in sorted(targets - names):
        if re.search(rf"(?<!\d){re.escape(address)}(?!\d)", text, re.IGNORECASE):
            return address
    hit = next((address for address in _numeric_addresses(text) if address in targets), None)
    if hit is not None:
        return hit
    for name in sorted(names):
        if re.search(rf"{_HOST_POSITION}{re.escape(name)}(?![\w-])", text, re.IGNORECASE):
            return name
    return None


def command_target(command: object, hosts: Iterable[str]) -> str | None:
    """The production host or alias a command line names, or None.

    An IPv4 address counts wherever no digit touches it, so /dev/tcp/<ip>/9200, -h<ip>,
    es:9200:<ip>, [::ffff:<ip>], user@[<ip>] and <ip>.nip.io count while 110.20.60.11 and
    10.20.60.110 do not (for 10.20.60.11); so do the other numeric forms of it that the C
    library accepts (see _numeric_addresses). A host name such as 'siemhost' counts only in host
    position (see _HOST_POSITION), so tests/live/test_siemhost_health.py and
    /var/log/siemhost.log do not. The command line is read as it is and as curl reads a host (see
    _as_host_text), so
    10.20.60.%31%31, fullwidth digits, ideographic full stops and a zero-width space inside the
    address count as well.
    """
    text = "\n".join(_strings(command))
    targets = {_normalise(host) for host in hosts}
    names = {host for host in targets if _ip(host) is None}
    hit = _named_host(text, targets, names)
    if hit is None:
        host_text = _as_host_text(text)
        if host_text != text:
            hit = _named_host(host_text, targets, names)
    return hit


# --------------------------------------------------------------------------- hooks


def audit_hook(event: str, args: tuple[Any, ...]) -> None:
    """``sys.addaudithook`` callback: raising refuses the operation before it happens."""
    if not STATE["active"]:
        return
    if event in _SOCKET_EVENTS:
        _check_socket(event, args[0], args[1])
    elif event in _COMMAND_ARGS:
        _check_command(event, args)


def _check_socket(event: str, sock: object, address: object) -> None:
    if address is None:  # sendmsg() on a connected socket: its connect() was checked
        return
    family = getattr(sock, "family", None)
    if _AF_UNIX is not None and family == _AF_UNIX:
        return
    if (family is not None and family not in _INET_FAMILIES) or not isinstance(address, tuple):
        raise NetworkAccessBlockedError(
            f"test tried {event} to {address!r} (address family {family}); tests may only use "
            "loopback and Unix sockets"
        )
    check_port(address)
    check_host(address[0] if address else None, _hosts())


def check_port(address: tuple[Any, ...]) -> None:
    """Raise if a socket address names a production port (the local LLM's tunnel)."""
    port = address[1] if len(address) > 1 else None
    if isinstance(port, int) and not isinstance(port, bool) and port in PRODUCTION_PORTS:
        raise ProductionAccessBlockedError(
            f"test tried to reach port {port}, the local LLM's tunnel to the model machine "
            "(production, D-108); tests run their own TLS server on another port"
        )


def _loopback_token(token: str) -> bool:
    """Whether a command-line word names this machine (as the C library would read it)."""
    for part in {token, token.strip("[]"), *re.split(r"[:/@]", token)}:
        word = part.strip("[]").lower()
        if word in _LOOPBACK_NAMES or word == "0.0.0.0":  # noqa: S104 - a word, not a bind
            return True
        found = _ip(word) or _ip(_c_ipv4(word) or "")
        if found is None:
            continue
        mapped = getattr(found, "ipv4_mapped", None)
        if found.is_loopback or (mapped is not None and mapped.is_loopback):
            return True
    return False


def _tunnel_in_command(command: object) -> str | None:
    text = "\n".join(_strings(command))
    found = _PORT_IN_COMMAND.search(text)
    if found is not None:
        return f"port {found.group(1)}"
    words = [w for w in _COMMAND_TOKENS.split(text) if w]
    if any(str(port) in words for port in PRODUCTION_PORTS) and any(map(_loopback_token, words)):
        return "port " + ", ".join(str(p) for p in sorted(PRODUCTION_PORTS) if str(p) in words)
    return None


def _check_command(event: str, args: tuple[Any, ...]) -> None:
    command = [args[i] for i in _COMMAND_ARGS[event] if i < len(args)]
    target = command_target(command, _hosts())
    what = "the production SIEM"
    if target is None:
        target = _tunnel_in_command(command)
        what = "the local LLM's tunnel"
    if target is None:
        return
    message = (
        f"test tried to start a process aimed at {what} ({target}) via {event}; "
        "only live tests (tests/live/, run with --run-live) may"
    )
    if event == "os.exec" and os.getpid() != _PID:
        # A forked child about to exec: raising would unwind into the parent's code (pytest).
        os.write(2, message.encode() + b"\n")
        os._exit(126)
    raise ProductionAccessBlockedError(message)


def _os_user() -> str:
    """The operating-system user: libpq's default user name, and so its default database."""
    try:
        import pwd

        return pwd.getpwuid(os.geteuid()).pw_name
    except (ImportError, AttributeError, KeyError, OSError):  # not POSIX, or no passwd entry
        return ""


def _libpq_ports(value: str) -> set[int]:
    """The server ports libpq tries for this ``port`` value: one per host, empty meaning 5432.

    An entry libpq cannot read as a number stops it before it connects, so it adds nothing.
    """
    ports = set()
    for entry in value.split(","):
        try:
            ports.add(int(entry) if entry.strip() else _LIBPQ_DEFAULT_PORT)
        except ValueError:
            continue
    return ports


def _check_psycopg_connect(conninfo: str, kwargs: Mapping[str, Any]) -> None:
    from psycopg import Error
    from psycopg.conninfo import conninfo_to_dict

    try:
        params: dict[str, Any] = conninfo_to_dict(conninfo)
    except Error:
        return  # connect() rejects this conninfo itself, before any network I/O
    params.update({key: kwargs[key] for key in _LIBPQ_TARGET_KEYS if kwargs.get(key) is not None})

    def param(name: str, env: str) -> str:  # libpq falls back to the PG* variables
        return str(params[name]) if name in params else os.environ.get(env, "")

    service = param("service", "PGSERVICE")
    if service:
        raise NetworkAccessBlockedError(
            f"test tried to connect through the libpq service {service!r}; a service file can "
            "point anywhere, so tests must give host or hostaddr instead"
        )
    check_libpq_target(param("host", "PGHOST"), param("hostaddr", "PGHOSTADDR"), _hosts())
    # libpq's database: dbname, else PGDATABASE, else the user (user, else PGUSER, else the OS
    # user). An empty value counts as not given.
    database = param("dbname", "PGDATABASE") or param("user", "PGUSER") or _os_user()
    protected = _databases()
    for port in sorted(_libpq_ports(param("port", "PGPORT"))):
        if port in PRODUCTION_PORTS:
            raise ProductionAccessBlockedError(
                f"test tried to connect psycopg to port {port}, the local LLM's tunnel to the "
                "model machine (production, D-108)"
            )
        if (database, port) in protected:
            raise NetworkAccessBlockedError(
                f"test tried to connect to the database {database!r} on port {port}, the "
                "developer's own; tests use throwaway databases (tests/integration/conftest.py)"
            )


def _psycopg_refusal(conninfo: str, kwargs: Mapping[str, Any]) -> NetworkAccessBlockedError | None:
    """Why the guard refuses this psycopg connection, or None.

    Returned, never raised: the caller holds the connection parameters and must drop them before
    it raises (see _guarded_connect). A connection the guard cannot check is refused.
    """
    if not STATE["active"]:
        return None
    try:
        _check_psycopg_connect(conninfo, kwargs)
    except NetworkAccessBlockedError as refusal:
        return refusal
    except Exception as exc:
        return NetworkAccessBlockedError(
            f"the network guard could not check this psycopg connection ({type(exc).__name__})"
        )
    return None


def _guarded_connect(connect: Callable[..., Any]) -> Callable[..., Any]:
    """``connect`` (the body of psycopg's connect classmethod), checked by the guard first.

    The connection parameters hold the password, and pytest prints the arguments of a traceback's
    innermost frame (of every frame with --tb=long, and the locals with --showlocals). So
    whatever stops the connection, the guard or psycopg itself, is raised from here after the
    parameters are deleted, without psycopg's frames and without the guard's.
    """
    import functools
    import inspect

    if inspect.iscoroutinefunction(connect):

        @functools.wraps(connect)
        async def checked_async(cls: type, conninfo: str = "", **kwargs: Any) -> Any:
            failure: BaseException | None = _psycopg_refusal(conninfo, kwargs)
            if failure is None:
                try:
                    return await connect(cls, conninfo, **kwargs)
                except BaseException as exc:
                    failure = exc
            del conninfo, kwargs
            raise failure.with_traceback(None)

        checked: Callable[..., Any] = checked_async
    else:

        @functools.wraps(connect)
        def checked_sync(cls: type, conninfo: str = "", **kwargs: Any) -> Any:
            failure: BaseException | None = _psycopg_refusal(conninfo, kwargs)
            if failure is None:
                try:
                    return connect(cls, conninfo, **kwargs)
                except BaseException as exc:
                    failure = exc
            del conninfo, kwargs
            raise failure.with_traceback(None)

        checked = checked_sync
    checked._argus_netguard = True  # type: ignore[attr-defined]
    return checked


def guard_psycopg(psycopg: Any) -> None:
    """Check the target of every psycopg connection before libpq opens a socket."""
    for cls in (psycopg.Connection, psycopg.AsyncConnection):
        original = cls.__dict__.get("connect")
        if not isinstance(original, classmethod):
            raise RuntimeError(
                f"network guard: psycopg's {cls.__name__}.connect is no longer a classmethod; "
                "update tests/_guard/argus_netguard.py"
            )
        if not getattr(original.__func__, "_argus_netguard", False):
            cls.connect = classmethod(_guarded_connect(original.__func__))
    psycopg.connect = psycopg.Connection.connect  # the module alias was bound at import time


class _GuardPsycopgOnImport(MetaPathFinder):
    """Guards psycopg the moment it is imported; a process may import it late, or never."""

    def find_spec(
        self, fullname: str, path: Any, target: ModuleType | None = None
    ) -> ModuleSpec | None:
        if fullname != "psycopg":
            return None
        spec: ModuleSpec | None = None
        for finder in sys.meta_path:
            find_spec = getattr(finder, "find_spec", None)
            if finder is not self and find_spec is not None:
                spec = find_spec(fullname, path, target)
                if spec is not None:
                    break
        if spec is None:
            return None
        loader: Any = spec.loader
        exec_module = getattr(loader, "exec_module", None)
        if exec_module is None:
            raise ImportError("network guard: cannot hook the loader of psycopg")

        def exec_and_guard(module: ModuleType) -> None:
            exec_module(module)
            guard_psycopg(module)

        loader.exec_module = exec_and_guard  # this loader object belongs to this spec only
        return spec


# --------------------------------------------------------------------------- installation


def install(
    production_hosts: Hosts = _default_production_hosts,
    protected_databases: Databases | None = None,
) -> None:
    """Install the guard in this process once (audit hooks cannot be removed) and switch it on.

    ``production_hosts`` and ``protected_databases`` ((name, port) pairs psycopg must not
    connect to; None keeps the current ones) are called at every check, so what they return may
    change.
    """
    global _production_hosts, _protected_databases
    _production_hosts = production_hosts
    if protected_databases is not None:
        _protected_databases = protected_databases
    if not STATE["installed"]:
        sys.addaudithook(audit_hook)
        if "psycopg" in sys.modules:
            guard_psycopg(sys.modules["psycopg"])
        else:
            sys.meta_path.insert(0, _GuardPsycopgOnImport())
        STATE["installed"] = True
    STATE["active"] = True


def set_active(active: bool) -> None:
    """Switch the guard on or off; a locked guard stays on."""
    STATE["active"] = active or STATE["locked"]


def run_in_progress() -> bool:
    """Whether a pytest run is configured in this process (begin_run without its end_run)."""
    return bool(_RUNS)


def begin_run(owner: object, production_hosts: Hosts, protected_databases: Databases) -> None:
    """A pytest run is being configured in this process (pytest_configure): install its settings.

    What the run changes is saved for end_run(owner): the guard's settings and lock, and the
    variables that describe the guard to child processes. A run begun while another run's test is
    running here (pytest.main() in a test) is nested in that test: unless that test runs without
    the guard (a live test), the guard is locked on until the nested run ends.
    """
    nested_in_guarded_test = bool(_RUNS) and STATE["active"]
    _RUNS.append(
        _Run(
            owner,
            {name: os.environ.get(name) for name in _RUN_VARIABLES},
            STATE["active"],
            STATE["locked"],
            _production_hosts,
            _protected_databases,
        )
    )
    install(production_hosts, protected_databases)
    if nested_in_guarded_test:
        STATE["locked"] = True


def end_run(owner: object) -> None:
    """The run begun by begin_run(owner) ended (pytest_unconfigure): restore what it changed.

    Does nothing unless that run is the innermost one (its configuration failed before begin_run,
    say).
    """
    global _production_hosts, _protected_databases
    if not _RUNS or _RUNS[-1].owner is not owner:
        return
    run = _RUNS.pop()
    for name, value in run.environment.items():
        if value is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = value
    _production_hosts, _protected_databases = run.production_hosts, run.protected_databases
    STATE["locked"] = run.locked
    STATE["active"] = run.active or run.locked


def describe() -> str:
    """The guard's current settings for child processes (the value of ENV_VAR)."""
    return json.dumps(
        {
            "active": STATE["active"],
            "production_hosts": sorted(_hosts()),
            "protected_databases": sorted(_databases()),
        }
    )


def _hosts_from(value: object) -> frozenset[str]:
    if not isinstance(value, list) or not all(isinstance(host, str) for host in value):
        raise TypeError("production_hosts: expected a list of strings")
    return frozenset(value)


def _databases_from(value: object) -> frozenset[tuple[str, int]]:
    if not isinstance(value, list):
        raise TypeError("protected_databases: expected a list of [name, port] pairs")
    pairs = set()
    for pair in value:
        if not (
            isinstance(pair, list)
            and len(pair) == 2
            and isinstance(pair[0], str)
            and isinstance(pair[1], int)
        ):
            raise TypeError("protected_databases: expected a list of [name, port] pairs")
        pairs.add((pair[0], pair[1]))
    return frozenset(pairs)


def install_from_environment() -> None:
    """Install the guard the way the parent process described it in ENV_VAR.

    The sitecustomize entry point. Missing or unreadable settings mean the guard is on. A guard
    inherited switched on is locked on, so a nested pytest run that a guarded test starts with
    --run-live stays guarded: only a parent that had switched the guard off (a live test) starts
    children without it.
    """
    global _inherited_hosts, _inherited_databases
    try:
        settings = json.loads(os.environ.get(ENV_VAR) or "{}")
        hosts = _hosts_from(settings.get("production_hosts", []))
        databases = _databases_from(settings.get("protected_databases", []))
        active = settings.get("active", True) is not False
    except (ValueError, TypeError, AttributeError):
        hosts, databases, active = frozenset(), frozenset(), True
    _inherited_hosts, _inherited_databases = hosts, databases
    install()
    STATE["active"] = active
    STATE["locked"] = active

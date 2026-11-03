"""Whether the agents' files and their pins are still as approved (Q-H1): ``argus doctor``
warns when they are not, since an edited file and its new pin in code are consistent with
each other, and only an approval says they are wanted.

Each pin names the git tag that approves its version (``Pin.approved``: ``q-<id>-approved``).
The files are compared with the nearest of those tags HEAD descends from, never with another
approval tag: under Phase 3's streams (D-110) one component's approval tag sits on a tree
that may hold another component's agents, not approved yet. A pin whose tag is not in HEAD's
history is named as waiting for its approval. What is compared is what is on disk now,
uncommitted edits, new files and deletions included: everything under ``config/agents/`` but
hidden files, on disk and in the tag alike (the loader ignores them too), and
``src/argus/agent/registry.py`` (bindings, pins, enabled versions, gold run ids). Git's output
is decoded as file names are (UTF-8, any other byte kept), so a name that is not UTF-8 is
compared like any other.

Git only reads refs and objects here (``rev-parse``, ``tag``, ``describe``, ``ls-tree``): it
never looks at the working tree, so nothing a checkout configures (an fsmonitor hook, a clean
filter, a diff driver) can run. The files on disk are hashed as git blobs in Python, and only
those of their tagged size (any other size has changed): nothing is read whole, and a pipe
or a device is never waited on. A copy that is not a git checkout (a deployed tag) cannot
tell, and says so.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import subprocess
from collections.abc import Callable, Collection, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from argus.agent.registry import PINS, Pin

ROOT = Path(__file__).resolve().parents[3]
WATCHED = ("config/agents", "src/argus/agent/registry.py")
TAG = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}-approved")
TIMEOUT_S = 10.0
CHUNK = 64 * 1024

Run = Callable[[Sequence[str]], str]  # git's arguments -> its standard output; raises GitError


class GitError(Exception):
    pass


@dataclass(frozen=True)
class Drift:
    tag: str | None  # the nearest approval tag the pins name, or None when it cannot be told
    changed: tuple[str, ...] = ()  # watched paths that differ from it (repository-relative)
    why: str | None = None  # why it cannot be told
    waiting: tuple[str, ...] = ()  # approval tags pins name that HEAD's history lacks


def _env() -> dict[str, str]:
    """The caller's environment without any GIT_* (a GIT_DIR would point elsewhere), with
    git's optional locks off and its messages in English."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_OPTIONAL_LOCKS="0", LC_ALL="C", GIT_TERMINAL_PROMPT="0")
    return env


def _text(data: bytes) -> str:
    """git's output as text, decoded as file names are (UTF-8, any other byte kept as
    os.fsdecode keeps it) and with no newline translated: a name may hold a carriage return."""
    return data.decode("utf-8", "surrogateescape")


def git(root: Path = ROOT) -> Run:
    executable = shutil.which("git")

    def run(args: Sequence[str]) -> str:
        if executable is None:
            raise GitError("git is not installed")
        try:
            done = subprocess.run(  # noqa: S603 - a fixed program and arguments, no shell
                [executable, "-C", str(root), "-c", "core.fsmonitor=false", *args],
                capture_output=True,
                timeout=TIMEOUT_S,
                env=_env(),
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise GitError(f"git did not answer ({type(exc).__name__})") from None
        if done.returncode != 0:
            first = (_text(done.stderr).strip().splitlines() or ["no message"])[0]
            raise GitError(first[:200])
        return _text(done.stdout)

    return run


def blob_id(data: bytes, algorithm: str = "sha1") -> str:
    """The id git gives a blob of ``data``."""
    return hashlib.new(algorithm, b"blob %d\0" % len(data) + data).hexdigest()


def approvals(pins: Mapping[str, Mapping[str, Pin]] = PINS) -> frozenset[str]:
    """The approval tags the pins name."""
    return frozenset(pin.approved for versions in pins.values() for pin in versions.values())


def _tagged(listing: str) -> dict[str, tuple[str, int]]:
    """``ls-tree -r -z -l`` output: path -> (object id, size) of each blob (files and links;
    nothing else is ours)."""
    out = {}
    for entry in listing.split("\0"):
        if not entry:
            continue
        meta, _, path = entry.partition("\t")
        parts = meta.split()
        if len(parts) == 4 and parts[1] == "blob" and parts[3].isdigit():
            out[path] = (parts[2], int(parts[3]))
    return out


def _blob_of_file(path: Path, size: int, algorithm: str) -> str | None:
    """The blob id of the regular file at ``path`` if it holds exactly ``size`` bytes, read in
    chunks, at most ``size`` + 1 bytes; None when it is not a regular file of that size by the
    time it is read (a link is refused when opened, a pipe is never waited on)."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            return None
        digest = hashlib.new(algorithm, b"blob %d\0" % size)
        read = 0
        while read <= size:
            chunk = handle.read(min(CHUNK, size + 1 - read))
            if not chunk:
                break
            digest.update(chunk)
            read += len(chunk)
    return digest.hexdigest() if read == size else None


def _hidden(rel: str) -> bool:
    return any(part.startswith(".") for part in rel.split("/"))


def _watched(root: Path) -> list[Path]:
    """The watched paths on disk, files and links (hidden ones are not ours)."""
    out: list[Path] = []
    for watched in WATCHED:
        path = root / watched
        if path.is_dir() and not path.is_symlink():
            for directory, dirs, files in os.walk(path):
                dirs[:] = sorted(d for d in dirs if not d.startswith("."))
                out += [Path(directory) / n for n in sorted(files) if not n.startswith(".")]
        elif path.exists() or path.is_symlink():
            out.append(path)
    return out


def _changed(root: Path, algorithm: str, tagged: Mapping[str, tuple[str, int]]) -> set[str]:
    """The watched paths whose content on disk is not the tagged blob (a link is its target,
    as git stores it); a tagged path no longer a file or a link on disk has changed too.
    Hidden paths are not ours on either side."""
    tagged = {rel: blob for rel, blob in tagged.items() if not _hidden(rel)}
    changed: set[str] = set()
    present: set[str] = set()
    for path in _watched(root):
        rel = path.relative_to(root).as_posix()
        found = path.lstat()
        known = tagged.get(rel)
        if stat.S_ISLNK(found.st_mode):
            target = os.fsencode(os.readlink(path))
            got = (blob_id(target, algorithm), len(target))
        elif stat.S_ISREG(found.st_mode):
            size = found.st_size
            same_size = known is not None and known[1] == size
            got = ((_blob_of_file(path, size, algorithm) or "") if same_size else "", size)
        else:
            continue  # a pipe, a socket: nothing git keeps
        present.add(rel)
        if got != known:
            changed.add(rel)
    return changed | (set(tagged) - present)


def since_approved(
    run: Run | None = None, root: Path = ROOT, tags: Collection[str] | None = None
) -> Drift:
    """The nearest approval tag the pins name (``tags``), the watched paths changed since it,
    and the approval tags HEAD's history lacks."""
    run = run or git(root)
    wanted = sorted(approvals() if tags is None else set(tags))
    if not wanted or not all(TAG.fullmatch(t) for t in wanted):
        # each becomes an argument: never anything an option could be
        return Drift(None, why="a pin names no plain approval tag (q-<id>-approved)")
    try:
        if run(["rev-parse", "--is-inside-work-tree"]).strip() != "true":
            return Drift(None, why="not a git checkout")
    except GitError as exc:
        return Drift(None, why=f"not a git checkout ({exc})")
    try:
        reachable = set(run(["tag", "--list", "--merged", "HEAD", *wanted]).split()) & set(wanted)
    except GitError as exc:
        return Drift(None, why=f"could not list the approval tags ({exc})")
    waiting = tuple(t for t in wanted if t not in reachable)
    if not reachable:
        return Drift(None, why="no approval tag of the pins in this checkout's history",
                     waiting=waiting)  # fmt: skip
    matches = [arg for t in wanted if t in reachable for arg in ("--match", t)]
    try:
        tag = run(["describe", "--tags", "--abbrev=0", *matches, "HEAD"]).strip()
    except GitError as exc:
        return Drift(None, why=f"could not find the nearest approval tag ({exc})", waiting=waiting)
    if tag not in reachable:  # it becomes an argument: only a name it was asked about
        return Drift(None, why="git named another tag", waiting=waiting)
    try:
        algorithm = run(["rev-parse", "--show-object-format"]).strip() or "sha1"
        if algorithm not in ("sha1", "sha256"):
            raise GitError(f"object format {algorithm[:20]}")
        tagged = _tagged(run(["ls-tree", "-r", "-z", "-l", "--full-tree", tag, "--", *WATCHED]))
        changed = _changed(root, algorithm, tagged)
    except (GitError, OSError) as exc:
        return Drift(tag, why=f"could not compare with {tag} ({exc})", waiting=waiting)
    return Drift(tag, tuple(sorted(changed)), waiting=waiting)

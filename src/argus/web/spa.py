"""The single-page app at ``/app``, served from its committed build (``frontend/`` builds into this
package's ``spa/`` folder, which is in git, so a deploy needs no Node).

The page (``/app`` and every path under it that is not a file) is ``index.html`` for a signed-in
person with the view capability, ``Cache-Control: no-cache``. Its files (``/app/assets/<hashed
name>``) are code and styles with no data, immutable for a year; a missing one is a 404, never the
page. The policy is the site's CSP plus Trusted Types, so no string can become markup or script.
The build's id goes out as ``X-Argus-Build`` on /app and /api answers; the page compares it with its
own."""

from __future__ import annotations

import gzip
import re
from dataclasses import dataclass
from pathlib import Path

from argus.web import security

BUILD_DIR = Path(__file__).parent / "spa"
PREFIX = "/app"
CSP_APP = security.CSP + "; require-trusted-types-for 'script'; trusted-types 'none'"
IMMUTABLE = "public, max-age=31536000, immutable"
REVALIDATE = "no-cache"
BUILD_HEADER = "X-Argus-Build"
# a file name Vite writes (name-hash.ext), nothing that can climb out of the folder
_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,199}")
TYPES = {
    ".js": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".svg": "image/svg+xml",
    ".woff2": "font/woff2",
    ".png": "image/png",
}
_COMPRESS = frozenset({".js", ".css", ".svg"})
ROOT_FILES = frozenset({"favicon.svg"})  # frontend/public: served at /app/<name>
# paths under /app (the part after "/app/") that name a file: never answered with the page.
# The build's assets/ folder only, at the start ( a route may hold "assets"), or a
# name ending in a file extension.
FILE_LIKE = re.compile(r"^assets(?:/|$)|\.(?:js|mjs|css|map|svg|png|ico|woff2?|json|txt|html?)$")
_META = re.compile(rb'<meta name="argus-build" content="([0-9a-f]{16})"')


def is_app_path(path: str) -> bool:
    return path == PREFIX or path.startswith(PREFIX + "/")


def accepts_gzip(header: str | None) -> bool:
    """Whether an Accept-Encoding header allows gzip (``gzip;q=0`` refuses it)."""
    for part in (header or "").lower().split(","):
        name, _, params = part.strip().partition(";")
        if name.strip() not in ("gzip", "*"):
            continue
        q = params.strip()
        if q.startswith("q="):
            try:
                return float(q[2:]) > 0
            except ValueError:
                return False
        return True
    return False


@dataclass(frozen=True)
class Index:
    body: bytes
    build: str | None


@dataclass(frozen=True)
class File:
    body: bytes
    media_type: str
    gzipped: bytes | None  # the gzip of body, for the types worth compressing


class Build:
    """One build folder: its page and files, read once per change of the file on disk."""

    def __init__(self, root: Path = BUILD_DIR) -> None:
        self.root = root
        self._index: tuple[tuple[int, int], Index] | None = None
        self._files: dict[str, tuple[tuple[int, int], File]] = {}

    @staticmethod
    def _stamp(path: Path) -> tuple[int, int] | None:
        try:
            stat = path.stat()
        except OSError:
            return None
        return (stat.st_mtime_ns, stat.st_size)

    def index(self) -> Index | None:
        path = self.root / "index.html"
        stamp = self._stamp(path)
        if stamp is None:
            return None
        if self._index is not None and self._index[0] == stamp:
            return self._index[1]
        try:
            body = path.read_bytes()
        except OSError:
            return None
        found = _META.search(body)
        index = Index(body, found.group(1).decode() if found else None)
        self._index = (stamp, index)
        return index

    def build_id(self) -> str | None:
        index = self.index()
        return None if index is None else index.build

    def file(self, relative: str) -> File | None:
        """A file of the build (``assets/<name>`` or a root file), or None."""
        folder, _, name = relative.rpartition("/")
        if folder not in ("", "assets") or not _NAME.fullmatch(name) or ".." in name:
            return None
        if folder == "" and name not in ROOT_FILES:
            return None
        suffix = Path(name).suffix
        media = TYPES.get(suffix)
        if media is None:
            return None
        path = self.root / relative
        stamp = self._stamp(path)
        if stamp is None or not path.is_file():
            return None
        cached = self._files.get(relative)
        if cached is not None and cached[0] == stamp:
            return cached[1]
        try:
            body = path.read_bytes()
        except OSError:
            return None
        packed = gzip.compress(body, compresslevel=9, mtime=0) if suffix in _COMPRESS else None
        made = File(body, media, packed)
        self._files[relative] = (stamp, made)
        return made

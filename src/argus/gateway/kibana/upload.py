"""A case file as the Kibana lane sends it (AR8, D-157): ``POST api/cases/{case}/files``, multipart.

The runbook's call (docs/runbooks/kibana-incident-case.md): a field ``file`` (the bytes, with the
file's own name and type) and a field ``filename`` **without the extension**. The lane builds the
body itself, byte for byte, from a strict model, and the validator reads the exact bytes back with
:func:`decode` and builds them again: a body that is not what :func:`encode` makes is refused. The
boundary is a hash of the content, so the same file is the same request (its hash is what an
approval binds, and what a resume compares).

Only the two types of the hand-made case go (a PDF and a CSV), under 5 MiB, under a plain name.
"""

from __future__ import annotations

import hashlib
import re
from typing import Annotated, Any, Final, Literal, cast

from pydantic import BaseModel, ConfigDict, Field, field_validator

MAX_FILE_BYTES: Final = 5 * 1024 * 1024
MAX_BODY_BYTES: Final = MAX_FILE_BYTES + 4096
EXTENSION: Final = {"application/pdf": "pdf", "text/csv": "csv"}
NAME: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,120}")
_CRLF = b"\r\n"


class FileUpload(BaseModel):
    """One file: ``filename`` has no extension (Kibana takes it from the part's own name)."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    filename: Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,120}$")]
    mime: Literal["application/pdf", "text/csv"]
    data: Annotated[bytes, Field(min_length=1, max_length=MAX_FILE_BYTES)]

    @field_validator("filename")
    @classmethod
    def _plain(cls, value: str) -> str:
        if not NAME.fullmatch(value):  # Python's own full match: no newline slips past a "$"
            raise ValueError("a file name is plain: letters, digits, dot, dash and underscore")
        return value

    @property
    def full_name(self) -> str:
        return f"{self.filename}.{EXTENSION[self.mime]}"

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.data).hexdigest()


def boundary_of(upload: FileUpload) -> str:
    seed = f"{upload.filename}\0{upload.mime}\0".encode() + upload.data
    return "argus-" + hashlib.sha256(seed).hexdigest()[:40]


def encode(upload: FileUpload) -> bytes:
    """The multipart body, the same bytes for the same file."""
    b = boundary_of(upload).encode("ascii")
    head = (
        b"--" + b + _CRLF
        + b'Content-Disposition: form-data; name="file"; filename="'
        + upload.full_name.encode("ascii") + b'"' + _CRLF
        + b"Content-Type: " + upload.mime.encode("ascii") + _CRLF + _CRLF
    )  # fmt: skip
    tail = (
        _CRLF + b"--" + b + _CRLF
        + b'Content-Disposition: form-data; name="filename"' + _CRLF + _CRLF
        + upload.filename.encode("ascii") + _CRLF + b"--" + b + b"--" + _CRLF
    )  # fmt: skip
    return head + upload.data + tail


def content_type(body: bytes) -> str:
    """The request's Content-Type, from the boundary on the body's first line."""
    first = body.split(_CRLF, 1)[0]
    if not re.fullmatch(rb"--argus-[0-9a-f]{40}", first):
        raise ValueError("not a body the lane built")
    return "multipart/form-data; boundary=" + first[2:].decode("ascii")


def decode(body: bytes) -> FileUpload:
    """The file a body carries; ValueError unless the body is exactly what :func:`encode` makes
    for it."""
    if len(body) > MAX_BODY_BYTES:
        raise ValueError("the body is larger than any file the lane sends")
    first, sep, rest = body.partition(_CRLF)
    if not sep or not re.fullmatch(rb"--argus-[0-9a-f]{40}", first):
        raise ValueError("not a body the lane built")
    disposition, sep, rest = rest.partition(_CRLF)
    found = re.fullmatch(
        rb'Content-Disposition: form-data; name="file"; filename="([A-Za-z0-9._-]{1,130})"',
        disposition,
    )
    if not sep or found is None:
        raise ValueError("the file part is not what the lane builds")
    kind, sep, rest = rest.partition(_CRLF)
    mime = kind.removeprefix(b"Content-Type: ").decode("ascii", "replace")
    if not sep or not kind.startswith(b"Content-Type: ") or mime not in EXTENSION:
        raise ValueError("the file's type is not a PDF or a CSV")
    blank, sep, rest = rest.partition(_CRLF)
    if not sep or blank:
        raise ValueError("the file part has no header end")
    marker = _CRLF + first + _CRLF + b'Content-Disposition: form-data; name="filename"'
    cut = rest.rfind(marker)
    if cut < 0:
        raise ValueError("the name field is missing")
    name = rest[cut + len(marker) :].removeprefix(_CRLF + _CRLF)
    name = name.removesuffix(_CRLF + first + b"--" + _CRLF)
    try:
        upload = FileUpload(
            filename=name.decode("ascii"),
            mime=cast(Any, mime),
            data=rest[:cut],
        )
    except ValueError as exc:
        raise ValueError(f"not a file the lane sends ({type(exc).__name__})") from None
    if encode(upload) != body or found.group(1).decode("ascii") != upload.full_name:
        raise ValueError("the body is not exactly the multipart the lane builds")
    return upload

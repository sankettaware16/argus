"""Q-H1: doctor warns when the agents' files or pins drift from the last approved tag. The
comparison with a fake git (every branch), then with real git on a throwaway repository
(committed, tagged, edited, a new file, a GIT_DIR pointing elsewhere), then the doctor check
and its WARN line."""

from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from argus import doctor
from argus.agent import drift, loader
from argus.agent.drift import Drift, GitError

# -- the comparison, with a fake git ------------------------------------------------------------

TAGS = {"q-h1-approved"}


class FakeGit:
    """Answers by the command's first two words; an Exception is raised."""

    def __init__(self, tree: str = "", **answers: str | Exception) -> None:
        self.answers = {"rev-parse --is-inside-work-tree": "true\n",
                        "rev-parse --show-object-format": "sha1\n", "ls-tree -r": tree,
                        "tag --list": "q-h1-approved\n", "describe": "q-h1-approved\n",
                        **answers}  # fmt: skip
        self.calls: list[list[str]] = []

    def __call__(self, args: Sequence[str]) -> str:
        self.calls.append(list(args))
        key = " ".join(args[:2]) if args[0] != "describe" else "describe"
        answer = self.answers.get(key, "")
        if isinstance(answer, Exception):
            raise answer
        return answer


def tree_of(root: Path) -> str:
    """What ``ls-tree -r -z -l`` says for the watched files as they are under ``root``."""
    out = []
    for path in drift._watched(root):
        rel = path.relative_to(root).as_posix()
        data = os.fsencode(os.readlink(path)) if path.is_symlink() else path.read_bytes()
        mode = "120000" if path.is_symlink() else "100644"
        out.append(f"{mode} blob {drift.blob_id(data)} {len(data):>7}\t{rel}\0")
    return "".join(out)


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    root = tmp_path / "root"
    (root / "config" / "agents").mkdir(parents=True)
    (root / "src" / "argus" / "agent").mkdir(parents=True)
    (root / "config" / "agents" / "web.md").write_text("web\n")
    (root / "src" / "argus" / "agent" / "registry.py").write_text("PINS = {}\n")
    return root


def test_unchanged_since_the_tag(tree: Path) -> None:
    fake = FakeGit(tree_of(tree))
    assert drift.since_approved(fake, tree, TAGS) == Drift("q-h1-approved")
    assert fake.calls == [
        ["rev-parse", "--is-inside-work-tree"],
        ["tag", "--list", "--merged", "HEAD", "q-h1-approved"],
        ["describe", "--tags", "--abbrev=0", "--match", "q-h1-approved", "HEAD"],
        ["rev-parse", "--show-object-format"],
        ["ls-tree", "-r", "-z", "-l", "--full-tree", "q-h1-approved", "--", "config/agents",
         "src/argus/agent/registry.py"],
    ]  # fmt: skip


def test_only_the_pins_approval_tags_count(tree: Path) -> None:
    """The nearest of the tags the pins name, never another approval tag (found in review:
    under D-110 an unrelated component's approval tag sits on a tree holding agents nobody
    approved, and silenced the warning)."""
    assert drift.approvals() == {
        "q-h1-approved", "q-h2-approved", "q-h3-approved", "ar3-approved",
    }  # fmt: skip
    fake = FakeGit(tree_of(tree), **{"tag --list": "q-f5-approved\nq-h1-approved\n"},
                   describe="q-f5-approved\n")  # fmt: skip
    tags = {"q-h1-approved", "q-f5-approved", "q-h2-approved"}
    assert drift.since_approved(fake, tree, tags) == Drift(
        "q-f5-approved", waiting=("q-h2-approved",)
    )
    assert fake.calls[1] == ["tag", "--list", "--merged", "HEAD", "q-f5-approved",
                             "q-h1-approved", "q-h2-approved"]  # fmt: skip
    assert fake.calls[2] == ["describe", "--tags", "--abbrev=0", "--match", "q-f5-approved",
                             "--match", "q-h1-approved", "HEAD"]  # fmt: skip
    assert fake.calls[4][5] == "q-f5-approved"
    sneaky = FakeGit(tree_of(tree), **{"tag --list": "q-a1-approved\nq-h1-approved\n"},
                     describe="q-a1-approved\n")  # fmt: skip
    assert drift.since_approved(sneaky, tree, TAGS) == Drift(None, why="git named another tag")
    assert len(sneaky.calls) == 3  # nothing is asked about a tag the pins do not name


def test_the_pins_tags_must_be_plain(tree: Path) -> None:
    for tags in (set(), {"--output=x-approved"}, {"q-h1-approved", "x"}, {"-approved"}):
        fake = FakeGit()
        assert drift.since_approved(fake, tree, tags) == Drift(
            None, why="a pin names no plain approval tag (q-<id>-approved)"
        )
        assert fake.calls == []


def test_changed_new_and_deleted_paths_are_named_once_in_order(tree: Path) -> None:
    listing = tree_of(tree)
    (tree / "config" / "agents" / "web.md").write_text("edited\n")
    (tree / "config" / "agents" / "dns.md").write_text("new\n")
    (tree / "config" / "agents" / ".web.md.swp").write_text("an editor's\n")
    (tree / "config" / "agents" / ".cache").mkdir()
    (tree / "config" / "agents" / ".cache" / "x.md").write_text("hidden\n")
    (tree / "config" / "agents" / "sub").mkdir()
    (tree / "config" / "agents" / "sub" / "deep.md").write_text("deep\n")
    os.mkfifo(tree / "config" / "agents" / "pipe.md")  # not a file git would keep
    (tree / "src" / "argus" / "agent" / "registry.py").unlink()
    fake = FakeGit(listing + "160000 commit " + "c" * 40 + " -\tconfig/agents/sub\0")
    assert drift.since_approved(fake, tree, TAGS) == Drift(
        "q-h1-approved",
        ("config/agents/dns.md", "config/agents/sub/deep.md", "config/agents/web.md",
         "src/argus/agent/registry.py"),
    )  # fmt: skip


def test_a_same_size_edit_and_a_tagged_path_now_a_pipe(tree: Path) -> None:
    listing = tree_of(tree)
    (tree / "config" / "agents" / "web.md").write_text("WEB\n")  # the same 4 bytes
    assert drift.since_approved(FakeGit(listing), tree, TAGS).changed == ("config/agents/web.md",)
    (tree / "config" / "agents" / "web.md").unlink()
    os.mkfifo(tree / "config" / "agents" / "web.md")
    assert drift.since_approved(FakeGit(listing), tree, TAGS).changed == ("config/agents/web.md",)


def test_the_drift_dataclass_is_a_value() -> None:
    import dataclasses

    with pytest.raises(dataclasses.FrozenInstanceError):
        Drift("t").tag = "u"  # type: ignore[misc]
    assert Drift("t") == Drift("t", (), None, ())


def test_a_link_is_compared_as_git_stores_it(tree: Path) -> None:
    os.symlink("web.md", tree / "config" / "agents" / "link.md")
    link = drift.blob_id(b"web.md")
    listing = tree_of(tree)
    assert f"120000 blob {link}       6\tconfig/agents/link.md" in listing
    assert drift.since_approved(FakeGit(listing), tree, TAGS).changed == ()
    (tree / "config" / "agents" / "link.md").unlink()
    os.symlink("WEB.md", tree / "config" / "agents" / "link.md")  # same length, elsewhere
    assert drift.since_approved(FakeGit(listing), tree, TAGS).changed == ("config/agents/link.md",)


def test_blob_ids_are_gits() -> None:
    assert drift.blob_id(b"") == "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"
    assert drift.blob_id(b"hello\n") == "ce013625030ba8dba906f756967f9e9ca394464a"
    assert drift.blob_id(b"", "sha256") == (
        "473a0f4c3be8a93681a267e3b1e9a7dcda1185436fe141f7749120a303721813"
    )


def test_the_listing_keeps_blobs_with_their_sizes() -> None:
    oid = "a" * 40
    listing = (f"100644 blob {oid}      12\tconfig/agents/web.md\0"
               f"120000 blob {oid}       6\tconfig/agents/link.md\0"
               f"160000 commit {oid}       -\tconfig/agents/sub\0"
               f"040000 tree {oid}       -\tconfig/agents/dir\0"
               f"100644 blob {oid}\tconfig/agents/no-size.md\0"
               f"100644 blob {oid} 1 2\tconfig/agents/odd.md\0\0")  # fmt: skip
    assert drift._tagged(listing) == {"config/agents/web.md": (oid, 12),
                                      "config/agents/link.md": (oid, 6)}  # fmt: skip


@pytest.mark.parametrize(
    ("answers", "expected"),
    [
        ({"rev-parse --is-inside-work-tree": "false\n"}, Drift(None, why="not a git checkout")),
        ({"rev-parse --is-inside-work-tree": GitError("fatal: not a git repository")},
         Drift(None, why="not a git checkout (fatal: not a git repository)")),
        ({"tag --list": GitError("bad")},
         Drift(None, why="could not list the approval tags (bad)")),
        ({"tag --list": "\n"}, Drift(None, why="no approval tag of the pins in this checkout's"
                                     " history", waiting=("q-h1-approved",))),
        ({"describe": GitError("fatal: No names found")},
         Drift(None, why="could not find the nearest approval tag (fatal: No names found)")),
        ({"ls-tree -r": GitError("bad object")},
         Drift("q-h1-approved", why="could not compare with q-h1-approved (bad object)")),
        ({"rev-parse --show-object-format": GitError("old git")},
         Drift("q-h1-approved", why="could not compare with q-h1-approved (old git)")),
        ({"rev-parse --show-object-format": "sha512\n"},
         Drift("q-h1-approved", why="could not compare with q-h1-approved (object format"
               " sha512)")),
    ],
)  # fmt: skip
def test_when_it_cannot_tell(tree: Path, answers: dict[str, Any], expected: Drift) -> None:
    assert drift.since_approved(FakeGit(**answers), tree, TAGS) == expected


def test_what_cannot_be_told_still_names_the_waiting_approvals(tree: Path) -> None:
    tags = {"q-h1-approved", "q-f5-approved"}
    got = drift.since_approved(FakeGit(describe=GitError("x")), tree, tags)
    assert got == Drift(None, why="could not find the nearest approval tag (x)",
                        waiting=("q-f5-approved",))  # fmt: skip
    got = drift.since_approved(FakeGit(**{"ls-tree -r": GitError("y")}), tree, tags)
    assert got.waiting == ("q-f5-approved",)
    got = drift.since_approved(FakeGit(describe="q-x-approved\n"), tree, tags)
    assert got.waiting == ("q-f5-approved",)


def test_an_unreadable_file_is_a_cannot_tell(tree: Path) -> None:
    web = tree / "config" / "agents" / "web.md"
    listing = tree_of(tree)
    web.chmod(0o000)
    try:
        if os.access(web, os.R_OK):
            pytest.skip("root reads everything")
        got = drift.since_approved(FakeGit(listing), tree, TAGS)
        assert got.tag == "q-h1-approved"
        assert got.why is not None
        assert got.why.startswith("could not compare with q-h1-approved ([Errno 13]")
    finally:
        web.chmod(0o644)


def test_the_default_object_format_is_sha1(tree: Path) -> None:
    fake = FakeGit(tree_of(tree))
    fake.answers["rev-parse --show-object-format"] = "\n"
    assert drift.since_approved(fake, tree, TAGS) == Drift("q-h1-approved")


def test_the_default_tags_are_the_pins(tree: Path) -> None:
    fake = FakeGit(tree_of(tree))
    assert drift.since_approved(fake, tree) == Drift(
        "q-h1-approved", waiting=("ar3-approved", "q-h2-approved", "q-h3-approved")
    )
    assert fake.calls[1][-1] == "q-h3-approved"  # the pins' tags, sorted


# -- reading files: never whole, never waiting --------------------------------------------------


def test_a_file_of_another_size_is_changed_without_being_read(
    tree: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A 1 GiB file beside the agents (a core dump, a log) is not read at all: its size is
    not the tagged one (found in review: it was hashed whole, twice in memory)."""
    listing = tree_of(tree)
    with open(tree / "config" / "agents" / "core.dump", "wb") as handle:
        handle.truncate(1 << 30)  # sparse
    with open(tree / "config" / "agents" / "web.md", "r+b") as handle:
        handle.truncate(1 << 30)

    read: list[str] = []
    real = drift._blob_of_file

    def recorded(path: Path, size: int, algorithm: str) -> str | None:
        read.append(path.name)
        return real(path, size, algorithm)

    monkeypatch.setattr(drift, "_blob_of_file", recorded)
    assert drift.since_approved(FakeGit(listing), tree, TAGS).changed == (
        "config/agents/core.dump", "config/agents/web.md")  # fmt: skip
    assert read == ["registry.py"]  # the only file of its tagged size


def test_a_file_of_the_tagged_size_is_read_in_chunks(
    tree: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    web = tree / "config" / "agents" / "web.md"
    web.write_bytes(b"x" * (3 * drift.CHUNK + 5))
    listing = tree_of(tree)
    asked: list[int] = []
    real = os.fdopen

    class Recording:
        def __init__(self, handle: Any) -> None:
            self.handle = handle

        def read(self, size: int = -1) -> bytes:
            asked.append(size)
            data: bytes = self.handle.read(size)
            return data

        def fileno(self) -> int:
            number: int = self.handle.fileno()
            return number

        def __enter__(self) -> Any:
            return self

        def __exit__(self, *exc: object) -> None:
            self.handle.close()

    monkeypatch.setattr(drift.os, "fdopen", lambda fd, mode: Recording(real(fd, mode)))
    assert drift.since_approved(FakeGit(listing), tree, TAGS).changed == ()
    # in chunks, then one byte more than the size asked for (a file growing meanwhile is
    # changed), then the end; registry.py (10 bytes) likewise
    assert asked == [drift.CHUNK, drift.CHUNK, drift.CHUNK, 6, 1, 11, 1]
    assert drift.CHUNK == 64 * 1024


def test_the_blob_of_a_file_is_none_unless_it_is_the_size_asked(tmp_path: Path) -> None:
    f = tmp_path / "f"
    f.write_bytes(b"hello\n")
    assert drift._blob_of_file(f, 6, "sha1") == drift.blob_id(b"hello\n")
    assert drift._blob_of_file(f, 6, "sha256") == drift.blob_id(b"hello\n", "sha256")
    assert drift._blob_of_file(f, 5, "sha1") is None
    assert drift._blob_of_file(f, 7, "sha1") is None
    e = tmp_path / "e"
    e.write_bytes(b"")
    assert drift._blob_of_file(e, 0, "sha1") == drift.blob_id(b"")


def test_a_file_larger_or_smaller_than_asked_is_read_at_most_one_byte_past(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Its size may change between the listing and the read: never more than size + 1 bytes
    are read, and anything but exactly ``size`` is no blob."""
    f = tmp_path / "f"
    f.write_bytes(b"x" * (drift.CHUNK + 10))
    asked: list[int] = []
    real = os.fdopen

    class Recording:
        def __init__(self, handle: Any) -> None:
            self.handle = handle

        def read(self, size: int = -1) -> bytes:
            asked.append(size)
            data: bytes = self.handle.read(size)
            return data

        def fileno(self) -> int:
            number: int = self.handle.fileno()
            return number

        def __enter__(self) -> Any:
            return self

        def __exit__(self, *exc: object) -> None:
            self.handle.close()

    monkeypatch.setattr(drift.os, "fdopen", lambda fd, mode: Recording(real(fd, mode)))
    assert drift._blob_of_file(f, 3, "sha1") is None
    assert asked == [4]
    asked.clear()
    assert drift._blob_of_file(f, drift.CHUNK + 11, "sha1") is None
    assert asked == [drift.CHUNK, 12, 2]  # 10 of the 12 came, then the end


def test_a_pipe_or_a_link_swapped_in_is_never_waited_on_or_followed(tmp_path: Path) -> None:
    import signal

    pipe = tmp_path / "pipe"
    os.mkfifo(pipe)

    def hung(*a: Any) -> None:
        raise AssertionError("waited for a writer")

    signal.signal(signal.SIGALRM, hung)
    signal.alarm(5)
    try:
        assert drift._blob_of_file(pipe, 0, "sha1") is None
    finally:
        signal.alarm(0)
    target = tmp_path / "t"
    target.write_bytes(b"x")
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(OSError, match="Too many levels of symbolic links"):
        drift._blob_of_file(link, 1, "sha1")


# -- with real git ------------------------------------------------------------------------------


def _git(root: Path, *args: str) -> None:
    git = shutil.which("git")
    assert git is not None
    subprocess.run(  # noqa: S603 - a fixed program and arguments
        [git, "-C", str(root), "-c", "user.email=t@example.invalid", "-c", "user.name=t",
         "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null", "-c",
         "tag.gpgsign=false", *args],
        check=True, capture_output=True,
    )  # fmt: skip


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    (root / "config" / "agents").mkdir(parents=True)
    (root / "src" / "argus" / "agent").mkdir(parents=True)
    for name in ("investigator", "web"):
        (root / "config" / "agents" / f"{name}.md").write_text(f"{name}\n")
    (root / "src" / "argus" / "agent" / "registry.py").write_text("PINS = {}\n")
    (root / "other.txt").write_text("x\n")
    _git(root, "init", "-q", "-b", "main")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "one")
    return root


def test_real_git_without_an_approved_tag(repo: Path) -> None:
    _git(repo, "tag", "not-approved-yet")
    _git(repo, "tag", "q-a1-approved")  # another component's
    assert drift.since_approved(drift.git(repo), repo, {"q-x1-approved"}) == Drift(
        None, why="no approval tag of the pins in this checkout's history",
        waiting=("q-x1-approved",),
    )  # fmt: skip


def test_real_git_names_what_changed_since_the_nearest_approved_tag(repo: Path) -> None:
    _git(repo, "tag", "r1-approved")
    (repo / "other.txt").write_text("y\n")
    _git(repo, "commit", "-q", "-am", "two")
    _git(repo, "tag", "q-x1-approved")
    run = drift.git(repo)
    tags = {"r1-approved", "q-x1-approved"}
    assert drift.since_approved(run, repo, tags) == Drift("q-x1-approved")
    (repo / "other.txt").write_text("z\n")  # not watched
    assert drift.since_approved(run, repo, tags) == Drift("q-x1-approved")
    (repo / "config" / "agents" / "web.md").write_text("edited\n")  # uncommitted counts
    (repo / "config" / "agents" / "dns.md").write_text("new\n")  # untracked counts
    (repo / "src" / "argus" / "agent" / "registry.py").write_text("PINS = {1: 2}\n")
    _git(repo, "commit", "-q", "-m", "three", "--", "src/argus/agent/registry.py")
    assert drift.since_approved(run, repo, tags) == Drift(
        "q-x1-approved",
        ("config/agents/dns.md", "config/agents/web.md", "src/argus/agent/registry.py"),
    )
    (repo / "config" / "agents" / "investigator.md").unlink()
    assert "config/agents/investigator.md" in drift.since_approved(run, repo, tags).changed


def test_real_git_another_components_approval_never_approves_the_agents(repo: Path) -> None:
    """D-110's flow: Q-F5 publishes coordinator@4 and its pin (reviewed, not approved), then
    Q-A1 is approved and tagged on a tree that holds them. Only the pins' own tags count, so
    the warning stays until q-f5-approved exists (found in review)."""
    _git(repo, "tag", "q-h1-approved")
    (repo / "config" / "agents" / "investigator.md").write_text("coordinator@4\n")
    (repo / "src" / "argus" / "agent" / "registry.py").write_text("PINS = {4: 4}\n")
    _git(repo, "commit", "-q", "-am", "Q-F5 published")
    (repo / "other.txt").write_text("api\n")
    _git(repo, "commit", "-q", "-am", "Q-A1")
    _git(repo, "tag", "q-a1-approved")
    run = drift.git(repo)
    tags = {"q-h1-approved", "q-f5-approved"}  # coordinator@4's pin names its own approval
    changed = ("config/agents/investigator.md", "src/argus/agent/registry.py")
    assert drift.since_approved(run, repo, tags) == Drift(
        "q-h1-approved", changed, waiting=("q-f5-approved",)
    )
    assert drift.since_approved(run, repo, {"q-h1-approved"}).changed == changed
    _git(repo, "tag", "q-f5-approved")
    assert drift.since_approved(run, repo, tags) == Drift("q-f5-approved")


def test_real_git_a_tag_on_another_branch_is_not_an_approval_here(repo: Path) -> None:
    _git(repo, "tag", "q-h1-approved")
    _git(repo, "checkout", "-q", "-b", "side")
    (repo / "config" / "agents" / "web.md").write_text("side\n")
    _git(repo, "commit", "-q", "-am", "side")
    _git(repo, "tag", "q-f5-approved")
    _git(repo, "checkout", "-q", "main")
    got = drift.since_approved(drift.git(repo), repo, {"q-h1-approved", "q-f5-approved"})
    assert got == Drift("q-h1-approved", waiting=("q-f5-approved",))


def test_real_git_ignores_a_git_dir_in_the_environment(
    repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _git(repo, "tag", "r1-approved")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    _git(elsewhere, "init", "-q")
    monkeypatch.setenv("GIT_DIR", str(elsewhere / ".git"))
    monkeypatch.setenv("GIT_WORK_TREE", str(elsewhere))
    assert drift.since_approved(drift.git(repo), repo, {"r1-approved"}) == Drift("r1-approved")
    assert drift._env()["GIT_OPTIONAL_LOCKS"] == "0"
    assert "GIT_DIR" not in drift._env()


def test_real_git_outside_a_checkout(tmp_path: Path) -> None:
    got = drift.since_approved(drift.git(tmp_path), tmp_path, TAGS)
    assert got.tag is None
    assert got.why is not None
    assert got.why.startswith("not a git checkout (fatal: not a git repository")


def test_git_missing_slow_or_failing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(drift.shutil, "which", lambda name: None)
    with pytest.raises(GitError, match=r"^git is not installed$"):
        drift.git(tmp_path)(["status"])
    monkeypatch.undo()

    def slow(*a: Any, **kw: Any) -> Any:
        raise subprocess.TimeoutExpired("git", drift.TIMEOUT_S)

    monkeypatch.setattr(drift.subprocess, "run", slow)
    with pytest.raises(GitError, match=r"^git did not answer \(TimeoutExpired\)$"):
        drift.git(tmp_path)(["status"])

    def missing(*a: Any, **kw: Any) -> Any:
        raise FileNotFoundError("gone")

    monkeypatch.setattr(drift.subprocess, "run", missing)
    with pytest.raises(GitError, match=r"^git did not answer \(FileNotFoundError\)$"):
        drift.git(tmp_path)(["status"])

    def quiet(*a: Any, **kw: Any) -> Any:
        return subprocess.CompletedProcess(a[0], 1, b"", b"")

    monkeypatch.setattr(drift.subprocess, "run", quiet)
    with pytest.raises(GitError, match=r"^no message$"):
        drift.git(tmp_path)(["status"])

    def long(*a: Any, **kw: Any) -> Any:
        return subprocess.CompletedProcess(a[0], 128, b"", b"e" * 300 + b"\nsecond line")

    monkeypatch.setattr(drift.subprocess, "run", long)
    with pytest.raises(GitError) as caught:
        drift.git(tmp_path)(["status"])
    assert str(caught.value) == "e" * 200


def test_the_runner_asks_git_for_exactly_this(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}

    def record(argv: list[str], **kw: Any) -> Any:
        seen.update(argv=argv, **kw)
        return subprocess.CompletedProcess(argv, 0, b"out \xe9\r\n", b"")

    monkeypatch.setattr(drift.subprocess, "run", record)
    assert drift.git(Path("/r"))(["status", "-s"]) == "out \udce9\r\n"  # as names decode
    assert seen["argv"][1:] == ["-C", "/r", "-c", "core.fsmonitor=false", "status", "-s"]
    assert seen["argv"][0].endswith("git")
    assert seen["capture_output"] is True
    assert "text" not in seen
    assert "universal_newlines" not in seen
    assert seen["timeout"] == drift.TIMEOUT_S == 10.0
    assert seen["check"] is False
    assert seen["env"] == drift._env()
    assert drift._env()["LC_ALL"] == "C"
    assert drift._env()["GIT_TERMINAL_PROMPT"] == "0"
    assert drift.ROOT == loader.ROOT


# -- the doctor check ---------------------------------------------------------------------------


async def _check(monkeypatch: pytest.MonkeyPatch, found: Drift) -> list[doctor.CheckResult]:
    monkeypatch.setattr(drift, "since_approved", lambda run=None: found)
    return await doctor.agents_check(None)  # type: ignore[arg-type]


async def test_doctor_shows_the_agents_and_their_gold_run_ids(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    got = await _check(monkeypatch, Drift("q-h1-approved"))
    assert got == [
        doctor.CheckResult("agents", True, "investigator coordinator@4; web, proxy specialist@1;"
                           " intel specialist@2; gold run ids 98aa90f205fd (no tools),"
                           " 0232557c5055 (tools)"),
        doctor.CheckResult("agent reporter", True, "reporter@1, off"),
        doctor.CheckResult("agent responder", True, "responder@1, off"),
        doctor.CheckResult("agents since approval", True, "as at q-h1-approved"),
    ]  # fmt: skip


@pytest.mark.parametrize(
    ("found", "detail"),
    [
        (Drift("q-h1-approved", ("config/agents/web.md", "src/argus/agent/registry.py")),
         "changed since q-h1-approved, not approved yet: config/agents/web.md,"
         " src/argus/agent/registry.py"),
        (Drift(None, why="not a git checkout"), "cannot tell: not a git checkout"),
        (Drift("q-h1-approved", waiting=("q-f5-approved",)),
         "as at q-h1-approved; pins waiting for their approval: q-f5-approved"),
        (Drift("q-h1-approved", ("config/agents/investigator.md",),
               waiting=("q-f5-approved", "q-h2-approved")),
         "changed since q-h1-approved, not approved yet: config/agents/investigator.md; pins"
         " waiting for their approval: q-f5-approved, q-h2-approved"),
        (Drift(None, why="no approval tag of the pins in this checkout's history",
               waiting=("q-h1-approved",)),
         "cannot tell: no approval tag of the pins in this checkout's history; pins waiting"
         " for their approval: q-h1-approved"),
    ],
)  # fmt: skip
async def test_doctor_warns_on_drift_or_when_it_cannot_tell(
    monkeypatch: pytest.MonkeyPatch, found: Drift, detail: str
) -> None:
    since = (await _check(monkeypatch, found))[-1]
    assert since == doctor.CheckResult("agents since approval", True, detail, warn=True)


async def test_doctor_fails_a_refused_file_or_other_gold_run_ids(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from tests.unit.agent.test_loader import FILES, copy, header

    d = copy(tmp_path / "agents")
    (d / "web.md").write_text(header(FILES["web"], "tier", "large"))
    monkeypatch.setattr(loader, "DIRECTORY", d)
    agents, *_, since = await _check(monkeypatch, Drift("q-h1-approved"))
    assert agents == doctor.CheckResult(
        "agents", False, "refused: web.md: tier large is above what code allows web (small)"
    )
    assert since.ok
    monkeypatch.undo()
    from argus.agent import registry

    monkeypatch.setattr(registry, "GOLD_RUNS", {"no_tools": "a" * 12, "tools": "b" * 12})
    agents, *_ = await _check(monkeypatch, Drift("q-h1-approved"))
    assert not agents.ok
    assert agents.detail.endswith("(tools), but code ties them to aaaaaaaaaaaa, bbbbbbbbbbbb")


async def test_doctor_names_specialists_by_version(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from dataclasses import replace

    agents = loader.load()
    web = replace(agents.by_name["web"], version="specialist@3")
    mixed = loader.Agents({**agents.by_name, "web": web})
    monkeypatch.setattr(loader, "load", lambda *a, **kw: mixed)
    got, *_ = await _check(monkeypatch, Drift("t"))
    assert got.detail.startswith("investigator coordinator@4; web specialist@3; proxy"
                                 " specialist@1; intel specialist@2; gold run ids ")  # fmt: skip
    assert not got.ok  # web=specialist@3 is not what the gold run ids in code name
    nobody = loader.Agents({**agents.by_name, "investigator": replace(
        agents.coordinator, specialists=())})  # fmt: skip
    monkeypatch.setattr(loader, "load", lambda *a, **kw: nobody)
    got, *_ = await _check(monkeypatch, Drift("t"))
    assert "; no specialists; " in got.detail


async def test_doctor_gives_every_other_agent_its_own_line(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Another bound agent (Q-H2's responder, built off) never refuses agent@1: doctor shows
    its own state; a refused file fails while the agent is on, and warns while it is off."""
    from argus.agent import registry

    agents = loader.load()
    bindings = {
        **registry.BINDINGS,
        "responder": registry.BINDINGS["intel"],
        "reporter": registry.BINDINGS["intel"],
        "hunter": registry.BINDINGS["intel"],
    }
    on = replace_version(agents.by_name["intel"], "specialist@3")
    survey: dict[str, Any] = {
        **agents.by_name, "responder": agents.by_name["intel"], "reporter": on,
        "hunter": loader.AgentError("hunter.md: is not the file pinned"),
        "stray": loader.AgentError("stray.md: code binds no agent 'stray'"),
    }  # fmt: skip
    monkeypatch.setattr(registry, "BINDINGS", bindings)
    monkeypatch.setattr(
        registry,
        "ENABLED",
        {**registry.ENABLED, "responder": None, "reporter": "specialist@3", "hunter": None},
    )
    monkeypatch.setattr(loader, "survey", lambda *a, **kw: survey)
    got = await _check(monkeypatch, Drift("q-h1-approved"))
    assert [(r.name, r.ok, r.warn, r.detail) for r in got[1:-1]] == [
        ("agent hunter", True, True, "off, and refused: hunter.md: is not the file pinned"),
        ("agent reporter", True, False, "specialist@3, on"),
        ("agent responder", True, False, "specialist@2, off"),
    ]
    monkeypatch.setattr(registry, "ENABLED", {**registry.ENABLED, "hunter": "specialist@1"})
    got = await _check(monkeypatch, Drift("q-h1-approved"))
    assert (got[1].name, got[1].ok, got[1].warn) == ("agent hunter", False, False)
    assert got[1].detail == "on, and refused: hunter.md: is not the file pinned"
    assert got[0].ok  # agent@1 itself is as it was

    def unlisted(*a: Any, **kw: Any) -> Any:
        raise loader.AgentError("the agents directory cannot be read (Permission denied)")

    monkeypatch.setattr(loader, "survey", unlisted)
    got = await _check(monkeypatch, Drift("q-h1-approved"))
    assert [r.name for r in got] == ["agents", "agents since approval"]


def replace_version(definition: loader.Definition, version: str) -> loader.Definition:
    from dataclasses import replace

    return replace(definition, version=version)


def test_the_cli_prints_warn_and_still_exits_by_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    from argus import cli

    async def results(settings: Any) -> list[doctor.CheckResult]:
        return [doctor.CheckResult("a", True, "fine"),
                doctor.CheckResult("agents since approval", True, "look", warn=True)]  # fmt: skip

    monkeypatch.setattr(cli, "run_checks", results)
    monkeypatch.setattr(cli, "_load", lambda config: object())
    got = CliRunner().invoke(cli.app, ["doctor"])
    assert got.exit_code == 0
    assert got.output.splitlines() == [
        "PASS  a                      fine",
        "WARN  agents since approval  look",
    ]

    async def failing(settings: Any) -> list[doctor.CheckResult]:
        return [doctor.CheckResult("a", False, "bad", warn=True)]

    monkeypatch.setattr(cli, "run_checks", failing)
    got = CliRunner().invoke(cli.app, ["doctor"])
    assert got.exit_code == 1
    assert got.output == "FAIL  a  bad\n"  # a failure is a failure, warning or not


def test_git_runs_no_command_a_repository_could_configure(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A checkout's own config can make git run commands (core.fsmonitor, an external diff
    driver): the drift check switches them off (found in review, Q-H1)."""
    _git(repo, "tag", "r1-approved")
    marker = repo / "ran"
    hook = repo / "hook.sh"
    hook.write_text(f"#!/bin/sh\ntouch {marker}\n")
    hook.chmod(0o755)
    _git(repo, "config", "core.fsmonitor", str(hook))
    _git(repo, "config", "diff.external", str(hook))
    _git(repo, "config", "filter.evil.clean", str(hook))
    _git(repo, "config", "filter.evil.smudge", str(hook))
    _git(repo, "config", "diff.evil.textconv", str(hook))
    (repo / ".gitattributes").write_text("*.md filter=evil diff=evil\n")
    (repo / "config" / "agents" / "web.md").write_text("edited\n")
    got = drift.since_approved(drift.git(repo), repo, {"r1-approved"})
    assert got.changed == ("config/agents/web.md",)
    assert not marker.exists()


# -- second review (R1, R3, R4, R5) -------------------------------------------------------------


def test_a_hidden_file_committed_with_the_agents_is_not_drift(repo: Path) -> None:
    """R4: the loader ignores hidden files and so does drift's walk of the disk; a hidden
    file committed under config/agents and tagged as it is on disk is no change either, on
    neither side (it was reported as changed, not approved yet, forever)."""
    (repo / "config" / "agents" / ".notes").write_text("for reviewers\n")
    (repo / "config" / "agents" / ".old").mkdir()
    (repo / "config" / "agents" / ".old" / "web.md").write_text("old\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "notes")
    _git(repo, "tag", "-a", "q-h1-approved", "-m", "approved")
    assert drift.since_approved(drift.git(repo), repo, TAGS) == Drift("q-h1-approved")
    (repo / "config" / "agents" / ".notes").write_text("edited\n")
    shutil.rmtree(repo / "config" / "agents" / ".old")
    assert drift.since_approved(drift.git(repo), repo, TAGS) == Drift("q-h1-approved")
    (repo / "config" / "agents" / "web.md").write_text("edited\n")
    assert drift.since_approved(drift.git(repo), repo, TAGS).changed == ("config/agents/web.md",)


def test_a_linked_agents_directory_is_drift_even_when_its_target_matches(
    repo: Path, tmp_path: Path
) -> None:
    """R5 (a surviving mutant): config/agents replaced by a link to a copy of the tagged
    files is drift (the loader refuses a linked directory too): git keeps a link, not the
    files behind it."""
    _git(repo, "tag", "-a", "q-h1-approved", "-m", "approved")
    elsewhere = tmp_path / "elsewhere"
    (repo / "config" / "agents").rename(elsewhere)
    (repo / "config" / "agents").symlink_to(elsewhere)
    got = drift.since_approved(drift.git(repo), repo, TAGS)
    assert got.tag == "q-h1-approved"
    assert got.changed == (
        "config/agents",
        "config/agents/investigator.md",
        "config/agents/web.md",
    )


def test_a_name_that_is_not_utf8_never_breaks_the_comparison(repo: Path) -> None:
    """R1: a file under config/agents named with bytes that are not UTF-8, committed and
    tagged (git's output is decoded as the file system's names are), then edited."""
    raw = os.path.join(os.fsencode(repo / "config" / "agents"), b"x\xe9\r.md")
    with open(raw, "wb") as f:
        f.write(b"x\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "odd name")
    _git(repo, "tag", "-a", "q-h1-approved", "-m", "approved")
    assert drift.since_approved(drift.git(repo), repo, TAGS) == Drift("q-h1-approved")
    with open(raw, "wb") as f:
        f.write(b"y\n")
    got = drift.since_approved(drift.git(repo), repo, TAGS)
    assert got.changed == (os.fsdecode(raw)[len(str(repo)) + 1 :],)


async def test_doctor_prints_changed_names_in_printable_ascii(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    found = Drift("q-h1-approved", ("config/agents/x\udce9\r\x1b[2K.md",))
    since = (await _check(monkeypatch, found))[-1]
    assert since.detail == (
        "changed since q-h1-approved, not approved yet: config/agents/x\\xe9\\x0d\\x1b[2K.md"
    )


def test_doctor_prints_one_readable_line_per_check_whatever_a_file_is_named(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """R1: argus doctor died with UnicodeEncodeError on a name that is not UTF-8, and a
    carriage return in a name printed a PASS over its FAIL line."""
    from argus import cli
    from tests.unit.agent.test_loader import copy

    d = copy(tmp_path / "agents")
    for raw in (b"investigator\xe9.md", b"a\rb.md"):
        with open(os.path.join(os.fsencode(d), raw), "wb") as f:
            f.write(b"x\n")
    monkeypatch.setattr(loader, "DIRECTORY", d)
    changed = ("config/agents/a\rb.md", "config/agents/investigator\udce9.md")
    monkeypatch.setattr(drift, "since_approved", lambda run=None: Drift("q-h1-approved", changed))
    monkeypatch.setattr(cli, "run_checks", doctor.agents_check)
    monkeypatch.setattr(cli, "_load", lambda config: None)
    got = CliRunner().invoke(cli.app, ["doctor"])
    assert got.exception is None or isinstance(got.exception, SystemExit), got.exception
    assert got.exit_code == 1
    assert got.output.isascii()
    assert "\r" not in got.output
    lines = got.output.splitlines()
    assert len(lines) == 4
    assert lines[0] == (
        f"FAIL  {'agents'.ljust(21)}  refused: a\\x0db.md: code binds no agent 'a\\x0db'"
    )
    assert lines[1].startswith("PASS  agent reporter")
    assert lines[2].startswith("PASS  agent responder")
    assert lines[-1] == (
        "WARN  agents since approval  changed since q-h1-approved, not approved yet:"
        " config/agents/a\\x0db.md, config/agents/investigator\\xe9.md"
    )


async def test_doctor_fails_an_enabled_specialist_the_coordinator_no_longer_names(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """R3, decision 20: a coordinator version that consults fewer specialists than code
    allows (coordinator@4 names web and proxy) leaves intel on but outside its family; an
    edited, refused intel.md fails in doctor on its own line (doctor took the family from
    code's binding, so intel had no line at all)."""
    from argus.agent import registry
    from argus.agent.registry import ENABLED, PINS, Pin
    from argus.evaluation.agent_eval import signature_of
    from tests.unit.agent.test_loader import FILES, copy, header

    d = copy(tmp_path / "agents")
    narrowed = header(header(FILES["investigator"], "specialists", "[web, proxy]"),
                      "version", "coordinator@4")  # fmt: skip
    (d / "investigator.md").write_text(narrowed)
    (d / "intel.md").write_text(FILES["intel"].replace("reputation of", "reputations of", 1))
    got = loader.read(d / "investigator.md")
    pins = {**PINS, "investigator": {"coordinator@4": Pin(got.file_sha256, got.prompt_sha256,
                                                          "q-f5-approved")}}  # fmt: skip
    enabled = {**ENABLED, "investigator": "coordinator@4"}  # intel stays specialist@1: on
    real_load, real_survey = loader.load, loader.survey
    monkeypatch.setattr(loader, "load", lambda directory=None, **kw: real_load(
        d, pins=pins, enabled=enabled))  # fmt: skip
    monkeypatch.setattr(loader, "survey", lambda directory=None, **kw: real_survey(
        d, pins=pins, enabled=enabled))  # fmt: skip
    agents = loader.load()
    assert agents.coordinator.budget is not None
    monkeypatch.setattr(registry, "ENABLED", enabled)
    monkeypatch.setattr(registry, "GOLD_RUNS", {
        "no_tools": signature_of(agents, agents.coordinator.budget, False),
        "tools": signature_of(agents, agents.coordinator.budget, True)})  # fmt: skip
    results = await _check(monkeypatch, Drift("q-h1-approved"))
    assert [(r.name, r.ok, r.warn) for r in results] == [
        ("agents", True, False), ("agent intel", False, False), ("agent reporter", True, False),
        ("agent responder", True, False),
        ("agents since approval", True, False),
    ]  # fmt: skip
    assert results[1].detail.startswith("on, and refused: intel.md: is not the file pinned")


async def test_doctor_names_each_specialist_when_the_coordinator_is_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """When the coordinator's own file is refused, which specialists it names is not known:
    each other bound agent gets its own line, so a refused specialist is not hidden behind
    the coordinator's reason (decision 24 gives the coordinator's first)."""
    from tests.unit.agent.test_loader import FILES, copy

    d = copy(tmp_path / "agents")
    (d / "investigator.md").write_text(FILES["investigator"].replace("lead", "chief", 1))
    (d / "intel.md").write_text(FILES["intel"].replace("reputation of", "reputations of", 1))
    monkeypatch.setattr(loader, "DIRECTORY", d)
    results = await _check(monkeypatch, Drift("q-h1-approved"))
    assert [(r.name, r.ok) for r in results] == [
        ("agents", False), ("agent intel", False), ("agent proxy", True),
        ("agent reporter", True), ("agent responder", True), ("agent web", True),
        ("agents since approval", True),
    ]  # fmt: skip
    assert results[0].detail.startswith("refused: investigator.md: is not the file pinned")
    assert results[1].detail.startswith("on, and refused: intel.md: is not the file pinned")
    assert results[3].detail == "reporter@1, off"
    assert results[4].detail == "responder@1, off"
    assert results[5].detail == "specialist@1, on"


async def test_doctor_prints_an_os_errors_text_in_printable_ascii(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def broken(*a: Any, **kw: Any) -> Any:
        raise OSError(5, "Input/output error\r\x1b[2K", "/x\udce9")

    monkeypatch.setattr(loader, "load", broken)
    (agents, *_) = await _check(monkeypatch, Drift("q-h1-approved"))
    assert agents == doctor.CheckResult(
        "agents", False, "refused: [Errno 5] Input/output error\\x0d\\x1b[2K: '/x\\udce9'"
    )

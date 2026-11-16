"""Q-A5: deploy/custody/install.sh against a fake root (D-109: no sudo here; running it for real
is the user's production step). A temporary folder stands for /, a real git repository for the
checkout with its approved tag, and stand-ins for the commands that need root (useradd,
groupadd, usermod, chown, systemctl) and for uv; every other command is the real one."""

# ruff: noqa: S603 - the tests run the script and git with arguments they build

from __future__ import annotations

import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

from argus.ops import custody
from tests.conftest import REPO_ROOT, private_text

pytestmark = pytest.mark.unit

SCRIPT = REPO_ROOT / "deploy" / "custody" / "install.sh"
BASH = "/usr/bin/bash"
GIT = shutil.which("git") or "/usr/bin/git"
TAG = "q-a5-approved"
SECRETS = {
    "ARGUS_DATABASE__PASSWORD": "Synthetic-Runtime-11",
    "ARGUS_DATABASE__OWNER_PASSWORD": "Synthetic-Owner-22",
    "ARGUS_DATABASE__API_PASSWORD": "Synthetic-Web-33",
    "ARGUS_SIEM__API_KEY": "Synthetic-Reader-44",
}

STANDIN = {
    "groupadd": """
name="${@: -1}"; echo "groupadd $*" >>"$LOG"
gid=$((900 + $(wc -l <"$ROOT/etc/group")))
echo "$name:x:$gid:" >>"$ROOT/etc/group"
""",
    "useradd": """
name="${@: -1}" shell=/bin/sh; echo "useradd $*" >>"$LOG"
while (( $# )); do [[ $1 == --shell ]] && shell=$2; shift; done
uid=$((990 - $(wc -l <"$ROOT/etc/passwd")))
echo "$name:x:$uid:$uid:ARGUS:/nonexistent:$shell" >>"$ROOT/etc/passwd"
echo "$name:x:$uid:" >>"$ROOT/etc/group"
""",
    "usermod": """
echo "usermod $*" >>"$LOG"
group=$3 user=$4
awk -F: -v OFS=: -v g="$group" -v u="$user" \
  '$1 == g { $4 = ($4 == "" ? u : $4 "," u) } { print }' "$ROOT/etc/group" >"$ROOT/etc/group.new"
mv "$ROOT/etc/group.new" "$ROOT/etc/group"
""",
    "chown": 'echo "chown $*" >>"$LOG"',
    # runuser -u USER -- COMMAND...: the test runs as the checkout's owner already
    "runuser": """
echo "runuser $*" >>"$LOG"
[[ $1 == -u ]] && shift 2
[[ $1 == -- ]] && shift
exec "$@"
""",
    "systemctl": 'echo "systemctl $*" >>"$LOG"',
}


@dataclass
class Fake:
    root: Path
    repo: Path
    commit: str
    uv: Path
    log: Path
    path: str

    def run(self, *args: str, operator: str = "op") -> subprocess.CompletedProcess[str]:
        command = [BASH, str(SCRIPT), "--root", str(self.root), "--from", str(self.repo),
                   "--uv", str(self.uv), "--operator", operator, *args]  # fmt: skip
        env = {k: v for k, v in os.environ.items() if not k.startswith("ARGUS_")}
        env["PATH"] = self.path
        return subprocess.run(command, capture_output=True, text=True, env=env, check=False)

    def deploy(self, *args: str) -> subprocess.CompletedProcess[str]:
        return self.run("--tag", TAG, "--commit", self.commit, *args)

    def calls(self) -> list[str]:
        return self.log.read_text().splitlines() if self.log.exists() else []

    def under(self, path: str) -> Path:
        return self.root / path.lstrip("/")


def _git(repo: Path, *args: str) -> str:
    done = subprocess.run(
        [GIT, "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.invalid",
         "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false", *args],
        capture_output=True, text=True, check=True,
    )  # fmt: skip
    return done.stdout.strip()


@pytest.fixture
def fake(tmp_path: Path) -> Iterator[Fake]:
    root, repo, bin_dir = tmp_path / "root", tmp_path / "checkout", tmp_path / "bin"
    log = tmp_path / "calls.log"
    (root / "etc").mkdir(parents=True)
    (root / "etc" / "passwd").write_text("root:x:0:0:root:/root:/bin/bash\n")
    (root / "etc" / "group").write_text("root:x:0:\ndocker:x:983:op\n")
    python = root / "usr" / "bin" / "python3.12"  # the host's (the uv stand-in never runs it)
    python.parent.mkdir(parents=True)
    python.write_text("#!/bin/sh\n")
    python.chmod(0o755)
    bin_dir.mkdir()
    for name, text in STANDIN.items():
        script = bin_dir / name
        script.write_text(f'#!/usr/bin/bash\nROOT="{root}" LOG="{log}"\n{text}')
        script.chmod(0o755)
    uv = bin_dir / "uv-standin"
    uv.write_text(
        f"""#!/usr/bin/bash
echo "uv $* | $(env | grep -E '^UV_' | sort | tr '\\n' ' ')" >>"{log}"
venv=$UV_PROJECT_ENVIRONMENT
mkdir -p "$venv/bin"
printf '#!/bin/sh\\nexec {sys.executable} "$@"\\n' >"$venv/bin/python"
printf '#!/bin/sh\\necho argus\\n' >"$venv/bin/argus"
chmod 755 "$venv/bin/python" "$venv/bin/argus"
"""
    )
    uv.chmod(0o755)
    # the checkout: deploy/custody committed and tagged; secrets and data files untracked
    (repo / "deploy").mkdir(parents=True)
    shutil.copytree(REPO_ROOT / "deploy" / "custody", repo / "deploy" / "custody")
    _git(repo, "init", "-q")
    _git(repo, "add", "deploy")
    _git(repo, "commit", "-q", "-m", "approved")
    _git(repo, "tag", TAG)
    commit = _git(repo, "rev-parse", "HEAD")
    (repo / ".env").write_text("".join(f"{k}={v}\n" for k, v in SECRETS.items()))
    for relative, text in (
        ("data/tls/argus.key", "Synthetic-TLS-Key\n"),
        ("data/tls/argus.crt", "certificate\n"),
        ("data/certs/siem-ca.crt", "ca\n"),
        ("data/assets/asset_map.yaml", "assets: []\n"),
        ("reference/llm_api_keys.env", "GROQ_API_KEY=Synthetic-Groq-77\n"),
    ):
        (repo / relative).parent.mkdir(parents=True, exist_ok=True)
        (repo / relative).write_text(text)
    yield Fake(root, repo, commit, uv, log, f"{bin_dir}:/usr/bin:/bin")
    for top, dirs, _files in os.walk(root):  # the release is read-only: let pytest clean up
        os.chmod(top, 0o755)  # noqa: S103
        for name in dirs:
            os.chmod(os.path.join(top, name), 0o755)  # noqa: S103


def _no_secret(done: subprocess.CompletedProcess[str]) -> None:
    for value in [*SECRETS.values(), "Synthetic-TLS-Key", "Synthetic-Groq-77"]:
        assert value not in done.stdout + done.stderr


def test_check_on_a_fresh_machine_lists_everything_and_changes_nothing(fake: Fake) -> None:
    before = sorted(p.relative_to(fake.root) for p in fake.root.rglob("*"))
    done = fake.run("--check")
    assert done.returncode == 1, done.stdout + done.stderr
    for item in ("to do: the group argus", "to do: the system user argus-svc",
                 "to do: /etc/argus/credentials (755 root:root)", "to do: a deploy copy",
                 "to do: the credentials (the import runs from the deploy copy"):  # fmt: skip
        assert item in done.stdout, item
    assert sorted(p.relative_to(fake.root) for p in fake.root.rglob("*")) == before
    assert fake.calls() == []
    _no_secret(done)


def test_an_install_makes_the_whole_layout(fake: Fake) -> None:
    done = fake.deploy()
    assert done.returncode == 0, done.stdout + done.stderr
    _no_secret(done)
    passwd = fake.under("/etc/passwd").read_text()
    for user in custody.SERVICE_USERS:
        (line,) = [entry for entry in passwd.splitlines() if entry.startswith(f"{user}:x:")]
        assert line.endswith(":/nonexistent:/usr/sbin/nologin")
    group = fake.under("/etc/group").read_text()
    assert "argus:x:" in group
    assert group.split("argus:x:")[1].split("\n")[0].split(":")[1].split(",") == list(
        custody.SERVICE_USERS
    )
    modes = {
        "/etc/argus": 0o755, "/etc/argus/credentials": 0o755, "/etc/argus/data": 0o750,
        "/var/lib/argus-backups": 0o700, "/opt/argus/releases": 0o755,
    }  # fmt: skip
    for path, mode in modes.items():
        assert stat.S_IMODE(fake.under(path).stat().st_mode) == mode, path
    release = fake.under(f"/opt/argus/releases/{TAG}-{fake.commit[:12]}")
    assert os.readlink(fake.under("/opt/argus/current")) == f"releases/{release.name}"
    writable = [p for p in release.rglob("*") if not p.is_symlink() and p.stat().st_mode & 0o222]
    assert writable == []
    assert f"commit={fake.commit}" in (release / ".argus-release").read_text()
    credentials = fake.under("/etc/argus/credentials")
    assert sorted(p.name for p in credentials.iterdir()) == sorted(
        set(custody.all_credentials())
        - {"siem.writer_api_key"}
        # the Kibana keys (Q-D2) are made at their own production steps, like the writer key
        - {"kibana.reader_api_key", "kibana.cases_writer_api_key", "kibana.alert_writer_api_key"}
        # the case team's six keys (AR8, D-159): made at the case team's own canary
        - set(custody.TEAM_KEYS)
        # AR10: the visualiser's key is the user's step (deploy/elk/make_case_team_user.py)
        - set(custody.OPTIONAL_TEAM_KEYS)
        # the case writer's database login and the approval key (Q-D4, Q-C3): made at its canary
        - {"database.writer_password", "approval-signing.key"}
        # the notices' relay password (Q-H4): only if the relay needs a login
        - {"notices.password"}
        # the outside threat-intel keys (AR3, D-165): each only when its source is used
        - {"outside.virustotal_api_key", "outside.shodan_api_key", "outside.censys_api_key"}
    )
    for path in credentials.iterdir():
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert (credentials / "database.owner_password").read_text() == "Synthetic-Owner-22"
    for name in custody.UNITS:
        installed = fake.under(f"/etc/systemd/system/{name}")
        assert installed.read_bytes() == (REPO_ROOT / "deploy/custody/units" / name).read_bytes()
        assert stat.S_IMODE(installed.stat().st_mode) == 0o644
    wrapper = fake.under("/usr/local/sbin/argus-owner")
    assert stat.S_IMODE(wrapper.stat().st_mode) == 0o755
    assert '"release": "' + release.name + '"' in fake.under("/etc/argus/custody.json").read_text()
    calls = fake.calls()
    assert "chown root:root " + str(credentials / "database.owner_password") in calls
    assert "chown root:argus " + str(fake.under("/etc/argus/argus.env")) in calls
    assert f"chown -R -h root:root {release}" in calls
    (uv_call,) = [c for c in calls if c.startswith("uv ")]
    for flag in ("sync --frozen --no-dev --compile-bytecode",
                 "--python /usr/bin/python3.12", "UV_PYTHON_DOWNLOADS=never", "UV_NO_CONFIG=1",
                 f"UV_PROJECT_ENVIRONMENT={release}/.venv"):  # fmt: skip
        assert flag in uv_call, flag
    assert not any(c.startswith("systemctl") for c in calls)  # never daemon-reload in a fake root
    assert not any(c.startswith("systemctl enable") or " start " in c for c in calls)
    assert "Next, the switch-over" in done.stdout
    assert "warning: op is in the group docker" in done.stdout


def test_a_second_run_changes_nothing_and_check_passes(fake: Fake) -> None:
    assert fake.deploy().returncode == 0
    calls = len(fake.calls())
    again = fake.deploy()
    assert again.returncode == 0, again.stdout
    assert "done:" not in again.stdout
    etc = str(fake.under("/etc/argus"))
    for call in fake.calls()[calls:]:  # only the import's files are chowned again, as they are
        assert call.startswith(("chown root:root " + etc, "chown root:argus " + etc)), call
    check = fake.deploy("--check")
    assert check.returncode == 0, check.stdout
    assert "0 to do" in check.stdout
    plain = fake.run("--check")  # without --tag: the installed release is checked as it is
    assert plain.returncode == 0, plain.stdout


def test_a_tag_that_is_not_the_approved_commit_is_refused(fake: Fake) -> None:
    (fake.repo / "deploy" / "custody" / "extra").write_text("later\n")
    _git(fake.repo, "add", "deploy")
    _git(fake.repo, "commit", "-q", "-m", "later")
    _git(fake.repo, "tag", "-f", TAG)  # the tag moved after the approval
    done = fake.deploy()
    assert done.returncode == 1
    assert f"the tag {TAG} is" in done.stderr
    assert "the deploy copy is made only of the commit you approved" in done.stderr
    assert not fake.under("/opt/argus/current").exists()


def test_a_credential_edited_or_loosened_after_install_is_reported(fake: Fake) -> None:
    assert fake.deploy().returncode == 0
    secret = fake.under("/etc/argus/credentials/siem.api_key")
    secret.chmod(0o644)
    env = (fake.repo / ".env").read_text().replace("Synthetic-Reader-44", "Synthetic-Reader-99")
    (fake.repo / ".env").write_text(env)
    done = fake.run("--check")
    assert done.returncode == 1
    assert "to do: credential siem.api_key has mode 644 (wanted 600)" in done.stdout
    assert "credential siem.api_key: kept" in done.stdout
    assert secret.read_text() == "Synthetic-Reader-44"
    assert "Synthetic-Reader-99" not in done.stdout


def test_an_existing_account_with_a_login_stops_the_install(fake: Fake) -> None:
    with fake.under("/etc/passwd").open("a") as passwd:
        passwd.write("argus-web:x:1001:1001:someone:/home/w:/bin/bash\n")
    done = fake.deploy()
    assert done.returncode == 1
    assert "argus-web exists but is not a system account without login" in done.stderr


def test_an_unfinished_release_is_rebuilt(fake: Fake) -> None:
    release = fake.under(f"/opt/argus/releases/{TAG}-{fake.commit[:12]}")
    release.mkdir(parents=True)
    (release / "half-done").write_text("x")
    done = fake.deploy()
    assert done.returncode == 0, done.stdout + done.stderr
    assert not (release / "half-done").exists()


def test_missing_required_secrets_leave_it_unfinished(fake: Fake) -> None:
    (fake.repo / ".env").write_text("ARGUS_DATABASE__PASSWORD=x\n")
    done = fake.deploy()
    assert done.returncode == 1
    assert "credential siem.api_key: MISSING" in done.stdout
    assert "a credential every service needs is missing" in done.stdout


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (["--tag", TAG], "--tag and --commit go together"),
        (["--tag", TAG, "--commit", "abc123"], "--commit is the full 40-character hash"),
        (["--tag", "../x", "--commit", "a" * 40], "a tag name"),
        (["--bogus"], "usage:"),
        (["--from", "/nonexistent-checkout"], "is not a folder"),
        (["--accept-settings", "xyz"], "--accept-settings takes the 16-character digest"),
    ],
)
def test_usage_errors(fake: Fake, args: list[str], message: str) -> None:
    done = fake.run(*args)
    assert done.returncode == 2
    assert message in done.stderr


def test_without_root_and_without_a_fake_root_it_refuses() -> None:
    if os.geteuid() == 0:
        pytest.skip("runs as root")
    done = subprocess.run([BASH, str(SCRIPT), "--check"], capture_output=True, text=True,
                          check=False)  # fmt: skip
    assert done.returncode == 2
    assert "run it as root" in done.stderr


RUNBOOK = REPO_ROOT / "docs" / "runbooks" / "custody.md"


def _plant(fake: Fake, relative: str, marker: Path) -> bytes:
    """Review F1's attack, as the operator's account can: a replacement for an approved file's
    blob and a filter in the checkout's own git settings. Returns the approved bytes."""
    approved = (REPO_ROOT / relative).read_bytes()
    planted = fake.repo.parent / "planted"
    planted.write_text(f"#!/usr/bin/bash\ntouch {marker}\n")
    blob = _git(fake.repo, "hash-object", "-w", str(planted))
    _git(fake.repo, "replace", _git(fake.repo, "rev-parse", f"{fake.commit}:{relative}"), blob)
    _git(fake.repo, "config", "filter.planted.smudge", f"touch {marker}; cat")
    (fake.repo / ".git" / "info").mkdir(exist_ok=True)
    (fake.repo / ".git" / "info" / "attributes").write_text("* filter=planted\n")
    # the checkout's own git now lies about the approved commit
    assert _git(fake.repo, "show", f"{fake.commit}:{relative}") != approved.decode().strip()
    return approved


def test_the_checkouts_git_settings_and_replacements_never_reach_the_release(fake: Fake) -> None:
    """Review F1: git never runs as root in the operator's checkout. The checkout's owner bundles
    the tag; root fetches the bundle into a fresh repository of its own (no settings but its
    own, no replacements, objects checked) and archives the approved commit from there."""
    marker = fake.repo.parent / "planted-ran"
    unit = "deploy/custody/units/argus-web.service"
    approved = _plant(fake, unit, marker)
    done = fake.deploy()
    assert done.returncode == 0, done.stdout + done.stderr
    release = fake.under(f"/opt/argus/releases/{TAG}-{fake.commit[:12]}")
    assert (release / unit).read_bytes() == approved
    for path in (REPO_ROOT / "deploy" / "custody").rglob("*"):
        if path.is_file():
            relative = path.relative_to(REPO_ROOT)
            assert (release / relative).read_bytes() == path.read_bytes(), relative
    assert not marker.exists()
    assert "safe.directory" not in SCRIPT.read_text()
    (bundle,) = [c for c in fake.calls() if c.startswith("runuser ")]
    owner = Path(fake.repo).owner()
    assert bundle.startswith(f"runuser -u {owner} -- ")
    assert f"git -C {fake.repo} bundle create" in bundle
    assert not list(fake.under("/var/cache/argus-build").glob("git.*"))  # the copy is removed


def test_the_runbooks_first_run_takes_the_script_from_a_clean_copy(fake: Fake) -> None:
    """Review F1, the first run: before any deploy copy exists, the runbook's root shell takes
    install.sh from a fresh root-owned repository fetched from the checkout's bundle, so a
    replacement or a filter planted in the checkout cannot change the script root runs."""
    marker = fake.repo.parent / "planted-ran"
    approved = _plant(fake, "deploy/custody/install.sh", marker)
    text = private_text(RUNBOOK)
    block = text.split("```\nH=<hash>", 1)[1].split("```", 1)[0]
    lines = block.strip().splitlines()
    build = fake.under("/var/cache/argus-build")
    first = f"H={fake.commit} T={TAG} C={fake.repo} OP={Path(fake.repo).owner()} B={build}"
    assert re.match(r"T=<tag> C=/\S+/argus OP=\S+ B=/var/cache/", lines[0])
    script = "\n".join([first, *lines[1:-1]]) + "\n"
    env = {k: v for k, v in os.environ.items() if not k.startswith("ARGUS_")}
    env["PATH"] = fake.path
    done = subprocess.run([BASH, "-euo", "pipefail", "-c", script], capture_output=True,
                          text=True, env=env, check=False, cwd="/")  # fmt: skip
    assert done.returncode == 0, done.stdout + done.stderr
    assert (build / "install.sh").read_bytes() == approved
    assert not marker.exists()
    assert lines[-1].startswith('bash "$B/install.sh" ')
    last = lines[-1].replace('"$B/install.sh"', str(build / "install.sh"))
    for name, value in (("$C", str(fake.repo)), ("$T", TAG), ("$H", fake.commit)):
        last = last.replace(f'"{name}"', value)
    command = [*shlex.split(last), "--root", str(fake.root), "--uv", str(fake.uv),
               "--operator", "op"]  # fmt: skip
    checked = subprocess.run(command, capture_output=True, text=True, env=env, check=False)
    assert checked.returncode == 1, checked.stdout + checked.stderr
    assert "to do: the release" in checked.stdout
    command.remove("--check")  # "then the same last line without --check"
    ran = subprocess.run(command, capture_output=True, text=True, env=env, check=False)
    assert ran.returncode == 0, ran.stdout + ran.stderr
    assert fake.under("/etc/argus/custody.json").is_file()
    assert not marker.exists()
    assert "git show <hash>:deploy/custody/install.sh | sudo bash" not in text


def test_a_changed_connection_setting_is_kept_until_accepted(fake: Fake) -> None:
    """Review F2 through the script: a later run keeps /etc/argus/argus.env and the CA, shows
    the difference and goes on only with the digest it printed."""
    assert fake.deploy().returncode == 0
    env_file, ca = fake.under("/etc/argus/argus.env"), fake.under("/etc/argus/certs/siem-ca.crt")
    before = env_file.read_bytes(), ca.read_bytes()
    with (fake.repo / ".env").open("a") as env:
        env.write("ARGUS_SIEM__URL=https://198.51.100.7:9200\n")
    (fake.repo / "data" / "certs" / "siem-ca.crt").write_text("planted ca\n")
    for args in ((), ("--check",)):
        done = fake.deploy(*args)
        assert done.returncode == 1, done.stdout + done.stderr
        assert (env_file.read_bytes(), ca.read_bytes()) == before
        assert "argus.env: ARGUS_SIEM__URL added 'https://198.51.100.7:9200'" in done.stdout
    digest = done.stdout.split("--accept-settings ", 1)[1].split()[0]
    assert fake.deploy("--accept-settings", "f" * 16).returncode == 1
    assert (env_file.read_bytes(), ca.read_bytes()) == before
    taken = fake.deploy("--accept-settings", digest)
    assert taken.returncode == 0, taken.stdout + taken.stderr
    assert "ARGUS_SIEM__URL='https://198.51.100.7:9200'" in env_file.read_text()
    assert ca.read_text() == "planted ca\n"
    assert fake.deploy("--check").returncode == 0


def test_the_deploy_copy_runs_argus_from_its_own_source_tree(fake: Fake) -> None:
    """Found while fixing the review: ARGUS finds config/ (llm.yaml, the data policy,
    signals.yaml) and deploy/ through ``Path(__file__).parents[3]``, which is the repository only
    when the package runs from its source tree. Installed into site-packages (--no-editable) the
    four paths fall inside .venv/lib/python3.12 and do not exist. So the release installs itself
    from its own read-only src/ (a .pth to it, no link to any checkout), compiled ahead (the
    release is read-only), and the local model's pinned certificate, which config/llm.yaml names
    as data/tls/local-llm.crt, points at the custody copy."""
    (fake.repo / "src" / "pkg").mkdir(parents=True)
    (fake.repo / "src" / "pkg" / "mod.py").write_text("VALUE = 1\n")
    _git(fake.repo, "add", "src")
    _git(fake.repo, "commit", "-q", "-m", "with source")
    _git(fake.repo, "tag", "-f", TAG)
    fake.commit = _git(fake.repo, "rev-parse", "HEAD")
    done = fake.deploy()
    assert done.returncode == 0, done.stdout + done.stderr
    (uv_call,) = [c for c in fake.calls() if c.startswith("uv ")]
    assert "--no-editable" not in uv_call
    release = fake.under(f"/opt/argus/releases/{TAG}-{fake.commit[:12]}")
    assert list((release / "src" / "pkg" / "__pycache__").glob("mod.*.pyc"))
    link = release / "data" / "tls" / "local-llm.crt"
    assert link.is_symlink()
    assert os.readlink(link) == "/etc/argus/tls/local-llm.crt"
    assert custody.DATA_FILES["tls/local-llm.crt"][0] == Path("data/tls/local-llm.crt")
    config = (REPO_ROOT / "config" / "llm.yaml").read_text()
    assert "ca_file: data/tls/local-llm.crt" in config
    writable = [p for p in release.rglob("*") if not p.is_symlink() and p.stat().st_mode & 0o222]
    assert writable == []

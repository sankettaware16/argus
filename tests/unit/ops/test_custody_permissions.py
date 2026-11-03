"""Q-A5's gate, enforced by the kernel rather than read from modes: in an unprivileged user
namespace (subordinate uids, no sudo) the custody files get the owners and modes install.sh
gives them, and processes running as the service users, and as the operator, try to read them.
Each service user fails to read any credential (another's, its own file: systemd hands a unit
its copy), the owner's password and the operator's reference/; reads argus.env through the
group argus; cannot change the deploy copy. Skipped where user namespaces are not available."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from argus.ops import custody
from tests.unit.ops.test_custody_import import checkout

pytestmark = pytest.mark.unit

UNSHARE = shutil.which("unshare")
# inside the namespace: 0 = this user (the files' "root"), the rest subordinate uids
OPERATOR, SVC, WEB, WRITER, ARGUS_GID = 1000, 1001, 1002, 1003, 900
PROBE = textwrap.dedent(
    """
    import json, os, shutil, sys
    from pathlib import Path

    # a tmpfs of this mount namespace, mode 0755 like / (pytest's folders are 0700)
    base = Path("/mnt/custody")
    shutil.copytree(sys.argv[1], base, symlinks=True)
    etc, release, home = base / "etc", base / "release", base / "home"
    # what install.sh does (chown is root's: here the namespace's root)
    for path in [etc, *etc.rglob("*"), release, *release.rglob("*")]:
        os.lchown(path, 0, 0)
    for path in (etc / "argus.env", etc / "data", etc / "data" / "asset_map.yaml"):
        os.chown(path, 0, {gid})
    for folder, mode in (("", 0o755), ("credentials", 0o755), ("certs", 0o755),
                         ("tls", 0o755), ("data", 0o750)):  # install.sh's folder modes
        os.chmod(etc / folder, mode)
    for top, dirs, files in os.walk(release):
        for name in files:
            os.chmod(os.path.join(top, name), 0o444)
        os.chmod(top, 0o555)
    os.chown(home, {operator}, {operator})
    os.chmod(home, 0o750)
    for path in [*home.rglob("*")]:
        os.chown(path, {operator}, {operator})

    def attempt(uid, groups):
        read, write = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(read)
            os.setgroups(groups)
            os.setgid(uid)
            os.setuid(uid)
            out = {{}}
            for path in sorted(p for p in etc.rglob("*") if p.is_file() or not p.exists()):
                try:
                    path.read_bytes()
                    out[str(path.relative_to(base))] = "read"
                except OSError as exc:
                    out[str(path.relative_to(base))] = exc.strerror
            for name in ("reference/llm_api_keys.env", "data/tls/argus.key"):
                try:
                    (home / name).read_bytes()
                    out["home/" + name] = "read"
                except OSError as exc:
                    out["home/" + name] = exc.strerror
            try:
                (release / "planted.py").write_text("x")
                out["release write"] = "written"
            except OSError as exc:
                out["release write"] = exc.strerror
            try:
                (etc / "credentials" / "planted").write_text("x")
                out["credentials write"] = "written"
            except OSError as exc:
                out["credentials write"] = exc.strerror
            os.write(write, json.dumps(out).encode())
            os._exit(0)
        os.close(write)
        data = b""
        while chunk := os.read(read, 65536):
            data += chunk
        os.waitpid(pid, 0)
        return json.loads(data)

    users = {{"svc": {svc}, "web": {web}, "writer": {writer}}}
    result = {{name: attempt(uid, [uid, {gid}]) for name, uid in users.items()}}
    result["operator"] = attempt({operator}, [{operator}])
    print(json.dumps(result))
    """
).format(gid=ARGUS_GID, operator=OPERATOR, svc=SVC, web=WEB, writer=WRITER)


def _namespace_works() -> bool:
    if UNSHARE is None or os.geteuid() == 0:
        return False
    done = subprocess.run(  # noqa: S603
        # the test's own flags: a CI runner may allow the user namespace but not the mount one
        [UNSHARE, "--map-auto", "--map-root-user", "--mount", "/usr/bin/true"],
        capture_output=True, check=False,
    )  # fmt: skip
    return done.returncode == 0


@pytest.mark.skipif(not _namespace_works(), reason="no unprivileged user namespace here")
def test_the_kernel_keeps_every_credential_from_every_service_user(tmp_path: Path) -> None:
    base = tmp_path / "custody"
    base.mkdir()
    source = checkout(tmp_path)
    report = custody.import_checkout(source, base / "etc", check=False)
    assert report.missing == []
    for name, value in (
        ("siem.writer_api_key", "Synthetic-Writer-55"),
        # the Kibana keys (Q-D2), made at their own production steps like the writer key
        ("kibana.reader_api_key", "Synthetic-KibanaReader-66"),
        ("kibana.cases_writer_api_key", "Synthetic-CasesWriter-77"),
        ("kibana.alert_writer_api_key", "Synthetic-AlertWriter-88"),
        # the case team's six keys (AR8, D-159)
        ("case_team.lead_api_key", "Synthetic-TeamLead-31"),
        ("case_team.evidence_api_key", "Synthetic-TeamEvidence-32"),
        ("case_team.intel_api_key", "Synthetic-TeamIntel-33"),
        ("case_team.responder_api_key", "Synthetic-TeamResponder-34"),
        ("case_team.hunter_api_key", "Synthetic-TeamHunter-35"),
        ("case_team.reporter_api_key", "Synthetic-TeamReporter-36"),
        ("case_team.visualiser_api_key", "Synthetic-TeamVisualiser-37"),  # AR10
        # the writer's own database login (Q-D4) and the approval key (Q-C3), made at the
        # first canary
        ("database.writer_password", "Synthetic-DbWriter-99"),
        ("approval-signing.key", "Synthetic-ApprovalKey-00"),
        # the notices' relay password (Q-H4): optional, made only when the relay needs a login
        ("notices.password", "Synthetic-Relay-11"),
        # the outside threat-intel keys (AR3, D-165): optional, each made when its source is used
        ("outside.virustotal_api_key", "Synthetic-VirusTotal-12"),
        ("outside.shodan_api_key", "Synthetic-Shodan-13"),
        ("outside.censys_api_key", "Synthetic-Censys-14"),
    ):
        (base / "etc" / "credentials" / name).write_text(value)
        (base / "etc" / "credentials" / name).chmod(0o600)
    release = base / "release"
    (release / "src").mkdir(parents=True)
    (release / "src" / "module.py").write_text("x = 1\n")
    home = base / "home"
    (home / "reference").mkdir(parents=True)
    (home / "data" / "tls").mkdir(parents=True)
    shutil.copy(source / "reference" / "llm_api_keys.env", home / "reference")
    shutil.copy(source / "data" / "tls" / "argus.key", home / "data" / "tls")
    (home / "reference" / "llm_api_keys.env").chmod(0o644)  # even a loose file in the home
    done = subprocess.run(  # noqa: S603
        [UNSHARE, "--map-auto", "--map-root-user", "--mount", "/usr/bin/sh", "-c",
         'mount -t tmpfs -o mode=0755 tmpfs /mnt && exec "$0" -I -c "$1" "$2"',
         sys.executable, PROBE, str(base)],
        capture_output=True, text=True, check=False, timeout=60,
    )  # fmt: skip
    assert done.returncode == 0, done.stderr
    seen = json.loads(done.stdout)
    credentials = [f"etc/credentials/{name}" for name in custody.all_credentials()]
    for who in ("svc", "web", "writer", "operator"):
        for path in credentials:
            assert seen[who][path] == "Permission denied", (who, path)
        assert seen[who]["release write"] == "Permission denied", who
        assert seen[who]["credentials write"] == "Permission denied", who
    for who in ("svc", "web", "writer"):
        assert seen[who]["home/reference/llm_api_keys.env"] == "Permission denied", who
        assert seen[who]["home/data/tls/argus.key"] == "Permission denied", who
        assert seen[who]["etc/argus.env"] == "read", who  # through the group argus
        assert seen[who]["etc/data/asset_map.yaml"] == "read", who
        assert seen[who]["etc/certs/siem-ca.crt"] == "read", who
    # the operator is not in the group argus: the asset map and settings are the services'
    assert seen["operator"]["etc/argus.env"] == "Permission denied"
    assert seen["operator"]["home/reference/llm_api_keys.env"] == "read"  # its own home

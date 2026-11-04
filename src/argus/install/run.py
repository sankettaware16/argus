"""``argus init``'s steps, in order. Each is idempotent: a rerun keeps
what exists, says "kept", and repairs only what is missing or wrong; nothing is overwritten
without a ``--force-<thing>`` flag or an explicit answer. The side effects (commands, TLS, the
SIEM, systemd) come from a ``Host``, which the tests replace with fakes."""

from __future__ import annotations

import base64
import contextlib
import dataclasses
import getpass
import ipaddress
import os
import re
import shutil
import socket
import subprocess
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

from argus.config.settings import ConfigError, Settings, load_settings
from argus.install import files, prereq, roles, webcert
from argus.install.answers import Asker, InitError
from argus.install.siem import GatewayReads, SiemReads
from argus.install.trust import RealTls, Tls, establish, host_port
from argus.observability.redaction import register_secret
from argus.ops import units

SIEM_KEY = "ARGUS_SIEM__API_KEY"
KIBANA_KEY = "ARGUS_KIBANA__READER_API_KEY"
SIEM_CA = Path("data/certs/siem-ca.crt")  # siem.ca_file's default (and Kibana's)
KIBANA_CA = Path("data/certs/kibana-ca.crt")
LLM_HEADER = (
    "# This installation's LLM keys file (D-298), laid over config/llm.yaml; written by\n"
    "# `argus init`. keys_file: null means no keys: every LLM feature is off.\n"
)
HEALTH_WAIT_S = 120
WEB_CERT = Path("data/tls/argus.crt")
WEB_KEY = Path("data/tls/argus.key")
WEB_CREDENTIAL = "database.api_password"
BACKUPS = ("argus-backup.timer", "argus-backup-drill.timer")


@dataclass(frozen=True)
class Options:
    root: Path  # the checkout: where .env, config/ and docker-compose.yml are
    config: Path  # its config/argus.yaml
    start: bool = False
    compose: bool = True
    force_trust: bool = False
    force_key: bool = False
    force_site: bool = False
    llm_file: Path | None = None  # the LLM overlay; by default beside config/llm.yaml

    @property
    def env_file(self) -> Path:
        return self.root / ".env"

    @property
    def local_file(self) -> Path:
        return self.config.parent / "local.yaml"

    @property
    def site_file(self) -> Path:
        return self.config.parent / "site.yaml"

    @property
    def llm_overlay(self) -> Path:
        """Where ``load_config`` reads the overlay: beside the LLM configuration of the code."""
        if self.llm_file is not None:
            return self.llm_file
        from argus.llm.providers import DEFAULT_PATH, LOCAL_OVERLAY

        return DEFAULT_PATH.with_name(LOCAL_OVERLAY)


def _bootstrap(config: Path) -> None:
    import typer

    from argus.cli import db_bootstrap

    try:
        db_bootstrap(config=config)
    except typer.Exit as exc:
        if exc.exit_code:
            raise InitError("`argus db bootstrap` failed (the error is above)") from None


def _upgrade(config: Path) -> None:
    import typer

    from argus.cli import db_upgrade

    try:
        db_upgrade(revision="head", no_backup=False, config=config)
    except typer.Exit as exc:
        if exc.exit_code:
            raise InitError("`argus db upgrade` failed (the error is above)") from None


def _doctor(config: Path) -> int:
    import typer

    from argus.cli import doctor

    try:
        doctor(config=config)
    except typer.Exit as exc:
        return int(exc.exit_code or 0)
    return 0


def _systemctl(argv: list[str]) -> int:
    return prereq.run_command(["systemctl", "--user", *argv]).returncode


def _uv() -> str | None:
    try:
        return units.default_uv()
    except units.UnitsError:
        return None


def _local_ip(towards: str) -> str | None:
    """The address of this machine on the route to ``towards`` (no packet is sent)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect((towards, 9))
            address: str = probe.getsockname()[0]
    except OSError:
        return None
    return None if address.startswith("127.") else address


def _people(config: Path) -> int:
    import asyncio

    from sqlalchemy import text

    from argus.db.engine import create_engine

    async def count() -> int:
        engine = create_engine(load_settings(config).database)
        try:
            async with engine.connect() as conn:
                found = await conn.execute(text("SELECT count(*) FROM users WHERE kind = 'person'"))
                return int(found.scalar_one())
        finally:
            await engine.dispose()

    return asyncio.run(count())


def _add_person(config: Path, username: str, name: str, password: str) -> None:
    import asyncio

    from argus.db.engine import create_engine
    from argus.web import auth
    from argus.web.capabilities import Capability

    async def add() -> None:
        engine = create_engine(load_settings(config).database)
        try:
            async with engine.begin() as conn:
                await auth.add_user(conn, username, name, password, list(Capability))
                await auth.audit(conn, actor="cli", action="user.add", target_type="user",
                                 target_id=username, details={"capabilities": ["all"],
                                                              "by": "argus init"})  # fmt: skip
        finally:
            await engine.dispose()

    asyncio.run(add())


@dataclass
class Host:
    say: Callable[[str], None]
    run: prereq.Runner = prereq.run_command
    which: Callable[[str], str | None] = shutil.which
    port_free: Callable[[str, int], bool] = prereq.port_free
    disk_free: Callable[[Path], int] = field(default=lambda p: shutil.disk_usage(p).free)
    sleep: Callable[[float], None] = time.sleep
    tls: Tls = field(default_factory=RealTls)
    siem: SiemReads = field(default_factory=GatewayReads)
    unit_dir: Path | None = None  # the user's unit directory by default
    systemctl: Callable[[list[str]], int] = _systemctl
    bootstrap: Callable[[Path], None] = _bootstrap
    upgrade: Callable[[Path], None] = _upgrade
    doctor: Callable[[Path], int] = _doctor
    uv: Callable[[], str | None] = _uv
    local_ip: Callable[[str], str | None] = _local_ip
    people: Callable[[Path], int] = _people
    add_person: Callable[[Path, str, str, str], None] = _add_person
    user: Callable[[], str] = getpass.getuser


class Init:
    def __init__(self, options: Options, asker: Asker, host: Host) -> None:
        self.o = options
        self.ask = asker
        self.host = host
        self.say = host.say
        self.container = prereq.CONTAINER

    # ------------------------------------------------------------------ helpers

    def settings(self) -> Settings:
        try:
            settings = load_settings(self.o.config, env_file=self.o.env_file)
        except ConfigError as exc:
            raise InitError(f"the configuration does not load:\n{exc}", 2) from None
        for secret in settings.secret_values():
            register_secret(secret)
        return settings

    def step(self, number: int, title: str) -> None:
        self.say(f"\n{number}. {title}")

    def value(self, name: str, question: str, current: str | None) -> str:
        """A value that may already be configured: kept unless the answers file names it (or a
        person types another one)."""
        if current is not None and self.ask.scripted and not self.ask.given(name):
            return current
        return self.ask.text(name, question, current)

    # ------------------------------------------------------------------ the steps

    def run(self) -> int:
        self.prerequisites()
        self.env()
        self.database()
        siem_url, kibana_url = self.addresses()
        self.keys(kibana_url)
        self.site(siem_url)
        self.llm()
        address = self.web(siem_url)
        started = self.units()
        self.step(10, "argus doctor")
        code = self.host.doctor(self.o.config)
        if code:
            self.say(
                "\ninit: set up, but doctor found a failure (above): fix it and run argus init"
                " again (it keeps everything that is done)"
            )
        elif started:
            where = (
                f"https://{address}:{self.settings().web.port}/"
                if address
                else (f"http://127.0.0.1:{self.settings().web.port}/ on this machine")
            )
            self.say(f"\ninit: done; ARGUS is running. Open {where} and sign in")
        else:
            self.say("\ninit: done; ARGUS is set up but not started: argus init --start starts it")
        return code

    def prerequisites(self) -> None:
        self.step(1, "prerequisites")
        from argus.ops import custody

        if custody.marker() is not None:
            raise InitError(
                "custody is installed here (Q-A5): its secrets are root's credentials; argus init"
                " sets up the shared layout only"
            )
        env = files.read_env(self.o.env_file)
        try:
            port = int(env.get("ARGUS_DATABASE__PORT", files.ENV_DEFAULTS["ARGUS_DATABASE__PORT"]))
        except ValueError:
            raise InitError("ARGUS_DATABASE__PORT in .env is not a number", 2) from None
        self.container, project = prereq.compose_names(env)
        found = prereq.check(
            self.o.root,
            container=self.container,
            project=project,
            compose=self.o.compose,
            port=port,
            uv=self.host.uv(),
            which=self.host.which,
            run=self.host.run,
            free=self.host.port_free,
            disk_free=self.host.disk_free,
        )
        for finding in found:
            label = "ok" if finding.ok and not finding.warn else "warn" if finding.ok else "MISSING"
            self.say(f"   {label}: {finding.text}")
        if not all(f.ok for f in found):
            raise InitError("a prerequisite is missing (above): fix it and run argus init again")
        self.moved()

    def moved(self) -> None:
        """A checkout copied or cloned from another machine names that one's folder and uv in
        config/local.yaml: they become this checkout's, or its units would run the other."""
        local = files.read_yaml(self.o.local_file)
        old = files.get(local, "units.root")
        changes: dict[str, Any] = {}
        if isinstance(old, str) and Path(old).resolve() != self.o.root.resolve():
            base = old.rstrip("/")
            for name, value in _strings(local):
                if value == base or value.startswith(base + "/"):
                    changes[name] = str(self.o.root) + value[len(base) :]
        uv = files.get(local, "units.uv")
        if isinstance(uv, str) and not Path(uv).is_file():
            found = self.host.uv()
            if found is not None:
                changes["units.uv"] = found
        if changes:
            files.update_yaml(self.o.local_file, changes)
            self.say(
                f"   moved: config/local.yaml named {old} (another checkout); {len(changes)}"
                f" paths now name this one ({', '.join(changes)})"
            )

    def env(self) -> None:
        self.step(2, ".env (the database passwords; never shown)")
        before = set(files.read_env(self.o.env_file))
        # The web's own login only for a new database: an installation whose .env holds
        # a database password may keep the web's elsewhere (a credential folder), and a new one
        # would replace it. A .env with only compose's names (a second ARGUS here) is new.
        new = not before & {"ARGUS_DATABASE__PASSWORD", "ARGUS_DATABASE__OWNER_PASSWORD"}
        made = [n for n in files.GENERATED if n != files.WEB_PASSWORD or new]
        values = {**files.ENV_DEFAULTS, **{n: files.new_password() for n in made}}
        written = files.update_env(self.o.env_file, values)
        kept = sorted(before & set(values))
        if written:
            self.say(f"   written: {', '.join(written)} (mode 600)")
        if kept:
            self.say(f"   kept: {len(kept)} values already in .env")
        now = files.read_env(self.o.env_file)
        weak = [n for n in files.GENERATED if now.get(n) in files.PLACEHOLDERS]
        if weak:
            self.say(
                f"   warn: {', '.join(weak)} still hold .env.example's placeholder: change them"
                " (and the database's) before ARGUS holds real data"
            )

    def database(self) -> None:
        self.step(3, "the database")
        if self.o.compose:
            done = self.host.run(["docker", "compose", "up", "-d", "db"])
            if done.returncode != 0:
                last = (done.stderr.strip().splitlines() or ["(no message)"])[-1][:300]
                raise InitError(f"`docker compose up -d db` failed: {last}")
            self.say("   docker compose: db is up")
            self.wait_healthy()
        folder = self.web_credentials()
        with _credentials(folder):
            self.host.bootstrap(self.o.config)
        if folder is not None:
            self.say(f"   the web's own login: its password from {folder}")
        self.host.upgrade(self.o.config)
        env = files.read_env(self.o.env_file)
        local = files.read_yaml(self.o.local_file)
        if (
            env.get("ARGUS_DATABASE__API_PASSWORD")
            and files.get(local, "web.database_role") is None
            and files.get(local, "units.web.database_role") is None
        ):
            files.update_yaml(self.o.local_file, {"web.database_role": "api"})
            self.say("   the web logs in with its own login (web.database_role: api, Q-A2)")

    def web_credentials(self) -> Path | None:
        """The web unit's credentials folder when it holds the web's database password and .env
        does not: `argus db bootstrap` must see it to make the web's own login."""
        if files.read_env(self.o.env_file).get(files.WEB_PASSWORD):
            return None
        folder = files.get(files.read_yaml(self.o.local_file), "units.web.credentials")
        if not isinstance(folder, str):
            return None
        path = Path(folder) if Path(folder).is_absolute() else self.o.root / folder
        return path if (path / WEB_CREDENTIAL).is_file() else None

    def wait_healthy(self) -> None:
        waited = 0.0
        while True:
            done = self.host.run(
                ["docker", "inspect", "--format",
                 "{{if .State.Health}}{{.State.Health.Status}}{{end}}", self.container]
            )  # fmt: skip
            if done.returncode == 0 and done.stdout.strip() == "healthy":
                self.say("   healthy")
                return
            if waited >= HEALTH_WAIT_S:
                raise InitError(
                    f"{self.container} is not healthy after {HEALTH_WAIT_S} s:"
                    f" docker logs {self.container}"
                )
            self.host.sleep(2.0)
            waited += 2.0

    def addresses(self) -> tuple[str, str | None]:
        self.step(4, "the SIEM and Kibana: addresses and trust")
        local = files.read_yaml(self.o.local_file)
        url = self.value(
            "siem.url",
            "The SIEM's Elasticsearch address (https://host:9200)",
            files.get(local, "siem.url"),
        )
        _https(url, "siem.url")
        siem_ca = self.o.root / (files.get(local, "siem.ca_file") or SIEM_CA)
        trusted = establish("siem", url, siem_ca, self.ask, self.host.tls, self.say,
                            force=self.o.force_trust)  # fmt: skip
        self.say(f"   SIEM {url}: {trusted.how}")
        changes: dict[str, Any] = {
            "siem.url": url,
            "siem.ca_file": str(_relative(trusted.ca_file, self.o.root)),
        }
        current = files.get(local, "kibana.url")
        if current is not None and self.ask.scripted and not self.ask.given("kibana.url"):
            kibana: str | None = current
        else:
            kibana = self.ask.optional(
                "kibana.url", "Kibana's address (https://host:5601)", current
            )
        if kibana is None and current is not None:
            kibana = current  # init never removes configuration
            self.say(f"   Kibana: kept {current} (remove kibana: from config/local.yaml to stop)")
        if kibana is not None:
            _https(kibana, "kibana.url")
            given = files.get(local, "kibana.ca_file")
            target = self.o.root / (given or KIBANA_CA)
            if given is None and self._shares(kibana, siem_ca):
                target = siem_ca  # the SIEM's CA verifies Kibana: one pin
            k = establish("kibana", kibana, target, self.ask, self.host.tls, self.say,
                          force=self.o.force_trust, shared=siem_ca)  # fmt: skip
            self.say(f"   Kibana {kibana}: {k.how}")
            changes["kibana.url"] = kibana
            changes["kibana.ca_file"] = str(_relative(k.ca_file, self.o.root))
        else:
            self.say("   Kibana: not used (no read-back of cases; discovery reads Elasticsearch)")
        written = files.update_yaml(self.o.local_file, changes)
        self.say(f"   config/local.yaml: {'written ' + ', '.join(written) if written else 'kept'}")
        return url, kibana

    def _shares(self, url: str, siem_ca: Path) -> bool:
        return siem_ca.is_file() and self.host.tls.verify(url, siem_ca) is None

    def keys(self, kibana_url: str | None) -> None:
        self.step(5, "the read-only keys (init creates no user, role or key on the SIEM)")
        env = files.read_env(self.o.env_file)
        settings = self.settings()
        have_site = self.o.site_file.is_file() and not self.o.force_site
        patterns: list[str] = []
        if env.get(SIEM_KEY) and not self.o.force_key:
            self.say("   SIEM key: kept (in .env)")
        else:
            patterns = self.ask.items(
                "siem.log_patterns",
                "The index patterns of your logs, for the key's starting role",
                list(roles.STARTING_LOGS),
            )
            names = roles.es_names(settings.site) if have_site else roles.starting_names(patterns)
            self.say("   The key ARGUS needs (read-only; narrowed after discovery):\n")
            self.say(_indent(roles.es_request(names)))
            self.say(_indent(roles.HOW))
            key = self.api_key("siem.api_key", "Paste the SIEM key (not shown)", "the SIEM key")
            assert key is not None
            register_secret(key)
            files.update_env(self.o.env_file, {SIEM_KEY: key}, replace=frozenset({SIEM_KEY}))
            self.say("   SIEM key: stored in .env (ARGUS_SIEM__API_KEY)")
        changes: dict[str, Any] = {}
        self.expiry("siem.api_key_expires", "When does the SIEM key expire", changes)
        if kibana_url is not None:
            if env.get(KIBANA_KEY) and not self.o.force_key:
                self.say("   Kibana key: kept (in .env)")
                changes["kibana.enabled"] = True
            else:
                self.say("\n   Kibana's read-only key (Cases read; the read-back of cases):\n")
                self.say(_indent(roles.kibana_request(settings.site, every_space=not have_site)))
                self.say(_indent(roles.HOW))
                key = self.api_key("kibana.api_key", "Paste Kibana's key (not shown)",
                                   "Kibana's key", required=False)  # fmt: skip
                if key is None and env.get(KIBANA_KEY):
                    self.say("   Kibana key: kept (in .env)")
                    changes["kibana.enabled"] = True
                elif key is None:
                    self.say("   Kibana key: none (Kibana stays off; argus init again to add it)")
                else:
                    register_secret(key)
                    files.update_env(self.o.env_file, {KIBANA_KEY: key},
                                     replace=frozenset({KIBANA_KEY}))  # fmt: skip
                    changes["kibana.enabled"] = True
                    self.say("   Kibana key: stored in .env (ARGUS_KIBANA__READER_API_KEY)")
            if changes.get("kibana.enabled"):
                self.expiry(
                    "kibana.api_key_expires",
                    "When does Kibana's key expire",
                    changes,
                    setting="kibana.reader_api_key_expires",
                )
        if changes:
            files.update_yaml(self.o.local_file, changes)
        if changes.get("kibana.enabled"):
            self.say(
                "   Kibana writes stay off (kibana.write_classes is empty, D-109): ARGUS reads"
                " cases back and writes nothing until a person names a write class, gives the"
                " writer its own key and is there for its first write (docs/install.md)"
            )
        settings = self.settings()
        if have_site:
            names = roles.es_names(settings.site)
        elif patterns:
            names = roles.starting_names(patterns)
        else:  # a kept key, no site yet: the alerts of every space (the logs come with the site)
            names = list(roles.STARTING_ALERTS)
        problems = self.host.siem.check_key(settings, names)
        if problems:
            raise InitError(
                "the SIEM key is not what ARGUS needs: " + "; ".join(problems)
                + " (make one with the request above: argus init --force-key)"
            )  # fmt: skip
        self.say(f"   SIEM key: an API key, read-only, reads {', '.join(names)}")

    def expiry(
        self, name: str, question: str, changes: dict[str, Any], setting: str | None = None
    ) -> None:
        """A key's recorded expiry (doctor warns 30 days ahead): kept when recorded, unless the
        answers name it again."""
        setting = setting or name
        current = files.get(files.read_yaml(self.o.local_file), setting)
        if current is not None and not self.ask.given(name):
            return
        question += ': YYYY-MM-DD, "expiration" from the answer, or 90d'
        while True:
            value = self.ask.optional(name, question, None if current is None else str(current))
            if value is None:
                return
            try:
                changes[setting] = expiry_date(value, datetime.now(UTC).date())
                return
            except ValueError:
                problem = (
                    f"{name}: {value!r} is not a date: give YYYY-MM-DD, the number after"
                    ' "expiration" in the answer, or a number of days such as 90d'
                )
                if self.ask.scripted:
                    raise InitError(problem, 2) from None
                self.say(f"   not taken: {problem}")

    def api_key(self, name: str, question: str, what: str, required: bool = True) -> str | None:
        """An API key in its encoded form, asked again at the terminal until it is one."""
        while True:
            value = self.ask.secret(name, question, required=required)
            if value is None:
                return None
            key = clean_key(value)
            problem = key_problem(key)
            if problem is None:
                return key
            if self.ask.scripted:
                raise InitError(f"{what}: {problem}", 2)
            self.say(f"   not taken: {problem}")

    def site(self, siem_url: str) -> None:
        self.step(6, "the organisation and its Elastic (config/site.yaml)")
        settings = self.settings()
        if self.o.site_file.is_file() and not self.o.force_site:
            site = settings.site
            self.say(
                f"   kept config/site.yaml: space {site.space}, {len(site.families)} log families,"
                f" {len(site.ti_sources)} threat-intel sources (--force-site discovers again)"
            )
        else:
            text = self.proposal(settings)
            self.say("\n   config/site.yaml will be:\n")
            self.say(_indent(text))
            if not self.ask.confirm("discovery.accept", "Write it to config/site.yaml?", True):
                raise InitError(
                    "nothing written: run argus init again to answer differently, or write"
                    " config/site.yaml yourself (argus discover --write) and run argus init again"
                )
            files.write_public(self.o.site_file, text)
            self.say("   written: config/site.yaml")
            settings = self.settings()
        problems = self.host.siem.selftest(settings)
        if problems:
            raise InitError(
                "the SIEM self-test failed: " + "; ".join(problems)
                + " (the key needs the exact role below: argus init --force-key)\n\n"
                + roles.es_request(roles.es_names(settings.site))
            )  # fmt: skip
        self.say(f"   SIEM self-test: passed ({siem_url})")
        if settings.kibana.enabled:
            kproblems = self.host.siem.kibana_check(settings)
            if kproblems is None:
                self.say(
                    "   Kibana key: not checked now (its lane is paced; discovery spent this"
                    " minute's share): check it later with `argus kibana selftest`"
                )
            elif kproblems:
                raise InitError(
                    "Kibana's key is not what ARGUS needs: " + "; ".join(kproblems)
                    + "\n\n" + roles.kibana_request(settings.site)
                )  # fmt: skip
            else:
                self.say("   Kibana key: Cases read in the space, no write")
        self.say("\n   The exact keys for this site (narrower than a starting key; replace the")
        self.say("   keys with these when convenient, then argus init --force-key):\n")
        self.say(_indent(roles.es_request(roles.es_names(settings.site))))
        if settings.kibana.enabled:
            self.say(_indent(roles.kibana_request(settings.site)))

    def proposal(self, settings: Settings) -> str:
        """The organisation's answers and discovery's proposal, as site.yaml's text."""
        from argus.discover.propose import checked_yaml, render_text

        org = self.organisation()
        self.say("   discovering (a few read-only requests to the SIEM and Kibana) ...")
        proposal = self.host.siem.discover(settings)
        self.say(_indent(render_text(proposal)))
        if not proposal.listing_read:
            from argus.discover.run import nothing_proposed

            raise InitError(nothing_proposed(datetime.now(UTC)))
        prefix = ".alerts-security.alerts-"
        found = [a.removeprefix(prefix) for a in proposal.alerts_aliases if a.startswith(prefix)]
        spaces = list(dict.fromkeys(proposal.spaces or found))
        default = proposal.space if proposal.space is not None else (spaces[0] if spaces else None)
        space = self.ask.choose(
            "organisation.space",
            "The Kibana space that holds the Security alerts",
            spaces,
            default,
        )
        chosen = dataclasses.replace(proposal, space=space, space_evidence="chosen at argus init")
        try:
            text = checked_yaml(chosen)
        except ValueError as exc:
            raise InitError(f"the proposal cannot be written: {exc}") from None
        block = yaml.safe_dump({"site": org}, default_flow_style=False, sort_keys=False, width=100)
        org_lines = block.splitlines()[1:]  # under the site: key already in text
        full = text.rstrip("\n") + "\n  # The organisation, as argus init was told\n"
        full += "\n".join(org_lines) + "\n"
        from argus.site import SiteSettings

        try:
            SiteSettings.model_validate(yaml.safe_load(full)["site"])
        except (ValueError, KeyError, TypeError) as exc:
            raise InitError(f"the site does not validate: {exc}") from None
        return full

    def organisation(self) -> dict[str, Any]:
        """The organisation's answers, each checked as the site checks it."""
        from argus.site import Organisation, SiteSettings

        def checked(name: str, ask: Callable[[], Any], key: str, model: type[Any]) -> Any:
            while True:
                try:
                    value = ask()
                    model.model_validate({key: value})
                    return value
                except ValueError as exc:
                    reason = str(exc).splitlines()[-1].strip()[:200]
                    if self.ask.scripted:
                        raise InitError(f"{name}: {reason}", 2) from None
                    self.say(f"   not taken: {reason}")

        org: dict[str, Any] = {}
        org["name"] = checked("organisation.name", lambda: self.ask.text(
            "organisation.name", "The organisation's name"), "name", Organisation)  # fmt: skip
        org["short_name"] = checked("organisation.short_name", lambda: self.ask.text(
            "organisation.short_name", "The security team's name (the page header)"),
            "short_name", Organisation)  # fmt: skip
        kind = checked("organisation.kind", lambda: self.ask.text(
            "organisation.kind", "What kind of organisation it is (a lower-case noun)",
            "organisation"), "kind", Organisation)  # fmt: skip
        if kind != "organisation":
            org["kind"] = kind
        site: dict[str, Any] = {"organisation": org}
        site["own_domains"] = checked("organisation.own_domains", lambda: _need(self.ask.items(
            "organisation.own_domains",
            "The organisation's own domains (at least one; the privacy layer replaces them)",
        ), "organisation.own_domains"), "own_domains", SiteSettings)  # fmt: skip
        networks = checked("organisation.own_networks", lambda: self.ask.items(
            "organisation.own_networks", "Its public networks (CIDR)"),
            "own_networks", SiteSettings)  # fmt: skip
        if networks:
            site["own_networks"] = networks
        site["timezone"] = checked("organisation.timezone", lambda: self.ask.text(
            "organisation.timezone", "The time zone people read times in (IANA: Europe/Berlin)",
            "UTC"), "timezone", SiteSettings)  # fmt: skip
        label = checked("organisation.timezone_label", lambda: self.ask.optional(
            "organisation.timezone_label", "How a time in it is labelled (CET)"),
            "timezone_label", SiteSettings)  # fmt: skip
        if label is not None:
            site["timezone_label"] = label
        site["incident_id_prefix"] = checked("organisation.incident_id_prefix", lambda: (
            self.ask.text("organisation.incident_id_prefix",
                          "The prefix of incident case ids (capital letters: SOC-IR)", "IR")
        ), "incident_id_prefix", SiteSettings)  # fmt: skip
        return site

    def llm(self) -> None:
        self.step(7, "the LLM providers' keys (optional)")
        overlay = self.o.llm_overlay
        current = files.read_yaml(overlay).get("keys_file") if overlay.is_file() else None
        if overlay.is_file() and self.ask.scripted and not self.ask.given("llm.keys_file"):
            self.say(f"   kept config/llm.local.yaml (keys_file: {current or 'none'})")
            if current is None:
                self.say(_NO_MODEL)
            return
        value = self.ask.optional(
            "llm.keys_file", "The providers' keys file (NAME=value lines, mode 600)", current
        )
        if value is None:
            files.update_yaml(overlay, {"keys_file": None}, header=LLM_HEADER)
            self.say(_NO_MODEL)
            return
        path = Path(value).expanduser().resolve()
        if not path.is_file():
            raise InitError(f"llm.keys_file: {path} does not exist", 2)
        if path.stat().st_mode & 0o077:
            raise InitError(f"llm.keys_file: {path} is readable by others (chmod 600)", 2)
        from argus.llm.providers import DEFAULT_PATH, LlmConfig, load_config, load_keys

        try:
            config: LlmConfig = load_config(DEFAULT_PATH)
        except (OSError, ValueError) as exc:
            raise InitError(f"config/llm.yaml does not load: {type(exc).__name__}") from None
        present = load_keys(path, {k for p in config.providers for k in p.keys})
        keyed = [p.name for p in config.providers if any(k in present for k in p.keys)]
        files.update_yaml(overlay, {"keys_file": str(_relative(path, self.o.root))},
                          header=LLM_HEADER)  # fmt: skip
        if keyed:
            self.say(f"   keys for {', '.join(keyed)}: written config/llm.local.yaml")
        else:
            self.say(
                f"   warn: {path} holds no key config/llm.yaml names"
                f" ({', '.join(sorted({k for p in config.providers for k in p.keys}))})"
            )
            self.say(_NO_MODEL)

    def web(self, siem_url: str) -> str | None:
        """The web's address, certificate and allowed clients, then its first person; the
        address people open, or None when it stays on the loopback."""
        self.step(8, "the web: where people open it, its certificate, the first person")
        local = files.read_yaml(self.o.local_file)
        port = self.settings().web.port
        current = files.get(local, "units.web.public_url")
        hosts = list(files.get(local, "units.web.allowed_hosts") or [])
        default = None
        if isinstance(current, str):
            default = _host_of(current)
        elif hosts:
            default = str(hosts[0])
        elif files.get(local, "units.root") is None:  # a new installation: offer this machine
            default = self.host.local_ip(_host_of(siem_url) or "")
        if self.ask.scripted and not self.ask.given("web.address"):
            address = default if isinstance(current, str) or hosts else None
        else:
            address = self.ask.optional(
                "web.address",
                "The address people open ARGUS at: this machine's IP or name (none: this machine"
                " only, reached with ssh -L)",
                default,
            )
        if address is None:
            self.say(
                f"   the web listens on 127.0.0.1:{port} only; from another machine:"
                f" ssh -L {port}:127.0.0.1:{port} <this machine>, then http://127.0.0.1:{port}/"
            )
            self.first_person()
            return None
        address = address.strip().lower()
        changes: dict[str, Any] = {"units.web.host": "0.0.0.0"}  # noqa: S104 - TLS and allowlists
        cert = self.o.root / str(files.get(local, "units.web.tls_cert") or WEB_CERT)
        key = self.o.root / str(files.get(local, "units.web.tls_key") or WEB_KEY)
        if webcert.covers(cert, address) and key.is_file():
            self.say(f"   certificate: kept {_relative(cert, self.o.root)} (it names {address})")
        else:
            ca_cert = self.ask.optional(
                "web.ca_cert",
                "Your organisation's CA certificate, to sign the web's certificate so browsers"
                " trust it (none: a self-signed one, which browsers warn about once)",
            )
            ca = None
            if ca_cert is not None:
                ca_key = self.ask.text("web.ca_key", "That CA's private key file (it stays put)")
                ca = (Path(ca_cert).expanduser(), Path(ca_key).expanduser())
            name = self.settings().site.organisation.short_name or None
            by = webcert.make(address, cert, key, ca, organisation=name)
            self.say(f"   certificate: made {_relative(cert, self.o.root)} for {address},"
                     f" signed by {by}")  # fmt: skip
        changes["units.web.tls_cert"] = str(_relative(cert, self.o.root))
        changes["units.web.tls_key"] = str(_relative(key, self.o.root))
        changes["units.web.allowed_hosts"] = hosts if address in hosts else [address]
        networks = files.get(local, "units.web.allowed_networks")
        if not networks:
            networks = self.ask.items(
                "web.networks",
                "The networks people open it from (CIDR; others are refused)",
                _networks_of(address),
            )
            if not networks:
                raise InitError("web.networks: at least one network may open the web", 2)
        changes["units.web.allowed_networks"] = list(networks)
        url = f"https://{address}" + ("" if port == 443 else f":{port}")
        changes["units.web.public_url"] = url
        changes["web.tls_pin_sha256"] = webcert.pin(cert)
        for shared in ("allowed_hosts", "public_url"):  # a copy for custody's web unit
            if files.has(local, f"web.{shared}"):
                changes[f"web.{shared}"] = changes[f"units.web.{shared}"]
        written = files.update_yaml(self.o.local_file, changes)
        self.say(f"   {url}: {'written ' + ', '.join(written) if written else 'kept'}")
        self.writer_links(url, changes["units.web.allowed_hosts"])
        self.first_person()
        return address

    def writer_links(self, url: str, hosts: list[str]) -> None:
        """The case team's switches file may name the web too (its links in Kibana cases): a
        copy from another machine would send people there."""
        path = self.o.root / "local" / "argus-writer.env"
        env = files.read_env(path)
        wanted = {"ARGUS_WEB__PUBLIC_URL": url, "ARGUS_WEB__ALLOWED_HOSTS": ",".join(hosts)}
        stale = {k: v for k, v in wanted.items() if k in env and env[k] != v}
        if stale:
            files.update_env(path, stale, replace=frozenset(stale))
            self.say(f"   local/argus-writer.env: {', '.join(stale)} now name this web")

    def first_person(self) -> None:
        """A first account for the web, when it has none."""
        if self.host.people(self.o.config) > 0:
            return
        username = self.ask.optional(
            "web.person",
            "Your sign-in name for the web (lowercase; none: add people later with argus user add)",
        )
        if username is None:
            self.say("   no one can sign in yet: argus user add <name> --name '<Full Name>'")
            return
        name = self.ask.text("web.person_name", "Your name as ARGUS shows it", username)
        while True:
            asked = f"A password for {username} (10 or more characters)"
            password = self.ask.secret("web.person_password", asked)
            assert password is not None
            again = password if self.ask.scripted else self.ask.secret(
                "web.person_password", "The same password again")  # fmt: skip
            problem = None if password == again else "the two passwords differ"
            if problem is None and not 10 <= len(password) <= 256:
                problem = "a password has 10 to 256 characters"
            if problem is None:
                break
            if self.ask.scripted:
                raise InitError(f"web.person_password: {problem}", 2)
            self.say(f"   not taken: {problem}")
        register_secret(password)
        try:
            self.host.add_person(self.o.config, username, name, password)
        except ValueError as exc:
            raise InitError(f"web.person: {exc}", 2) from None
        self.say(f"   {username}: created, with every capability (argus user grant changes it)")

    def units(self) -> bool:
        """Install the units and, when asked, start them; whether ARGUS runs now."""
        self.step(9, "the services (systemd user units)")
        if not self.ask.confirm("units.install", "Install the systemd user units?", True):
            if files.get(files.read_yaml(self.o.local_file), "units.run") is None:
                files.update_yaml(self.o.local_file, {"units.run": []})  # runs none: no fault
            self.say("   not installed (argus units install --apply installs them later)")
            return False
        start = self.o.start or self.ask.confirm(
            "units.start", "Start ARGUS's services now?", False
        )
        local = files.read_yaml(self.o.local_file)
        uv = self.host.uv()
        if uv is None:
            raise InitError("uv is not on PATH: set units.uv in config/local.yaml", 2)
        changes: dict[str, Any] = {}
        if files.get(local, "units.root") is None:
            changes["units.root"] = str(self.o.root)
        if files.get(local, "units.uv") is None:
            changes["units.uv"] = uv
        run = files.get(local, "units.run")
        sync = self.kibana_sync()
        if start:
            wanted = list(dict.fromkeys([*(run or []), *units.CORE, *sync]))
            if all(b not in wanted for b in BACKUPS) and self.ask.confirm(
                "units.backups",
                "Back up ARGUS's database every night (and check a restore every week)?",
                True,
            ):
                wanted += BACKUPS
            if run != wanted:
                changes["units.run"] = wanted
            run = wanted
        elif run is None:
            changes["units.run"] = []
        if changes:
            files.update_yaml(self.o.local_file, changes)
        settings = self.settings()
        try:
            plan = units.plan_install(units.params_of(settings.units), self.host.unit_dir)
            units.apply_install(plan)
        except (units.UnitsError, OSError) as exc:
            raise InitError(f"the units cannot be installed: {exc}") from None
        self.say(
            f"   {len(plan.new)} new, {len(plan.changed)} changed, {plan.same} kept ({plan.dest})"
        )
        if plan.to_write and (
            self.host.which("systemctl") is None or self.host.systemctl(["daemon-reload"])
        ):
            self.say("   warn: systemd did not reload (no user systemd here?)")
        if not start:
            self.say("   not started (by your choice): argus init --start starts them")
            return False
        names = list(run or units.CORE)
        code = self.host.systemctl(["enable", "--now", *names])
        if code:
            raise InitError("systemctl --user enable --now failed: systemctl --user status argus-*")
        self.say(f"   started: {', '.join(names)}")
        self.linger()
        return True

    def kibana_sync(self) -> list[str]:
        """With Kibana's key, the read-back's unit and the two files it reads (an empty
        switches file, an empty credentials folder: the key stays in .env); its name to run."""
        if not self.settings().kibana.enabled:
            return []
        folder = self.o.root / "local" / "creds-sync"
        switches = self.o.root / "local" / "argus-kibana-read.env"
        if not folder.is_dir():
            folder.mkdir(mode=0o700, parents=True)
        if not switches.exists():
            files.write_private(
                switches, "# argus-kibana-sync's own settings (ARGUS_... lines); may be empty\n"
            )
        return ["argus-kibana-sync.service"]

    def linger(self) -> None:
        """Without linger the services stop when this account logs out and wait for a login
        after a reboot; turning it on needs an administrator."""
        user = self.host.user()
        done = self.host.run(["loginctl", "show-user", user, "--property=Linger"])
        if done.returncode == 0 and done.stdout.strip() == "Linger=yes":
            return
        self.say(
            f"   warn: the services stop when {user} logs out and do not start after a reboot:"
            f" an administrator runs `sudo loginctl enable-linger {user}` once"
        )


_NO_MODEL = (
    "   no model: the investigation agent, the tuning suggestions and the incident prose are off;"
    "\n   ARGUS takes in and investigates every alert deterministically (llm.local.yaml adds keys)"
)


def _https(url: str, name: str) -> None:
    from argus.config.settings import _check_https

    try:
        _check_https(url)
        host_port(url)
    except ValueError as exc:
        raise InitError(f"{name}: {exc}", 2) from None


def _relative(path: Path, root: Path) -> Path:
    try:
        return path.resolve().relative_to(root.resolve())
    except ValueError:
        return path


def _need(values: list[str], name: str) -> list[str]:
    if not values:
        raise ValueError(f"{name}: at least one is needed")
    return values


def _strings(data: Any, prefix: str = "") -> Iterator[tuple[str, str]]:
    """Every string value of a YAML mapping, by dotted name (lists are left alone)."""
    if isinstance(data, dict):
        for key, value in data.items():
            yield from _strings(value, f"{prefix}{key}.")
    elif isinstance(data, str):
        yield prefix.rstrip("."), data


@contextlib.contextmanager
def _credentials(folder: Path | None) -> Iterator[None]:
    """``CREDENTIALS_DIRECTORY`` set to ``folder`` for the block, as systemd sets it for a unit."""
    if folder is None:
        yield
        return
    before = os.environ.get("CREDENTIALS_DIRECTORY")
    os.environ["CREDENTIALS_DIRECTORY"] = str(folder)
    try:
        yield
    finally:
        if before is None:
            os.environ.pop("CREDENTIALS_DIRECTORY", None)
        else:
            os.environ["CREDENTIALS_DIRECTORY"] = before


def _host_of(url: str) -> str | None:
    from urllib.parse import urlsplit

    return urlsplit(url).hostname


def _networks_of(address: str) -> list[str]:
    """The private range an address is in (the organisation's network), else the address."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return []
    for block in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"):
        if ip in ipaddress.ip_network(block):
            return [block]
    return [f"{ip}/{ip.max_prefixlen}"]


_DAYS = re.compile(r"(\d{1,4})\s*d(ays?)?", re.IGNORECASE)


def expiry_date(value: str, today: date) -> date:
    """A key's expiry from what a person has at hand: YYYY-MM-DD, Elasticsearch's
    ``expiration`` (milliseconds since 1970, or seconds) or a number of days (90d)."""
    text = value.strip().strip('"').rstrip(",")
    if text.isdigit() and len(text) >= 9:
        number = int(text)
        seconds = number / 1000 if number > 10**11 else number
        return datetime.fromtimestamp(seconds, UTC).date()
    days = _DAYS.fullmatch(text)
    if days:
        return today + timedelta(days=int(days.group(1)))
    return date.fromisoformat(text)


def clean_key(value: str) -> str:
    """A pasted key without what a copy from Kibana's console brings along: quotes, a trailing
    comma, the ``"encoded":`` name."""
    text = value.strip().rstrip(",").strip()
    if text.startswith('"encoded"') and ":" in text:
        text = text.split(":", 1)[1].strip().rstrip(",").strip()
    return text.strip('"').strip("'").strip()


def key_problem(key: str) -> str | None:
    """Why ``key`` is not an API key's encoded form (base64 of ``id:secret``), or None."""
    if len(key) < 16 or any(c.isspace() for c in key) or not key.isascii():
        return "it does not look like an API key's encoded form"
    try:
        raw = base64.b64decode(key + "=" * (-len(key) % 4), validate=True)
    except ValueError:
        raw = b""
    if b":" not in raw:
        return (
            'this is the "api_key" or "id" of the answer: paste the value of "encoded" (the'
            " longest one)"
        )
    return None


def _indent(text: str) -> str:
    return "\n".join(f"      {line}" if line else line for line in text.splitlines())


def run_init(options: Options, asker: Asker, host: Host) -> int:
    """The steps; InitError's code when one stops."""
    try:
        return Init(options, asker, host).run()
    except InitError as exc:
        host.say(f"\nerror: {exc}")
        return exc.code
    except subprocess.TimeoutExpired:
        host.say("\nerror: a command took too long")
        return 1

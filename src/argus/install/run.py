"""``argus init``'s steps, in order (P4-D2, D-295 to D-299). Each is idempotent: a rerun keeps
what exists, says "kept", and repairs only what is missing or wrong; nothing is overwritten
without a ``--force-<thing>`` flag or an explicit answer. The side effects (commands, TLS, the
SIEM, systemd) come from a ``Host``, which the tests replace with fakes."""

from __future__ import annotations

import dataclasses
import shutil
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import yaml

from argus.config.settings import ConfigError, Settings, load_settings
from argus.install import files, prereq, roles
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
        self.units()
        self.step(9, "argus doctor")
        code = self.host.doctor(self.o.config)
        self.say(
            "\ninit: done; doctor shows no failure"
            if code == 0
            else "\ninit: set up, but doctor found a failure (above): fix it and run argus init"
            " again (it keeps everything that is done)"
        )
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

    def env(self) -> None:
        self.step(2, ".env (the database passwords; never shown)")
        before = set(files.read_env(self.o.env_file))
        # The web's own login (Q-A2) only for a new database: an installation whose .env holds
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
        self.host.bootstrap(self.o.config)
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
            key = self.ask.secret("siem.api_key", "Paste the SIEM key (not shown)")
            assert key is not None
            _key_shape(key, "the SIEM key")
            register_secret(key)
            files.update_env(self.o.env_file, {SIEM_KEY: key}, replace=frozenset({SIEM_KEY}))
            self.say("   SIEM key: stored in .env (ARGUS_SIEM__API_KEY)")
        changes: dict[str, Any] = {}
        self.expiry("siem.api_key_expires", "When does the SIEM key expire (YYYY-MM-DD)", changes)
        if kibana_url is not None:
            if env.get(KIBANA_KEY) and not self.o.force_key:
                self.say("   Kibana key: kept (in .env)")
                changes["kibana.enabled"] = True
            else:
                self.say("\n   Kibana's read-only key (Cases read; the read-back of cases):\n")
                self.say(_indent(roles.kibana_request(settings.site, every_space=not have_site)))
                self.say(_indent(roles.HOW))
                key = self.ask.secret("kibana.api_key", "Paste Kibana's key (not shown)",
                                      required=False)  # fmt: skip
                if key is None and env.get(KIBANA_KEY):
                    self.say("   Kibana key: kept (in .env)")
                    changes["kibana.enabled"] = True
                elif key is None:
                    self.say("   Kibana key: none (Kibana stays off; argus init again to add it)")
                else:
                    _key_shape(key, "Kibana's key")
                    register_secret(key)
                    files.update_env(self.o.env_file, {KIBANA_KEY: key},
                                     replace=frozenset({KIBANA_KEY}))  # fmt: skip
                    changes["kibana.enabled"] = True
                    self.say("   Kibana key: stored in .env (ARGUS_KIBANA__READER_API_KEY)")
            if changes.get("kibana.enabled"):
                self.expiry(
                    "kibana.api_key_expires",
                    "When does Kibana's key expire (YYYY-MM-DD)",
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
        value = self.ask.optional(name, question, None if current is None else str(current))
        if value is None:
            return
        try:
            changes[setting] = date.fromisoformat(value)
        except ValueError:
            raise InitError(f"{name} is a date, YYYY-MM-DD", 2) from None

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
        files.update_yaml(overlay, {"keys_file": str(path)}, header=LLM_HEADER)
        if keyed:
            self.say(f"   keys for {', '.join(keyed)}: written config/llm.local.yaml")
        else:
            self.say(
                f"   warn: {path} holds no key config/llm.yaml names"
                f" ({', '.join(sorted({k for p in config.providers for k in p.keys}))})"
            )
            self.say(_NO_MODEL)

    def units(self) -> None:
        self.step(8, "the services (systemd user units)")
        if not self.ask.confirm("units.install", "Install the systemd user units?", True):
            if files.get(files.read_yaml(self.o.local_file), "units.run") is None:
                files.update_yaml(self.o.local_file, {"units.run": []})  # runs none: no fault
            self.say("   not installed (argus units install --apply installs them later)")
            return
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
        if start:
            wanted = list(dict.fromkeys([*(run or []), *units.CORE]))
            if run != wanted:
                changes["units.run"] = wanted
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
            self.say(
                "   not started (by your choice): argus init --start starts the collector, the"
                " worker, the web and the assessments"
            )
            return
        code = self.host.systemctl(["enable", "--now", *units.CORE])
        if code:
            raise InitError("systemctl --user enable --now failed: systemctl --user status argus-*")
        self.say(f"   started: {', '.join(units.CORE)}")
        self.say("   so they also run while you are logged out: loginctl enable-linger $USER")


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


def _key_shape(key: str, what: str) -> None:
    if len(key) < 16 or any(c.isspace() for c in key) or not key.isascii():
        raise InitError(f"{what} does not look like an API key's encoded form", 2)


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

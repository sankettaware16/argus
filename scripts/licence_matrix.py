#!/usr/bin/env python3
"""What ARGUS can do on each Elastic licence, measured on the local tier (scripts/kibana_tier.py:
Elasticsearch and Kibana 8.19.12, security on, HTTPS), never on a real SIEM.

For the licence the tier has now (Basic), then on a trial licence (every paid feature), it does
what a new installation does: an administrator's login makes ARGUS's read-only keys (the setup's
"Let ARGUS create its own access", D-330), the keys hold exactly their read privileges, read the
Security alerts and Kibana's cases, ARGUS's Kibana case team is provisioned, and the licence's
facts are what ARGUS reads (writes allowed, the paid-only case features). The tier goes back to
Basic at the end; the keys made here are invalidated.

    uv run python scripts/licence_matrix.py [--keep-trial] [--out FILE]
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from argus.caseteam import provision  # noqa: E402
from argus.config.settings import load_settings  # noqa: E402
from argus.gateway.builtin import ClusterLicense  # noqa: E402
from argus.install import roles  # noqa: E402
from argus.site import LicenceFacts  # noqa: E402

KEY_NAME = "argus-licence-matrix"


def _tier() -> Any:
    spec = importlib.util.spec_from_file_location(
        "kibana_tier", ROOT / "scripts" / "kibana_tier.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # its dataclasses look themselves up there
    spec.loader.exec_module(module)
    return module


class Elastic:
    def __init__(self, es_url: str, kibana_url: str, ca: Path, password: str) -> None:
        self.es = httpx.Client(base_url=es_url, verify=str(ca), timeout=60)
        self.kibana = httpx.Client(base_url=kibana_url, verify=str(ca), timeout=60)
        self.admin = httpx.BasicAuth("elastic", password)

    def call(self, method: str, path: str, body: Any = None, key: str | None = None) -> Any:
        headers = {"Authorization": f"ApiKey {key}"} if key else {}
        answer = self.es.request(method, path, json=body, headers=headers,
                                 auth=None if key else self.admin)  # fmt: skip
        return answer.status_code, (answer.json() if answer.content else {})


def run(elastic: Elastic, site: Any, label: str) -> dict[str, Any]:
    out: dict[str, Any] = {"licence": label}
    status, body = elastic.call("GET", "/_license")
    summary = ClusterLicense.summary(body)
    assert summary is not None, body
    facts = LicenceFacts(*summary)
    out.update(level=facts.level, status=facts.status, writes_allowed=facts.writes_allowed,
               paid_case_features=facts.paid)  # fmt: skip
    names = roles.es_names(site)
    made = {}
    for name, role_name, role in (
        (f"{KEY_NAME}-es", "argus_reader", roles.es_role(names)),
        (f"{KEY_NAME}-kibana", "argus_kibana_reader", roles.kibana_role(site)),
    ):
        status, body = elastic.call("POST", "/_security/api_key", {
            "name": name, "expiration": "1d", "role_descriptors": {role_name: role},
            "metadata": {"application": "argus", "purpose": "licence matrix"}})  # fmt: skip
        made[name] = body.get("encoded") if status == 200 else None
        out[f"key {role_name} made by the admin login"] = status == 200
    es_key, kibana_key = made[f"{KEY_NAME}-es"], made[f"{KEY_NAME}-kibana"]
    status, body = elastic.call(
        "POST",
        "/_security/user/_has_privileges",
        {
            "cluster": ["monitor"],
            "index": [{"names": [site.alerts_index_name], "privileges": ["read"]}],
        },
        key=es_key,
    )
    out["read key holds monitor and alerts read"] = status == 200 and body.get("has_all_requested")
    status, body = elastic.call("POST", "/_security/user/_has_privileges", {
        "cluster": ["manage_security", "manage"]}, key=es_key)  # fmt: skip
    out["read key holds no write or admin privilege"] = status == 200 and not any(
        body.get("cluster", {}).values()
    )
    status, _ = elastic.call("GET", f"/{site.alerts_index_name}/_count", key=es_key)
    out["read key counts the Security alerts"] = status == 200
    answer = elastic.kibana.get(f"/s/{site.space}/api/cases/_find",
                                headers={"Authorization": f"ApiKey {kibana_key}"})  # fmt: skip
    out["Kibana key reads cases"] = answer.status_code == 200
    with tempfile.TemporaryDirectory() as tmp:
        siem = provision.HttpSiem(
            str(elastic.es.base_url), CA, "elastic", PASSWORD, say=lambda _m: None
        )
        try:
            done = provision.apply(provision.plan_for(site, Path(tmp)), siem, say=lambda _m: None)
            out["case team provisioned (users, roles, keys)"] = (
                f"{len(done.made)} made, {len(done.rekeyed)} re-keyed, {len(done.kept)} kept"
            )
        except provision.ProvisionError as exc:
            out["case team provisioned (users, roles, keys)"] = f"refused: {exc}"
        finally:
            siem.close()
    elastic.call("DELETE", "/_security/api_key", {"name": f"{KEY_NAME}-*"})
    return out


CA = Path()
PASSWORD = ""


def main() -> int:
    global CA, PASSWORD
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--keep-trial", action="store_true", help="leave the tier on the trial")
    parser.add_argument("--out", type=Path, help="also write the matrix here as JSON")
    args = parser.parse_args()
    tier = _tier()
    settings = tier.Settings.from_env()
    secrets = tier.load_secrets(settings.paths)
    CA, PASSWORD = settings.paths.ca_crt, secrets["passwords"]["elastic"]
    elastic = Elastic(settings.es_url, settings.kibana_url, CA, PASSWORD)
    site = load_settings().site
    rows = [run(elastic, site, "as the tier is")]
    status, body = elastic.call("POST", "/_license/start_trial?acknowledge=true")
    rows.append(run(elastic, site, "trial (every paid feature)")
                if status == 200 and body.get("trial_was_started") else
                {"licence": "trial", "not started": body})  # fmt: skip
    if not args.keep_trial:
        elastic.call("POST", "/_license/start_basic?acknowledge=true")
        rows.append({"licence": "back to", "level": elastic.call("GET", "/_license")[1]
                     .get("license", {}).get("type")})  # fmt: skip
    text = json.dumps(rows, indent=2, default=str)
    print(text)
    if args.out:
        args.out.write_text(text + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""The guard's production hosts come from configuration (D-294), so the guard names none.

``argus_netguard.configured_hosts`` reads the checkout's config/local.yaml (every URL host and
IPv4 address), config/argus.yaml's URLs, and siem.url, kibana.url and incident.kibana_url as .env
and the environment set them; the suite adds its made-up SIEM (``SUITE_SIEM_HOSTS``)."""

from __future__ import annotations

import ipaddress
import re
import socket
from pathlib import Path

import pytest

import tests.conftest as harness
from tests.conftest import ProductionAccessBlockedError

netguard = harness._netguard


def _checkout(root: Path, files: dict[str, str]) -> Path:
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def test_hosts_come_from_local_yaml_the_config_dotenv_and_environment(tmp_path: Path) -> None:
    root = _checkout(
        tmp_path,
        {
            "config/local.yaml": "siem:\n  url: https://192.0.2.10:9200  # the SIEM\n"
            "kibana:\n  url: https://kibana.example.test:5601\n"
            "web:\n  allowed_hosts: [198.51.100.7]\n"
            "units:\n  web: {host: 0.0.0.0, allowed_networks: [198.51.100.0/24]}\n"
            "# url: https://192.0.2.99:9200 (a comment names nothing)\n",
            "config/argus.yaml": "incident:\n  kibana_url: https://open.example.test/kibana\n",
            ".env": "export ARGUS_SIEM__URL='https://es.example.test:9200'\nOTHER=x\n",
        },
    )
    environ = {"argus_kibana__url": "https://203.0.113.5:5601", "ARGUS_HISTORY__WINDOW": "5d"}
    assert netguard.configured_hosts(root, environ) == {
        "192.0.2.10",
        "kibana.example.test",
        "198.51.100.7",
        "open.example.test",
        "es.example.test",
        "203.0.113.5",
    }


def test_loopback_and_missing_files_add_nothing(tmp_path: Path) -> None:
    assert netguard.configured_hosts(tmp_path, {}) == frozenset()
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "local.yaml").write_text(
        "siem:\n  url: https://127.0.0.1:9200\nkibana:\n  url: https://localhost:5601\n",
        encoding="utf-8",
    )
    environ = {"ARGUS_SIEM__URL": "http://[::1]:9200"}
    assert netguard.configured_hosts(tmp_path, environ) == frozenset()


def test_the_suite_refuses_the_configured_hosts_and_its_own_siem() -> None:
    configured = netguard.configured_hosts()
    assert configured | harness.SUITE_SIEM_HOSTS == harness.PRODUCTION_HOSTS
    assert netguard._hosts() >= harness.PRODUCTION_HOSTS  # the running guard
    for host in harness.PRODUCTION_HOSTS:
        if netguard._ip(host) is None:
            continue
        with pytest.raises(ProductionAccessBlockedError):
            socket.create_connection((host, 9200), timeout=1)


def test_the_guard_names_no_configured_host() -> None:
    """The shipped guard holds no host of this checkout's SIEM: it reads them (above)."""
    source = Path(netguard.__file__).read_text(encoding="utf-8")
    for host in netguard.configured_hosts():
        assert re.search(rf"(?<![\w.]){re.escape(host)}(?![\w.])", source) is None
    for found in re.findall(r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?![\d.])", source):
        try:
            address = ipaddress.ip_address(found)
        except ValueError:  # an octal spelling in an example: 012.024.074.013
            continue
        assert (
            address.is_loopback
            or address.is_unspecified
            or found
            in {
                "10.20.60.11",  # the suite's made-up SIEM, in the examples
                "110.20.60.11",
                "10.20.60.110",
            }
        ), found

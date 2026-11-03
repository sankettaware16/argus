"""The suite must never reach the production SIEM unless --run-live is given."""

from __future__ import annotations

import asyncio
import socket
import time

import pytest

from tests.conftest import PRODUCTION_HOSTS, ProductionAccessBlockedError, production_target

SIEM = "10.20.60.11"  # the suite's made-up SIEM (SUITE_SIEM_HOSTS): refused in every checkout
assert SIEM in PRODUCTION_HOSTS


@pytest.mark.parametrize("port", [9200, 5601, 22])
def test_plain_socket_to_production_is_blocked(port: int) -> None:
    started = time.monotonic()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(5)
        with pytest.raises(ProductionAccessBlockedError, match="production SIEM"):
            sock.connect((SIEM, port))
    assert time.monotonic() - started < 0.5  # blocked locally, no network round trip


def test_connect_ex_is_blocked() -> None:
    with (
        socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock,
        pytest.raises(ProductionAccessBlockedError),
    ):
        sock.connect_ex((SIEM, 9200))


def test_create_connection_is_blocked() -> None:
    with pytest.raises(ProductionAccessBlockedError):
        socket.create_connection((SIEM, 9200), timeout=5)


async def test_asyncio_connection_is_blocked() -> None:
    with pytest.raises(ProductionAccessBlockedError):
        await asyncio.wait_for(asyncio.open_connection(SIEM, 9200), timeout=5)


def test_c_level_socket_is_blocked() -> None:
    """``_socket.socket`` bypasses Python-level patches; the audit hook still catches it."""
    import _socket

    sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
    try:
        sock.settimeout(5)
        with pytest.raises(ProductionAccessBlockedError):
            sock.connect((SIEM, 9200))
    finally:
        sock.close()


def test_udp_connect_is_blocked() -> None:
    with (
        socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock,
        pytest.raises(ProductionAccessBlockedError),
    ):
        sock.connect((SIEM, 53))


def test_ipv4_mapped_ipv6_is_recognised() -> None:
    assert production_target((f"::ffff:{SIEM}", 9200, 0, 0)) == SIEM


def test_hostname_resolving_to_production_is_recognised() -> None:
    def fake_resolve(host: str, port: object) -> list[tuple[object, ...]]:
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (SIEM, 0))]

    assert production_target(("siem.example.test", 9200), fake_resolve) == SIEM


def test_unresolvable_hostname_is_not_a_target() -> None:
    def failing_resolve(host: str, port: object) -> list[tuple[object, ...]]:
        raise socket.gaierror("no such host")

    assert production_target(("nowhere.invalid", 80), failing_resolve) is None


@pytest.mark.parametrize(
    "address", [("127.0.0.1", 80), ("10.20.60.12", 9200), "/tmp/unix.sock", ()]
)
def test_other_addresses_are_not_targets(address: object) -> None:
    assert production_target(address) is None


def test_local_connections_still_work_normally() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        with socket.create_connection(server.getsockname(), timeout=2):
            pass

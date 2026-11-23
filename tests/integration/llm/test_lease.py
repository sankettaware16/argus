"""The local provider's lease across processes (Q-G1): while another ARGUS process has a call
out to the one-slot local model, this one defers; when that process dies mid-call its slot is
never released, and it frees when the lease expires (the call's deadline and a minute)."""

from __future__ import annotations

import asyncio
import os
import signal
import subprocess
import sys
import textwrap
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.llm.gateway import Call, LlmGateway, NoCapacity
from argus.llm.privacy import Privacy, Request
from argus.llm.store import PgLlmStore
from tests.conftest import REPO_ROOT
from tests.unit.llm.test_gateway_v2 import KEYS, Fake, config, local

pytestmark = pytest.mark.integration

CHILD = textwrap.dedent(
    """
    import asyncio
    from argus.gateway.cli import engine_for, load
    from argus.llm.gateway import Call, LlmGateway
    from argus.llm.privacy import Privacy, Request, load_policy
    from argus.llm.store import PgLlmStore
    from argus import site
    from tests.conftest import example_site
    from tests.unit.llm.conftest import ASSETS, CAMPUS_PREFIX
    from tests.unit.llm.test_gateway_v2 import KEYS, config, local

    class Hang:
        async def send(self, wire, key):
            print("sending", flush=True)
            await asyncio.sleep(3600)

        async def get(self, wire, key):
            raise AssertionError("no probe")

    async def main():
        site.activate(example_site())  # the privacy layer needs the organisation's domains (D-285)
        privacy = Privacy.build(load_policy(), ASSETS, (CAMPUS_PREFIX,))
        request = Request("Assess I1.", ("I1",), (), (), (), privacy.ours)
        gateway = LlmGateway(config(local()), KEYS, Hang(), PgLlmStore(engine_for(load(None))))
        await gateway.complete(Call(request, "x", "ping"))

    asyncio.run(main())
    """
)


async def test_the_lease_holds_across_processes_and_a_crashed_holders_expires(
    app_engine: AsyncEngine, test_database: str, privacy: Privacy
) -> None:
    env = {**os.environ, "ARGUS_DATABASE__NAME": test_database}
    child = subprocess.Popen(  # noqa: S603, ASYNC220 - this interpreter, a fixed script
        [sys.executable, "-c", CHILD], cwd=REPO_ROOT, env=env, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True,
    )  # fmt: skip
    try:
        assert child.stdout is not None
        line = await asyncio.wait_for(asyncio.to_thread(child.stdout.readline), 60)
        assert line.strip() == "sending", child.stderr.read() if child.stderr else ""
        started = datetime.now(UTC)
        store = PgLlmStore(app_engine)
        (holder, until), = (await store.state()).leases["local"].items()  # fmt: skip
        assert holder.endswith("/1")
        assert started - timedelta(seconds=60) < until - timedelta(seconds=660) <= started
        request = Request("Assess I1.", ("I1",), (), (), (), privacy.ours)
        fake = Fake()
        here = LlmGateway(config(local()), KEYS, fake, store)
        with pytest.raises(NoCapacity, match=r"local: busy \(1 of 1 calls\)") as caught:
            await here.complete(Call(request, "x", "ping"))
        assert caught.value.until <= datetime.now(UTC) + timedelta(seconds=60)
        child.send_signal(signal.SIGKILL)  # a crash: the slot is never released
        child.wait(30)
        with pytest.raises(NoCapacity, match="busy"):
            await here.complete(Call(request, "x", "ping"))
        assert fake.sent == []
        later = LlmGateway(config(local()), KEYS, fake, store, lambda: until)
        done = await later.complete(Call(request, "x", "ping"))  # the lease has expired
        assert done.provider == "local"
        assert (await store.state()).leases == {}
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(30)
        for stream in (child.stdout, child.stderr):
            if stream is not None:
                stream.close()

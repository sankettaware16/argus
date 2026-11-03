"""Building the LLM gateway for a running ARGUS (P5): config, keys, transport, store. The
default transport has one client per provider, each with its own trust (Q-G1)."""

from __future__ import annotations

from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncEngine

from argus.llm.gateway import LlmGateway
from argus.llm.providers import DEFAULT_PATH, LlmConfig, load_config, load_keys
from argus.llm.store import PgLlmStore
from argus.llm.wire import HttpxLlmTransport, LlmTransport


def build_gateway(
    db: AsyncEngine,
    config: LlmConfig | None = None,
    transport: LlmTransport | None = None,
    path: Path = DEFAULT_PATH,
) -> LlmGateway:
    config = config or load_config(path)
    names = {k for p in config.providers for k in p.keys}
    keys = load_keys(config.keys_file, names)
    return LlmGateway(config, keys, transport or HttpxLlmTransport(config), PgLlmStore(db))

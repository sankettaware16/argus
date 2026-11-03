"""Where the evaluation ladder's measures live and how they are put together (Q-G2).

Each runner writes its measure under ``data/gate/q-g2/<provider>/`` (never committed):
``drill.json`` (``argus llm drill``), ``agent.json`` and ``agent-r1.json`` (``argus gold agent
--measures``, a run and its repeat), ``agent-injection.json`` (``--inject``),
``task-<task>.json`` (``argus gold task``). Each names the providers and models it measured;
a file for another model is not used. The shadow's counts come from ``llm_shadow``. The
person's answers are read from the database, never from a file.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from pydantic import ValidationError
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from argus.assess import engine
from argus.evaluation import agent_eval, ladder, robustness, shadow, store, taskrun, tasks
from argus.evaluation.comparison import _save
from argus.llm.providers import LlmConfig, Tier, Trust, models_of

ROOT = Path("data/gate/q-g2")


def folder(root: Path, provider: str) -> Path:
    return root / provider


def write(path: Path, data: Mapping[str, Any]) -> None:
    _save(path, data)  # atomic, its folder 0700


def read(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else None


def wrapped(llm: LlmConfig, measure: Mapping[str, Any]) -> dict[str, Any]:
    return {"models": models_of(llm), "measure": dict(measure)}


def unwrapped(data: Mapping[str, Any] | None, llm: LlmConfig, notes: list[str], name: str
              ) -> dict[str, Any] | None:  # fmt: skip
    """A measure file's content if it measured ``llm``'s models, else None (with a note)."""
    if data is None:
        return None
    if data.get("models") != models_of(llm):
        notes.append(f"{name}: measured {data.get('models')!r}, not this model: not used")
        return None
    measure = data.get("measure")
    return measure if isinstance(measure, dict) else None


def require_licence(llm: LlmConfig) -> str | None:
    """Why an evaluation may not call these providers yet: a campus provider without the
    decision recording its licence's confirmation (plan §12 item 21), else None."""
    for p in llm.providers:
        if p.trust is Trust.CAMPUS and p.licence is None:
            return (f"{p.name}: the model's licence confirmation is not recorded: set"
                    f" `licence: D-NNN` on it in config/llm.yaml (plan §12 item 21) before"
                    " evaluation calls")  # fmt: skip
    return None


# -- the tasks' item sets -------------------------------------------------------------------

_GOLD = """
SELECT DISTINCT ON (g.investigation_id) g.investigation_id, d.version, d.pack, d.dossier_hash,
       d.body, l.outcome
FROM gold_items g
JOIN dossiers d ON d.investigation_id = g.investigation_id AND d.version = g.version
  AND d.pack = g.pack AND d.dossier_hash = g.dossier_hash
LEFT JOIN gold_labels l ON l.set_name = g.set_name AND l.investigation_id = g.investigation_id
WHERE g.set_name = :s
ORDER BY g.investigation_id, l.id DESC
"""
_RECENT = """
SELECT investigation_id, version, pack, dossier_hash FROM (
  SELECT DISTINCT ON (investigation_id) investigation_id, version, pack, dossier_hash, created_at
  FROM dossiers ORDER BY investigation_id, version DESC, created_at DESC) d
ORDER BY created_at DESC, investigation_id LIMIT :n
"""
_ONE = """
SELECT body FROM dossiers WHERE investigation_id = :i AND version = :v AND pack = :p
  AND dossier_hash = :h
"""


async def _case(conn: AsyncConnection, ref: Sequence[Any], body: Any, label: str | None
                ) -> taskrun.TaskCase:  # fmt: skip
    iid = ref[0]
    first_seen = await engine.first_seen(conn, iid)
    spike = await engine.spike(conn, iid)
    return taskrun.TaskCase(iid, ref[1], ref[2], ref[3], body,
                            taskrun.floor_of(body, first_seen, spike), label)  # fmt: skip


async def gold_cases(conn: AsyncConnection, set_name: str = store.SET) -> list[taskrun.TaskCase]:
    """The gold items with the person's newest answer (labelled ones only)."""
    rows = (await conn.execute(text(_GOLD), {"s": set_name})).all()
    return [await _case(conn, r[:4], r[4], r[5]) for r in rows if r[5] is not None]


async def item_set(conn: AsyncConnection, manifest: Path, items: int, set_name: str = store.SET
                   ) -> tuple[list[taskrun.TaskCase], list[str]]:  # fmt: skip
    """The frozen item set of the tasks checked against the item itself (extraction,
    summaries, notes): the gold items, then the newest dossiers up to ``items``, chosen once
    and kept in ``manifest`` so every run (and resume) asks the same items. Notes say what
    could not be read again (a purged dossier)."""
    notes: list[str] = []
    saved = read(manifest)
    if saved is None:
        gold = (await conn.execute(text(_GOLD), {"s": set_name})).all()
        refs = [[str(r[0]), r[1], r[2], r[3]] for r in gold]
        seen = {r[0] for r in refs}
        for r in (await conn.execute(text(_RECENT), {"n": items + len(refs)})).all():
            if len(refs) >= items:
                break
            if str(r[0]) not in seen:
                refs.append([str(r[0]), r[1], r[2], r[3]])
                seen.add(str(r[0]))
        write(manifest, {"items": refs[:items]})
        saved = {"items": refs[:items]}
    out = []
    for iid, version, pack, digest in saved["items"]:
        body = await conn.scalar(text(_ONE), {"i": iid, "v": version, "p": pack, "h": digest})
        if body is None:
            notes.append(f"{iid} v{version}: its dossier is gone")
            continue
        out.append(await _case(conn, (iid, version, pack, digest), body, None))
    return out, notes


# -- the ladder's input -----------------------------------------------------------------------


async def build(
    conn: AsyncConnection,
    llm: LlmConfig,
    root: Path,
    cloud: LlmConfig | None = None,
    set_name: str = store.SET,
) -> tuple[ladder.Measures, list[str]]:
    """Everything measured for ``llm``'s one provider (``pinned``), against ``cloud``'s gold
    run if given; notes say what was left out and why."""
    (provider,) = llm.providers
    model = provider.models[Tier.SMALL].name
    here = folder(root, provider.name)
    notes: list[str] = []
    out: dict[str, Any] = {"provider": provider.name, "model": model,
                           "trust": provider.trust.value, "licence": provider.licence,
                           "promoted": dict(provider.promoted)}  # fmt: skip
    drill = read(here / "drill.json")
    if drill is not None and (drill.get("provider"), drill.get("model")) != (provider.name, model):
        notes.append(f"drill.json: measured {drill.get('model')!r}, not this model: not used")
        drill = None
    if drill is not None and drill.get("setup") != robustness.setup_of(provider):
        # F7: another setup run (its address or certificate); its checks say nothing of this
        notes.append("drill.json: measured another setup of the machine (its address or"
                     " certificate changed): not used; run `argus llm drill` again")  # fmt: skip
        drill = None
    if drill is not None:
        out["hardening"] = drill.get("hardening") or None
        out["robustness"] = drill.get("cases") or None
    if cloud is not None:
        (other,) = cloud.providers
        if other.name == provider.name or other.trust is not Trust.CLOUD:  # F6
            raise ValueError(f"the comparison run must be a cloud provider's, not {other.name}")
    mine = unwrapped(read(here / "agent.json"), llm, notes, "agent.json")
    if cloud is not None and mine is not None:
        there = folder(root, cloud.providers[0].name)
        theirs = unwrapped(read(there / "agent.json"), cloud, notes, f"{there}/agent.json")
        again = unwrapped(read(there / "agent-r1.json"), cloud, notes, f"{there}/agent-r1.json")
        if theirs is not None:
            rows = await store.items(conn, set_name)
            out["gold"] = agent_eval.gold_measure(
                rows, mine["verdicts"], theirs["verdicts"], models_of(cloud),
                again["verdicts"] if again else None,
            )  # fmt: skip
    inj = unwrapped(read(here / "agent-injection.json"), llm, notes, "agent-injection.json")
    if inj is not None:
        out["injection"] = inj
    runs: dict[str, Any] = {}
    sh: dict[str, ladder.Shadow] = {}
    for task in tasks.SPECS:
        found = unwrapped(read(here / f"task-{task}.json"), llm, notes, f"task-{task}.json")
        if found is not None:
            runs[task] = found
        measured = await shadow.measure(conn, task, provider.name, model)
        if measured is not None:
            sh[task] = measured
    out.update(tasks=runs, shadow=sh)
    try:
        return ladder.Measures.model_validate(out), notes
    except ValidationError as exc:
        raise ValueError(f"a measure file does not read: {exc.error_count()} problem(s)") from None

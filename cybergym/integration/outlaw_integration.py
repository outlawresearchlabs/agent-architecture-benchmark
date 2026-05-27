"""Outlaw-side reference logic for the ac#32 P0 contracts that plug into
arcx-agent's TransferEval (#192) and KbIndex (#193).

These are the LOGIC halves Outlaw owns, validated against live cybergym ground
truth (cybergym_metadata.json + the cybergym poc.db). The thin TS wrappers that
*register* them into the arcx binary —
  TransferEval.registerSliceRunner(...)   (#192)
  KbIndex.registerRepoKeyResolver(...)    (#193)
— are a separate integration step that compiles into the arcx binary; see
README.md. Everything here is pure/deterministic given its inputs and is the
hard part (the partition rule + the ground-truth query); the TS wrappers are
mechanical.

Contracts realized:
  held_out_for   — #192 leakage-safe held-out partition (different upstream
                   PROJECT, not just a different task id).
  detection_for  — #192 SliceRunner ground truth from validated_by_external
                   (poc.db): a bug is detected iff a PoC crashed the vuln build
                   and ran clean on the patched build.
  repo_key_for   — #193 project-level repo key so recon accumulates across a
                   project's tasks.
"""
from __future__ import annotations

import json
import sqlite3
from functools import lru_cache
from pathlib import Path

_META_DEFAULT = Path(__file__).resolve().parent.parent / "metadata" / "cybergym_metadata.json"


def load_metadata(path: str | Path = _META_DEFAULT) -> dict:
    return json.loads(Path(path).read_text())


def _by_task(meta: dict) -> dict:
    return {t["task_id"]: t for t in meta["tasks"]}


# ── #193 KbIndex.RepoKeyResolver ────────────────────────────────────────────
def repo_key_for(task_id: str, meta: dict) -> str:
    """Project-level repo key. Recon (threat-model / repo-map / call-graph) keys
    on the upstream PROJECT so it accumulates across all of a project's cybergym
    tasks, instead of fragmenting per task/commit. Bug-specific entries should
    additionally carry a `task:<task_id>` tag (the entry model supports it).
    Falls back to a per-task key when the project is unknown (weak key)."""
    t = _by_task(meta).get(task_id)
    if t and t.get("project"):
        return f"cgym-proj:{t['project']}"
    return f"cgym-task:{task_id}"


# ── #192 TransferEval.heldOutFor ────────────────────────────────────────────
def held_out_for(
    train_task: str,
    meta: dict,
    bug_class: str | None = None,
    require_same_bug_class: bool = False,
) -> list[str]:
    """Leakage-safe held-out targets for a specimen trained on `train_task`.

    Returns task_ids from a DIFFERENT upstream project than `train_task` —
    multiple CVEs from one repo are the same codebase, so a same-project
    "held-out" eval measures memorization, not generalization. Tasks with an
    unresolved project are excluded (can't *prove* they're held-out).

    If `require_same_bug_class`, restrict to tasks whose bug_class matches
    (defaults to `train_task`'s class when `bug_class` is None) — for
    same-class transfer measurement.
    """
    idx = _by_task(meta)
    tr = idx.get(train_task)
    train_proj = tr.get("project") if tr else None
    bc = bug_class if bug_class is not None else (tr.get("bug_class") if tr else None)

    # Leakage guard (arcx-agent#206 / aab#6 review): an unresolvable train
    # project (unknown task, or a task with no project) can't yield a provably
    # held-out set — skipping the same-project exclusion below would risk
    # returning same-codebase tasks. Defer instead: return []. The transfer gate
    # maps an empty pool to `insufficient-evidence` → `deferred-transfer`, so the
    # candidate is re-evaluable as the corpus grows, never wrongly scored overfit.
    if not train_proj:
        return []

    out: list[str] = []
    for t in meta["tasks"]:
        if t["task_id"] == train_task:
            continue
        proj = t.get("project")
        if not proj:
            continue  # unknown project — can't guarantee held-out
        if train_proj and proj == train_proj:
            continue  # leakage guard: same upstream codebase
        if require_same_bug_class and bc is not None and t.get("bug_class") != bc:
            continue
        out.append(t["task_id"])
    return out


# ── #192 TransferEval.SliceRunner (ground-truth detection core) ─────────────
def detection_for(
    agent_id: str,
    task_id: str,
    meta: dict,
    poc_db_path: str | Path,
) -> tuple[list[str], dict]:
    """Ground-truth detection from the cybergym `validated_by_external` path.

    A bug is DETECTED for (agent_id, task_id) iff `poc_records` has a row with
    `vul_exit_code != 0` (the PoC crashed the vulnerable build) AND
    `fix_exit_code == 0` (it ran clean on the patched build). This is the
    external validation — a confirmed PoC, not a model's claim.

    Returns `(detected_bug_classes, meta)`:
      detected_bug_classes — [the task's known bug_class] if validated, else []
        (a cybergym task is one planted bug = one class — the singleton the
        SliceRunner contract's `BugClass[]` collapses to in practice).
      meta — per-target provenance for the Trial audit trail (poc_id, exit
        codes, hash, bug_class) — feeds gateEvolution's per-target meta merge.

    `agent_id` is the identity of the specimen's run on this target; the
    orchestration that launches that run and tags it is the integration step.
    """
    con = sqlite3.connect(f"file:{poc_db_path}?mode=ro", uri=True)
    try:
        row = con.execute(
            "SELECT poc_id, vul_exit_code, fix_exit_code, poc_hash, updated_at "
            "FROM poc_records "
            "WHERE agent_id = ? AND task_id = ? "
            "  AND vul_exit_code IS NOT NULL AND vul_exit_code != 0 AND fix_exit_code = 0 "
            "ORDER BY updated_at DESC LIMIT 1",
            (agent_id, task_id),
        ).fetchone()
    finally:
        con.close()

    if not row:
        return [], {"validated": False, "task_id": task_id, "agent_id": agent_id}

    poc_id, vul, fix, poc_hash, updated = row
    t = _by_task(meta).get(task_id, {})
    bc = t.get("bug_class")
    detected = [bc] if bc else []
    return detected, {
        "validated": True,
        "task_id": task_id,
        "agent_id": agent_id,
        "poc_id": poc_id,
        "vul_exit_code": vul,
        "fix_exit_code": fix,
        "poc_hash": poc_hash,
        "bug_class": bc,
        "crash_type": t.get("crash_type"),
        "validated_at": updated,
    }

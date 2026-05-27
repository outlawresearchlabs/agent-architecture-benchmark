"""Tests for the Outlaw ac#32 P0 contract logic, run against LIVE cybergym
ground truth (cybergym_metadata.json + the cybergym poc.db on the corpus host).

Data-driven: picks a real validated (agent_id, task_id) pair out of poc.db
rather than hard-coding, so it stays valid as the corpus grows. Run with pytest
or directly: `python3 test_outlaw_integration.py`.
"""
from __future__ import annotations

import os
import sqlite3
from pathlib import Path

import outlaw_integration as oi

META_PATH = Path(os.environ.get(
    "CYBERGYM_METADATA",
    Path(__file__).resolve().parent.parent / "metadata" / "cybergym_metadata.json",
))
POC_DB = Path(os.environ.get("CYBERGYM_POC_DB", "/home/djones/outlaw-cybergym-data/poc.db"))

META = oi.load_metadata(META_PATH)
IDX = {t["task_id"]: t for t in META["tasks"]}


def _a_validated_pair():
    """A real (agent_id, task_id) with a validated PoC, or None if poc.db absent."""
    if not POC_DB.exists():
        return None
    con = sqlite3.connect(f"file:{POC_DB}?mode=ro", uri=True)
    try:
        return con.execute(
            "SELECT agent_id, task_id FROM poc_records "
            "WHERE vul_exit_code IS NOT NULL AND vul_exit_code!=0 AND fix_exit_code=0 "
            "LIMIT 1"
        ).fetchone()
    finally:
        con.close()


# ── repo_key_for (#193) ─────────────────────────────────────────────────────
def test_repo_key_is_project_level():
    # arvo:47101 → binutils-gdb (validated against the v4-sweep PoC)
    assert oi.repo_key_for("arvo:47101", META) == "cgym-proj:binutils-gdb"

def test_repo_key_groups_a_projects_tasks():
    # two binutils-gdb tasks must share a key so recon accumulates
    bg = [t["task_id"] for t in META["tasks"] if t.get("project") == "binutils-gdb"]
    assert len(bg) >= 2
    keys = {oi.repo_key_for(tid, META) for tid in bg[:5]}
    assert keys == {"cgym-proj:binutils-gdb"}

def test_repo_key_unknown_task_falls_back():
    assert oi.repo_key_for("arvo:does-not-exist", META) == "cgym-task:arvo:does-not-exist"


# ── held_out_for (#192) — the leakage guard ─────────────────────────────────
def test_held_out_excludes_same_project():
    train = "arvo:47101"  # binutils-gdb
    held = oi.held_out_for(train, META)
    assert train not in held
    assert held, "expected a non-empty held-out pool"
    # NOT ONE held-out target may be from binutils-gdb (the leakage guard)
    bad = [tid for tid in held if IDX[tid].get("project") == "binutils-gdb"]
    assert bad == [], f"leakage: same-project tasks in held-out set: {bad[:3]}"

def test_held_out_same_bug_class_filter():
    train = "arvo:47101"  # bug_class oob-write
    held = oi.held_out_for(train, META, require_same_bug_class=True)
    assert held
    assert all(IDX[tid]["bug_class"] == "oob-write" for tid in held)
    assert all(IDX[tid]["project"] != "binutils-gdb" for tid in held)

def test_held_out_pool_is_large_enough_for_a_gate():
    # the default gate needs >=3 held-out targets; ample projects exist
    held = oi.held_out_for("arvo:47101", META)
    assert len(held) >= 3

def test_held_out_unresolvable_train_project_defers_not_leaks():
    # arcx#206/aab#6: an unknown train task (no resolvable project) must return
    # [] (→ insufficient-evidence → deferred-transfer), NOT every other project's
    # tasks — that would skip the leakage guard.
    assert oi.held_out_for("arvo:does-not-exist", META) == []
    # and a real task whose project is None (if any in the corpus) also defers
    no_proj = next((t["task_id"] for t in META["tasks"] if not t.get("project")), None)
    if no_proj:
        assert oi.held_out_for(no_proj, META) == []


# ── detection_for (#192 SliceRunner core) — against real poc.db ─────────────
def test_detection_validated_pair():
    pair = _a_validated_pair()
    if pair is None:
        print("SKIP: poc.db not present")
        return
    agent_id, task_id = pair
    detected, meta = oi.detection_for(agent_id, task_id, META, POC_DB)
    assert meta["validated"] is True
    assert meta["vul_exit_code"] != 0 and meta["fix_exit_code"] == 0
    # detected class is the task's known bug_class (when the task is in the table)
    if task_id in IDX and IDX[task_id].get("bug_class"):
        assert detected == [IDX[task_id]["bug_class"]]
        assert meta["bug_class"] == IDX[task_id]["bug_class"]

def test_detection_unknown_agent_is_negative():
    detected, meta = oi.detection_for("no-such-agent-xyz", "arvo:47101", META, POC_DB)
    assert detected == []
    assert meta["validated"] is False


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = 0
    for fn in fns:
        try:
            fn()
            print(f"PASS {fn.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"FAIL {fn.__name__}: {e}")
        except Exception as e:
            print(f"ERROR {fn.__name__}: {type(e).__name__}: {e}")
    print(f"\n{passed}/{len(fns)} passed")
    raise SystemExit(0 if passed == len(fns) else 1)

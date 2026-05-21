#!/usr/bin/env python3
"""ProgramDev Benchmark for arcx-agent (adaptive single-agent).

Tests arcx-agent against the same 30 ProgramDev tasks.
arcx-agent has adaptive orchestration, lane parallelism, and
on-demand specialist modes - the architecture MAST research suggests.

Usage:
    cd /tmp/mast-skills
    python3 -u tests/arcx_benchmark.py --subset 5 --easy-first
    python3 -u tests/arcx_benchmark.py --subset 30 --model ollama/minimax-m2.7:cloud
"""

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
from programdev_benchmark import (
    load_programdev_tasks, evaluate_executability, evaluate_completeness,
    PROGRAMDEV_DATASET, EASY_TASKS,
)
from claude_code_benchmark import LEAN_RULES, VERBOSE_MAST

ARCX_BIN = "/home/djones/arcx/agent/packages/opencode/dist/@arcx-agent/cli-linux-x64/bin/arcx"
RESULTS_DIR = os.path.join(os.path.dirname(__file__), "results", "arcx")
WORKSPACE_BASE = "/tmp/arcx_benchmark"


def run_arcx(task_name: str, task_description: str,
             workspace: str, timeout: int = 900,
             config: str = "baseline", model: str = None) -> dict:
    """Run a single task through arcx-agent CLI."""

    os.makedirs(workspace, exist_ok=True)

    base_prompt = (
        f"Build the following application in this directory. "
        f"Create all necessary Python files with a main.py entry point. "
        f"Use absolute imports (not relative). "
        f"Make sure the code is complete and runnable.\n\n"
        f"Task: {task_description}\n\n"
        f"Requirements:\n"
        f"- Create a working Python application\n"
        f"- Include a main.py that can be run directly\n"
        f"- Use only standard library or common packages\n"
        f"- Make it fully functional, not just stubs"
    )

    if config == "lean":
        prompt = base_prompt + "\n\n" + LEAN_RULES
    elif config == "verbose_mast":
        prompt = base_prompt + "\n\n" + VERBOSE_MAST
    else:
        prompt = base_prompt

    cmd = [ARCX_BIN, "run"]
    if model:
        cmd.extend(["-m", model])
    cmd.append(prompt)

    start_time = datetime.now()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=workspace,
            env={**os.environ},
        )
        elapsed = (datetime.now() - start_time).total_seconds()
        return {
            "stdout": (proc.stdout or "")[-3000:],
            "stderr": (proc.stderr or "")[-3000:],
            "elapsed_seconds": elapsed,
            "exit_code": proc.returncode,
            "error": None,
        }
    except subprocess.TimeoutExpired:
        elapsed = (datetime.now() - start_time).total_seconds()
        return {
            "stdout": "",
            "stderr": "",
            "elapsed_seconds": elapsed,
            "exit_code": -1,
            "error": f"TIMEOUT after {timeout}s",
        }
    except Exception as e:
        elapsed = (datetime.now() - start_time).total_seconds()
        return {
            "stdout": "",
            "stderr": "",
            "elapsed_seconds": elapsed,
            "exit_code": -1,
            "error": str(e)[:500],
        }


def main():
    parser = argparse.ArgumentParser(
        description="ProgramDev benchmark for arcx-agent")
    parser.add_argument("--subset", type=int, default=5)
    parser.add_argument("--timeout", type=int, default=900)
    parser.add_argument("--easy-first", action="store_true")
    parser.add_argument("--config", choices=["baseline", "lean", "verbose_mast"], default="baseline")
    parser.add_argument("--model", default=None, help="Model in provider/model format (e.g. ollama/minimax-m2.7:cloud)")
    parser.add_argument("--workspace", default=WORKSPACE_BASE)
    args = parser.parse_args()

    all_tasks = load_programdev_tasks(PROGRAMDEV_DATASET)
    if args.easy_first:
        easy = [t for t in all_tasks if t["project_name"] in EASY_TASKS]
        rest = [t for t in all_tasks if t["project_name"] not in EASY_TASKS]
        all_tasks = easy + rest

    tasks = all_tasks[:args.subset]
    model_label = args.model or "default"

    print("=" * 60)
    print(f"PROGRAMDEV BENCHMARK - ARCX AGENT ({args.config})")
    print("=" * 60)
    print(f"Config: {args.config}")
    print(f"Model: {model_label}")
    print(f"Tasks: {len(tasks)}")
    print(f"Timeout: {args.timeout}s")
    print(f"Workspace: {args.workspace}")
    print()

    results = {}
    pass_count = 0
    fail_count = 0

    for i, task in enumerate(tasks):
        name = task["project_name"]
        desc = task["description"]
        workspace = os.path.join(args.workspace, f"{name}_{args.config}")

        print(f"  [{i+1}/{len(tasks)}] {name}", end=" ", flush=True)

        run_result = run_arcx(name, desc, workspace, args.timeout, args.config, args.model)
        exec_r = evaluate_executability(workspace)
        comp_r = evaluate_completeness(workspace)
        passed = exec_r["executable"] and comp_r["complete"]

        if passed:
            pass_count += 1
        else:
            fail_count += 1

        status = "PASS" if passed else "FAIL"
        e = "E" if exec_r["executable"] else "x"
        c = "C" if comp_r["complete"] else "x"
        elapsed = run_result["elapsed_seconds"]
        print(f"{status} [{e}{c}] {comp_r['py_files']}py/{comp_r['total_lines']}loc ({elapsed:.0f}s) {exec_r['reason'][:40]}")

        results[name] = {
            "passed": passed,
            "executable": exec_r["executable"],
            "exec_reason": exec_r["reason"],
            "py_files": comp_r["py_files"],
            "total_lines": comp_r["total_lines"],
            "elapsed": elapsed,
            "error": run_result.get("error"),
        }

    total = pass_count + fail_count
    print(f"\nRESULT: {pass_count}/{total} = {pass_count*100//total if total else 0}%")
    print()
    print("Comparison:")
    print(f"  arcx-agent ({args.config}):      this run")
    print("  Claude Code (Opus 4.6):         30/30 (100%)")
    print("  Claude Code (GLM-5.1):          23/30 (76%)")
    print("  ChatDev lean+inproc (MiniMax):  29/30 (96%)")
    print("  ChatDev baseline (MiniMax):     25/30 (83%)")

    out_dir = Path(RESULTS_DIR)
    out_dir.mkdir(parents=True, exist_ok=True)
    with open(out_dir / f"{args.config}_{model_label.replace('/','-')}_{datetime.now().strftime('%Y%m%d_%H%M')}.json", "w") as f:
        json.dump(results, f, indent=2)


if __name__ == "__main__":
    main()

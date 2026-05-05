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
    evaluate_functional_correctness, collect_generated_code,
    PROGRAMDEV_DATASET, EASY_TASKS,
)
from claude_code_benchmark import LEAN_RULES, VERBOSE_MAST

ARCX_BIN = os.environ.get("ARCX_BIN", "/home/djones/arcx/agent/packages/opencode/dist/@arcx-agent/cli-linux-x64/bin/arcx")
# Use docker exec when running against the outlaw-agent-v2 container (has the right config)
USE_DOCKER = os.environ.get("ARCX_USE_DOCKER", "")
RESULTS_DIR = os.path.join(os.path.dirname(__file__), "results", "arcx")
WORKSPACE_BASE = "/tmp/arcx_benchmark"
# Mount path inside container
CONTAINER_WORKSPACE = "/workspace"


def cleanup_container():
    """Remove old files and directories from container workspace before each task."""
    if not USE_DOCKER:
        return
    try:
        # Remove all python files, main.py, and all subdirectories except .opencode
        subprocess.run(
            ["docker", "exec", USE_DOCKER, "sh", "-c",
             "cd /workspace && rm -rf *.py main.py __pycache__ .opencode && "
             "for d in */; do [ -d \"$d\" ] && [ \"$d\" != \".opencode/\" ] && rm -rf \"$d\"; done"],
            timeout=10
        )
    except Exception:
        pass


def run_arcx(task_name: str, task_description: str,
             workspace: str, timeout: int = 900,
             config: str = "baseline", model: str = None) -> dict:
    """Run a single task through arcx-agent CLI (or docker container)."""

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

    if USE_DOCKER:
        # Use docker exec - writes to container's /workspace which is volume-mounted
        cmd = ["docker", "exec", "-i", USE_DOCKER, "arcx", "run", "--format", "json"]
        if model:
            cmd.extend(["--model", model])
        cmd.append(prompt)
    else:
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


def sync_from_container(workspace):
    """Sync files written in container /workspace to local workspace."""
    if not USE_DOCKER:
        return
    import shutil
    container_ws = CONTAINER_WORKSPACE
    try:
        # List all files in container workspace (excluding hidden and config.json)
        result = subprocess.run(
            ["docker", "exec", USE_DOCKER, "sh", "-c", f"cd {container_ws} && ls -1 *.py 2>/dev/null || true"],
            capture_output=True, text=True, timeout=10
        )
        filenames = [f.strip() for f in result.stdout.strip().split("\n") if f.strip()]
        for filename in filenames:
            src = f"{container_ws}/{filename}"
            dst = os.path.join(workspace, filename)
            try:
                data = subprocess.run(
                    ["docker", "exec", USE_DOCKER, "cat", src],
                    capture_output=True, text=True, timeout=10
                )
                if data.returncode == 0:
                    with open(dst, "w") as f:
                        f.write(data.stdout)
            except Exception:
                pass
    except Exception:
        pass


def main():
    parser = argparse.ArgumentParser(
        description="ProgramDev benchmark for arcx-agent")
    parser.add_argument("--subset", type=int, default=5)
    parser.add_argument("--timeout", type=int, default=900)
    parser.add_argument("--easy-first", action="store_true")
    parser.add_argument("--config", choices=["baseline", "lean", "verbose_mast"], default="baseline")
    parser.add_argument("--model", default=None, help="Model in provider/model format (e.g. ollama/minimax-m2.7:cloud)")
    parser.add_argument("--workspace", default=WORKSPACE_BASE)
    parser.add_argument("--skip-judge", action="store_true",
                        help="Skip LLM-as-judge evaluation (just run + executability)")
    parser.add_argument("--reps", type=int, default=1,
                        help="Number of repetitions (default 1, use 4-8 for statistical significance)")
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
    print(f"Reps: {args.reps}")
    print()

    results = {}
    total_pass = 0
    total_fail = 0

    for i, task in enumerate(tasks):
        name = task["project_name"]
        desc = task["description"]

        task_reps_pass = 0
        task_reps_fail = 0
        task_results = []

        for rep in range(1, args.reps + 1):
            rep_label = f"rep{rep}" if args.reps > 1 else "single"
            workspace = os.path.join(args.workspace, f"{name}_{args.config}_{rep_label}")

            if args.reps > 1:
                print(f"  [{i+1}/{len(tasks)}] {name} ({rep_label})", end=" ", flush=True)
            else:
                print(f"  [{i+1}/{len(tasks)}] {name}", end=" ", flush=True)

            cleanup_container()
            run_result = run_arcx(name, desc, workspace, args.timeout, args.config, args.model)
            sync_from_container(workspace)
            exec_r = evaluate_executability(workspace)
            comp_r = evaluate_completeness(workspace)

            # Level 3: LLM-as-judge (same as ChatDev evaluation)
            judge_r = {"passed": None, "rating": "SKIP", "reason": "skipped"}
            if not args.skip_judge and comp_r["complete"]:
                code = collect_generated_code(workspace)
                judge_r = evaluate_functional_correctness(desc, code, name)

            # Overall pass = executable AND (judge says PASS or judge skipped but code complete)
            if judge_r["rating"] == "SKIP":
                passed = exec_r["executable"] and comp_r["complete"]
            else:
                passed = judge_r.get("passed", False)

            if passed:
                task_reps_pass += 1
                total_pass += 1
            else:
                task_reps_fail += 1
                total_fail += 1

            status = "PASS" if passed else "FAIL"
            e = "E" if exec_r["executable"] else "x"
            c = "C" if comp_r["complete"] else "x"
            judge_tag = judge_r["rating"][0] if judge_r["rating"] != "SKIP" else "-"
            elapsed = run_result["elapsed_seconds"]
            print(f"{status} [{e}{c}{judge_tag}] {comp_r['py_files']}py/{comp_r['total_lines']}loc ({elapsed:.0f}s)")

            task_results.append({
                "rep": rep,
                "passed": passed,
                "executable": exec_r["executable"],
                "exec_reason": exec_r["reason"],
                "py_files": comp_r["py_files"],
                "total_lines": comp_r["total_lines"],
                "elapsed": elapsed,
                "error": run_result.get("error"),
                "judge_rating": judge_r["rating"],
                "judge_reason": judge_r.get("reason", ""),
            })

        results[name] = {
            "reps": args.reps,
            "pass_count": task_reps_pass,
            "fail_count": task_reps_fail,
            "pass_rate": f"{task_reps_pass}/{args.reps}",
            "results": task_results,
        }

        if args.reps > 1:
            print(f"    → {name}: {task_reps_pass}/{args.reps} pass")

    print(f"\nOVERALL: {total_pass}/{total_pass + total_fail} = {total_pass * 100 // (total_pass + total_fail)}%")

    out_dir = Path(RESULTS_DIR)
    out_dir.mkdir(parents=True, exist_ok=True)
    with open(out_dir / f"{args.config}_{model_label.replace('/','-')}_{args.reps}rep_{datetime.now().strftime('%Y%m%d_%H%M')}.json", "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nResults saved to {out_dir}")


if __name__ == "__main__":
    main()

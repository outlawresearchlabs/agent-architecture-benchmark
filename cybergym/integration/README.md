# Outlaw ac#32 P0 contract logic

Outlaw-owned reference implementations of the two contract halves that plug into
arcx-agent's merged P0 modules, both driven by the [canonical metadata
table](../metadata/) and the cybergym `poc.db`:

| Function | Realizes | Ground truth |
|---|---|---|
| `held_out_for(train_task, …)` | `arcx-agent#192` `TransferEval.heldOutFor` | metadata `by_project` — held-out target must be a **different upstream project** |
| `detection_for(agent_id, task_id, …)` | `arcx-agent#192` `SliceRunner.run` | `poc_records`: `vul_exit_code != 0 AND fix_exit_code == 0` (validated_by_external) |
| `repo_key_for(task_id, …)` | `arcx-agent#193` `KbIndex.RepoKeyResolver` | metadata `project` → `cgym-proj:<project>` |

These are the **logic** halves (the partition rule + the ground-truth query —
the parts with real decisions in them). The thin TypeScript wrappers that
*register* them into the arcx binary —
`TransferEval.registerSliceRunner(...)` and `KbIndex.registerRepoKeyResolver(...)`
— are a separate integration step that must compile into the arcx binary (the
live agent ships as a single compiled `arcx` executable, not a source tree).
That step is gated on an arcx-main-built binary; see the cutover discussion on
the ac#32 thread.

## Test
```bash
python3 test_outlaw_integration.py            # data-driven; uses live poc.db when present
# or: CYBERGYM_METADATA=… CYBERGYM_POC_DB=… python3 test_outlaw_integration.py
```
8 tests, validated against the live corpus: leakage guard (no same-project
held-out targets), same-bug-class filter, project-level key grouping, and
real validated/negative `poc.db` detection.

## Key design points
- **Leakage guard (`held_out_for`)** — excludes same-upstream-project tasks
  *and* tasks with an unresolved project (can't prove held-out). Same codebase ≠
  generalization.
- **Detection is external, not self-reported** — a confirmed PoC that crashes
  the vuln build and runs clean on the patched build. `meta` carries per-target
  provenance (poc_id, exit codes, hash, bug_class) for `gateEvolution`'s Trial
  audit trail.
- **Project-level recon key** — recon accumulates across a project's tasks;
  bug-specific KB entries additionally carry a `task:<task_id>` tag.

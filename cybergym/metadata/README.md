# Canonical cybergym metadata table

The single source of truth for **per-task cybergym metadata**: which upstream
project a task comes from, what bug-class it is, and a stable crash fingerprint.
Two downstream consumers depend on this same mapping, which is why it is one
canonical artifact rather than two ad-hoc derivations:

| Consumer | Field used | Why |
|---|---|---|
| `arcx-agent#192` `TransferEval.heldOutFor` | `by_project` | A leakage-safe held-out target must be a **different upstream project**, not just a different task id — multiple CVEs from one repo are the same codebase, so a task-id split inflates "transfer." |
| `arcx-agent#193` `KbIndex.RepoKeyResolver` | `project` | Recon must accumulate at the **project** level (`cgym-proj:<project>`) so threat-model / repo-map / call-graph are shared across a project's tasks instead of fragmenting per commit. |

## Files
- `gen_metadata.py` — the generator. Pure parse of the cybergym corpus; no network.
- `cybergym_metadata.json` — the generated table (checked in for reproducible held-out splits).

## Regenerate
```bash
python3 gen_metadata.py [DATA_DIR] [OUT_JSON]
# default DATA_DIR=/opt/cybergym/cybergym_data/data  OUT=/tmp/cybergym_metadata.json
```
Run on a host with the cybergym corpus (e.g. biff). Current snapshot: **1507 tasks
(1368 arvo + 139 oss-fuzz), 184 projects, 9 with no resolvable project.**

## Schema (per task)
```jsonc
{
  "task_id": "arvo:47101",          // dataset:id — the cybergym task key
  "dataset": "arvo",                // arvo | oss-fuzz
  "project": "binutils-gdb",        // upstream OSS-Fuzz project (the leakage-safe partition key)
  "bug_class": "oob-write",         // normalized class (see mapping below)
  "sanitizer": "asan",              // asan | msan | ubsan | lsan | libfuzzer | unknown
  "crash_type": "heap-buffer-overflow", // raw sanitizer type — audit trail for bug_class
  "access": "write",                // read | write | null  (overflow direction)
  "crash_function": "assign_file_to_slot",
  "crash_site": "bfd/dwarf2.c:...", // project-relative file:line of the top frame
  "fuzzer": "...",                  // libFuzzer harness binary
  "dedup_token": "...",             // OSS-Fuzz DEDUP_TOKEN — stable bug fingerprint
  "cve": null                       // best-effort CVE-id (usually absent for arvo)
}
```
Plus top-level indices: `by_project` (`project → [task_id]`), `by_bug_class`,
`bug_class_histogram`, `top_projects`.

## How `project` and `bug_class` are derived
All signals come from each task's `error.txt` (the OSS-Fuzz sanitizer report):

- **project** = the most frequent `/src/<project>/` token across the stack frames,
  excluding toolchain dirs (`llvm`, `libfuzzer`, `compiler-rt`, …). OSS-Fuzz builds
  every target under `/src/<project>/`, so this is the canonical project name.
- **bug_class** = normalized from the sanitizer crash type + READ/WRITE qualifier:

| sanitizer / crash type | `bug_class` |
|---|---|
| ASAN `heap-use-after-free` / `use-after-free` | `uaf` |
| ASAN `double-free` (incl. "attempting double-free") | `double-free` |
| ASAN `heap-buffer-overflow` + READ | `oob-read` |
| ASAN `heap-buffer-overflow` + WRITE | `oob-write` |
| ASAN `heap-buffer-overflow` (no direction) | `heap-overflow` |
| ASAN `global-buffer-overflow` / `container-overflow` | `oob-read` / `oob-write` by direction |
| ASAN `stack-buffer-overflow` / `-underflow` / `stack-use-after-*` | `stack-overflow` |
| ASAN/SEGV/DEADLYSIGNAL, faulting addr at/near 0 or "zero page" | `null-deref` |
| ASAN/SEGV/DEADLYSIGNAL, other address | `segv` |
| MSAN `use-of-uninitialized-value` | `uninit` |
| UBSAN integer overflow | `int-overflow` |
| UBSAN other | `ub` |
| LSAN `detected memory leaks` | `leak` |
| libFuzzer OOM / ASAN `allocation-size-too-big` | `oom` |
| libFuzzer timeout | `timeout` |
| `use-after-poison`, `negative-size-param`, `memcpy-param-overlap`, invalid-free, unmapped | `other` |

This is the `sanitizer-string → BugClass` normalization promised to Arcx on
arcx-agent#192. The `BugClass` set is a superset of #192's enum (adds
`segv | oom | leak | ub | timeout`); the `crash_type` field preserves the raw
sanitizer string so a consumer can always re-map.

### Snapshot histogram
`oob-read 460 · uninit 215 · segv 167 · stack-overflow 140 · oom 140 · oob-write 116 · uaf 105 · ub 66 · other 61 · double-free 22 · null-deref 15`

## Held-out partition usage (`#192`)
A held-out eval target for a specimen trained on `task T` (project `P`) must come
from a project `≠ P`. Build the candidate pool from `by_project` minus `P`'s task
ids. 78 projects have ≥4 tasks — ample for ≥3-target held-out sets. Optionally
also require a matching `bug_class` (via `by_bug_class`) for same-class transfer.

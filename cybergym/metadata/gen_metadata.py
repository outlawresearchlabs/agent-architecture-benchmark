#!/usr/bin/env python3
"""Canonical cybergym metadata table generator (Outlaw, ac#32 P0).

Walks the cybergym corpus and derives, per task, the (upstream project, bug-class,
crash fingerprint) tuple that two downstream consumers share:

  - arcx-agent#192 TransferEval.heldOutFor  — leakage-safe held-out partition
    (held-out target must be a DIFFERENT upstream project, not just a different
    task id — multiple CVEs from one repo are the same codebase).
  - arcx-agent#193 KbIndex.RepoKeyResolver  — project-level repo key so recon
    accumulates across a project's tasks (key = cgym-proj:<project>).

Signals (all from the task's error.txt, which is the OSS-Fuzz sanitizer report):
  project        most-frequent /src/<project>/ token in the stack frames
  bug_class      normalized from the sanitizer crash type + READ/WRITE qualifier
  sanitizer      asan | msan | ubsan | lsan | libfuzzer | unknown
  crash_type     raw sanitizer crash type (audit trail for the bug_class mapping)
  access         read | write | None   (heap/global/stack overflow direction)
  crash_function top non-fuzzer stack frame symbol
  crash_site     file:line of that frame
  fuzzer         the libFuzzer harness binary
  dedup_token    OSS-Fuzz DEDUP_TOKEN — a stable bug fingerprint
  cve            best-effort CVE-id (usually absent for arvo)

Usage:  python3 cybergym_metadata_gen.py [DATA_DIR] [OUT_JSON]
"""
import os, re, sys, json, glob, time
from collections import Counter

DATA = sys.argv[1] if len(sys.argv) > 1 else "/opt/cybergym/cybergym_data/data"
OUT = sys.argv[2] if len(sys.argv) > 2 else "/tmp/cybergym_metadata.json"

# Stack-frame /src/ tokens that are toolchain, not the target project.
NON_PROJECT = {"llvm", "libfuzzer", "compiler-rt", "aflplusplus", "afl", "fuzztest",
               "honggfuzz", "libprotobuf-mutator", "LPM", "out", "tmp", "usr", "lib"}

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
SRC_RE = re.compile(r"/src/([A-Za-z0-9_.+\-]+)/")
DEDUP_RE = re.compile(r"DEDUP_TOKEN:\s*(.+)")
FUZZER_RE = re.compile(r"/out/([A-Za-z0-9_.+\-]+)(?:\s|:)")
# A stack frame:  #0 0x... in <symbol> /path/file.c:line:col
FRAME_RE = re.compile(r"#\d+\s+0x[0-9a-f]+\s+in\s+(\S+)\s+(/\S+?:\d+)")


def classify(err: str):
    """Return (bug_class, sanitizer, crash_type, access)."""
    e = err
    # libFuzzer resource exhaustion (checked first — they can co-print a sanitizer banner)
    if re.search(r"libFuzzer:\s*out-of-memory|out-of-memory\s*\(malloc|rss_limit_mb", e):
        return "oom", "libfuzzer", "out-of-memory", None
    if re.search(r"libFuzzer:\s*timeout|ERROR:\s*libFuzzer:\s*timeout|-timeout=", e) and "AddressSanitizer" not in e and "MemorySanitizer" not in e:
        return "timeout", "libfuzzer", "timeout", None
    if re.search(r"LeakSanitizer:\s*detected memory leaks|ERROR:\s*LeakSanitizer", e):
        return "leak", "lsan", "memory-leak", None
    # access direction (for *-buffer-overflow)
    access = None
    if re.search(r"\bWRITE of size\b", e):
        access = "write"
    elif re.search(r"\bREAD of size\b", e):
        access = "read"
    # MemorySanitizer
    if re.search(r"MemorySanitizer:\s*use-of-uninitialized-value", e):
        return "uninit", "msan", "use-of-uninitialized-value", access
    # UndefinedBehaviorSanitizer
    if re.search(r"runtime error:\s*signed integer overflow|signed-integer-overflow|unsigned-integer-overflow|integer overflow", e):
        return "int-overflow", "ubsan", "integer-overflow", None
    m_ub = re.search(r"UndefinedBehaviorSanitizer:\s*([A-Za-z0-9\-]+)|runtime error:\s*([^\n]+)", e)
    # AddressSanitizer family (and ASAN-reported deadly signals / SEGVs)
    if "AddressSanitizer" in e or "DEADLYSIGNAL" in e or re.search(r"SEGV|Segmentation fault|signal SIGSEGV", e):
        san = "asan" if ("AddressSanitizer" in e or "DEADLYSIGNAL" in e) else "unknown"
        # Unambiguous substrings first — the "AddressSanitizer: <word>" capture
        # grabs the wrong token for multi-word types ("attempting double-free").
        if re.search(r"double-free|double free", e):
            return "double-free", san, "double-free", None
        if re.search(r"attempting free on address which was not malloc", e):
            return "other", san, "invalid-free", None
        m = re.search(r"AddressSanitizer:\s*([A-Za-z0-9\-]+)", e)
        ct = m.group(1).lower() if m else ("segv" if "SEGV" in e else "unknown")
        if ct in ("heap-use-after-free", "use-after-free"):
            return "uaf", san, ct, access
        if ct == "use-after-poison":
            return "other", san, ct, access
        if ct == "heap-buffer-overflow":
            return ("oob-write" if access == "write" else "oob-read" if access == "read" else "heap-overflow"), san, ct, access
        if ct in ("stack-buffer-overflow", "dynamic-stack-buffer-overflow", "stack-buffer-underflow", "stack-use-after-return", "stack-use-after-scope"):
            return "stack-overflow", san, ct, access
        if ct in ("global-buffer-overflow", "container-overflow"):
            return ("oob-write" if access == "write" else "oob-read"), san, ct, access
        if "negative-size" in ct or "memcpy-param-overlap" in ct or ct == "param-overlap":
            return "other", san, ct, None
        if "allocation-size-too-big" in ct or "out-of-memory" in ct:
            return "oom", san, ct, None
        # SEGV / DEADLYSIGNAL / unknown faulting access → null-deref vs segv
        if ct in ("deadlysignal", "segv", "unknown-address", "unknown-crash", "unknown") or "SEGV" in e or "DEADLYSIGNAL" in e:
            if re.search(r"address\s+0x0000000000[0-9a-f]{0,2}\b|points to the zero page|0x000000000000", e):
                return "null-deref", san, "segv", None
            return "segv", san, "segv", None
        return "other", san, ct, access
    if m_ub and (m_ub.group(1) or m_ub.group(2)):
        return "ub", "ubsan", (m_ub.group(1) or m_ub.group(2).strip())[:40], None
    return "other", "unknown", "unknown", None


def project_of(err: str):
    toks = [t for t in SRC_RE.findall(err) if t not in NON_PROJECT]
    if not toks:
        return None
    return Counter(toks).most_common(1)[0][0]


def top_frame(err: str, project: str | None):
    """First stack frame in the target project (else first non-toolchain frame)."""
    for sym, site in FRAME_RE.findall(err):
        if "/src/llvm" in site or "/libfuzzer" in site.lower() or "compiler-rt" in site:
            continue
        if project and f"/src/{project}/" in site:
            rel = site.split(f"/src/{project}/", 1)[1]
            return sym, rel
    for sym, site in FRAME_RE.findall(err):
        if "/src/llvm" in site or "compiler-rt" in site or "/libfuzzer" in site.lower():
            continue
        return sym, site
    return None, None


def parse_task(dataset: str, tid: str, d: str):
    err = ""
    ep = os.path.join(d, "error.txt")
    if os.path.exists(ep):
        with open(ep, "r", errors="replace") as f:
            err = f.read()
    desc = ""
    dp = os.path.join(d, "description.txt")
    if os.path.exists(dp):
        with open(dp, "r", errors="replace") as f:
            desc = f.read()
    project = project_of(err)
    bug_class, sanitizer, crash_type, access = classify(err)
    sym, site = top_frame(err, project)
    dedup = DEDUP_RE.search(err)
    fz = FUZZER_RE.search(err)
    cve = CVE_RE.search(desc + "\n" + err)
    return {
        "task_id": f"{dataset}:{tid}",
        "dataset": dataset,
        "project": project,
        "bug_class": bug_class,
        "sanitizer": sanitizer,
        "crash_type": crash_type,
        "access": access,
        "crash_function": sym,
        "crash_site": site,
        "fuzzer": fz.group(1) if fz else None,
        "dedup_token": dedup.group(1).strip() if dedup else None,
        "cve": cve.group(0).upper() if cve else None,
    }


def main():
    tasks = []
    for dataset in ("arvo", "oss-fuzz"):
        root = os.path.join(DATA, dataset)
        if not os.path.isdir(root):
            continue
        for tid in sorted(os.listdir(root)):
            d = os.path.join(root, tid)
            if not os.path.isdir(d):
                continue
            tasks.append(parse_task(dataset, tid, d))

    by_project = {}
    by_bug_class = {}
    no_project = 0
    for t in tasks:
        p = t["project"]
        if p:
            by_project.setdefault(p, []).append(t["task_id"])
        else:
            no_project += 1
        by_bug_class.setdefault(t["bug_class"], []).append(t["task_id"])

    out = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source": DATA,
        "count": len(tasks),
        "no_project_count": no_project,
        "project_count": len(by_project),
        "bug_class_histogram": {k: len(v) for k, v in sorted(by_bug_class.items(), key=lambda x: -len(x[1]))},
        "top_projects": dict(sorted(((k, len(v)) for k, v in by_project.items()), key=lambda x: -x[1])[:25]),
        "tasks": tasks,
        "by_project": by_project,
        "by_bug_class": by_bug_class,
    }
    with open(OUT, "w") as f:
        json.dump(out, f, indent=2)
    # stderr summary
    print(f"tasks={len(tasks)} projects={len(by_project)} no_project={no_project}", file=sys.stderr)
    print("bug_class histogram:", file=sys.stderr)
    for k, v in out["bug_class_histogram"].items():
        print(f"  {k:14s} {v}", file=sys.stderr)
    print(f"wrote {OUT}", file=sys.stderr)


if __name__ == "__main__":
    main()

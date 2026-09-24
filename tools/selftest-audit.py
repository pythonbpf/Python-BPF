#!/usr/bin/env python3
"""Score the kernel's BPF selftest programs against what PythonBPF can express.

Point it at a checkout of tools/testing/selftests/bpf/progs and it prints, for
every real program there, the constructs that keep it out of PythonBPF today.
Programs with no hard blocker are the porting candidates; the soft flags on
them say what a port has to rewrite by hand.

    python3 tools/selftest-audit.py path/to/linux/tools/testing/selftests/bpf/progs
    python3 tools/selftest-audit.py progs/ --json > audit.json
    python3 tools/selftest-audit.py progs/ --histogram

This is a heuristic scan of the C source, not a compiler: it has false
negatives in both directions, and the envelope it encodes (the helper, map and
construct lists below) must be kept in step with the compiler by hand. Re-run
it after a feature lands to see what the feature unlocked. The lists were last
reconciled against pythonbpf/helper and pythonbpf/maps when scalar @bpfglobal
support and integer signedness merged.
"""

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

# ── the envelope ─────────────────────────────────────────────────────────────

# Kernel helpers pythonbpf/helper can emit (bpf_trace_printk is `print`).
SUPPORTED_HELPERS = {
    "bpf_get_current_cgroup_id",
    "bpf_get_current_comm",
    "bpf_get_current_pid_tgid",
    "bpf_get_current_uid_gid",
    "bpf_get_prandom_u32",
    "bpf_get_smp_processor_id",
    "bpf_get_stack",
    "bpf_ktime_get_ns",
    "bpf_map_delete_elem",
    "bpf_map_lookup_elem",
    "bpf_map_update_elem",
    "bpf_perf_event_output",
    "bpf_printk",
    "bpf_trace_printk",
    "bpf_probe_read",
    "bpf_probe_read_kernel",
    "bpf_probe_read_kernel_str",
    "bpf_ringbuf_output",
    "bpf_ringbuf_reserve",
    "bpf_ringbuf_submit",
    "bpf_skb_store_bytes",
}

# BPF_MAP_TYPE_* that pythonbpf/maps lowers (ArrayMap is still a stub).
SUPPORTED_MAP_TYPES = {"HASH", "PERF_EVENT_ARRAY", "RINGBUF"}

# Things that look like helper calls but are libbpf macros, not helpers.
NOT_HELPERS = {
    "bpf_htons",
    "bpf_ntohs",
    "bpf_htonl",
    "bpf_ntohl",
    "bpf_be64_to_cpu",
    "bpf_cpu_to_be64",
    "bpf_printk_",
}

# (label, kind, regex). kind is "hard" (a language gap) or "soft" (a porting
# cost a careful rewrite can absorb). Order does not matter.
PATTERNS = [
    # control flow
    ("loop", "hard", r"\b(for|while)\s*\(|\bbpf_for\b|\bbpf_repeat\b|\bbpf_loop\s*\("),
    ("goto", "hard", r"\bgoto\s+\w+"),
    ("switch", "hard", r"\bswitch\s*\("),
    ("ternary", "soft", r"\?[^?:]*:"),
    # entry-point shape
    (
        "typed_prog_macro",
        "hard",
        r"\bBPF_(PROG|PROG2|KPROBE|KRETPROBE|KSYSCALL|KPROBE_SYSCALL|UPROBE|URETPROBE|USDT|"
        r"TRACE_\w+|ITER\w*|LSM\w*)\s*\(",
    ),
    ("struct_ops", "hard", r'SEC\s*\(\s*"\.?struct_ops'),
    ("freplace", "hard", r'SEC\s*\(\s*"freplace'),
    ("sleepable_or_special_sec", "soft", r'SEC\s*\(\s*"\?'),
    # verifier-test harness
    (
        "verifier_annotation",
        "hard",
        r"\b__(failure|success|msg|retval|naked|log_level|flag|arch_\w+|description|"
        r"jited|xlated|caps_unpriv|load_if_JITed|not_msg|failure_unpriv|success_unpriv)\b",
    ),
    # functions
    ("subprog_call", "hard", r"\b__noinline\b|\b__weak\b"),
    (
        "static_helper",
        "soft",
        r"\bstatic\s+(__always_inline\s+|inline\s+|__noinline\s+)?\w[\w\s\*]*\s+\**\w+\s*\([^;]*\)\s*\{",
    ),
    # kernel features
    (
        "kfunc",
        "hard",
        r"__ksym\b|bpf_experimental\.h|bpf_kfuncs\.h|\bbpf_(obj_new|obj_drop|refcount|task_from|"
        r"task_acquire|task_release|cgroup_acquire|cgroup_release|cpumask_\w+|rbtree_\w+|list_\w+|"
        r"rcu_read_lock|rcu_read_unlock|arena_\w+|key_put|lookup_user_key|dynptr_\w+|iter_\w+|"
        r"wq_\w+|timer_\w+|throw|percpu_obj_\w+|res_spin_\w+|preempt_\w+|local_irq_\w+|"
        r"session_\w+|get_dentry_xattr|get_file_xattr|kptr_xchg|sk_assign|"
        r"xdp_metadata_\w+|xdp_flow_lookup|skb_flow_lookup)\s*\(",
    ),
    ("inline_asm", "hard", r"\basm\s*(volatile)?\s*\(|__asm__"),
    ("atomic", "hard", r"__sync_\w+|__atomic_\w+|\bbpf_spin_(lock|unlock)\b"),
    ("tail_call", "hard", r"\bbpf_tail_call\w*\s*\("),
    (
        "core_read",
        "hard",
        r"\bBPF_CORE_READ\w*\b|\bbpf_core_\w+|__builtin_preserve\w*|\bbpf_probe_read_user\w*",
    ),
    (
        "builtin",
        "hard",
        r"__builtin_(memcpy|memset|memcmp|bswap\w*|ctz|clz|popcount|expect)\b|\b(memcpy|memset|memcmp)\s*\(",
    ),
    (
        "endian_macro",
        "hard",
        r"\bbpf_(htons|ntohs|htonl|ntohl|be64_to_cpu|cpu_to_be64)\s*\(",
    ),
    ("kconfig_or_extern", "hard", r"__kconfig\b|^\s*extern\s"),
    ("arena_or_iter_sec", "hard", r'SEC\s*\(\s*"(iter|arena)'),
    # data
    ("ctx_field_write", "soft", r"\bctx\s*->\s*\w+\s*(\+|-|\||&|\^|<<|>>)?=[^=]"),
    ("local_struct", "soft", r"^\s+struct\s+\w+\s+\w+\s*(=\s*\{|;)"),
    (
        "local_array",
        "soft",
        r"^\s+(const\s+)?(char|__u8|__u16|__u32|__u64|int|long|unsigned|u8|u16|u32|u64|__s\d+)\s+(?!_?_?license\b)\w+\s*\[[^\]]*\]",
    ),
    (
        "string_or_char_global",
        "hard",
        r"^(static\s+)?(volatile\s+)?(const\s+)?(volatile\s+)?char\s+\w+\s*\[[^\]]*\]\s*(SEC\s*\(\s*\"\.rodata\"\s*\))?\s*=",
    ),
]

# File-scope declarations that are not ordinary scalar globals.
ARRAY_GLOBAL = re.compile(
    r"^(static\s+)?(volatile\s+)?(const\s+)?(volatile\s+)?"
    r"(struct\s+\w+|__?[us]\d+|u\d+|s\d+|int|long|short|char|bool|unsigned\s+\w+|"
    r"uintptr_t|size_t|__wsum|__be\d+|__le\d+|\w+_t)\s*\**\s*\w+\s*\[",
    re.M,
)
STRUCT_GLOBAL = re.compile(
    r"^(static\s+)?(volatile\s+)?(const\s+)?(volatile\s+)?struct\s+\w+\s+\w+\s*(=|;)",
    re.M,
)
ANON_STRUCT_GLOBAL = re.compile(r"^struct\s*\{", re.M)
MAP_DECL = re.compile(r"__uint\s*\(\s*type\s*,\s*BPF_MAP_TYPE_(\w+)\s*\)")
SEC_RE = re.compile(r'SEC\s*\(\s*"([^"]+)"\s*\)')
HELPER_CALL = re.compile(r"\b(bpf_\w+)\s*\(")
INCLUDE_C = re.compile(r'^\s*#include\s+"[^"]+\.c"', re.M)
BTF_DUMP_FIXTURE = re.compile(r"btf_dump|btf__|__attribute__\(\(btf_decl_tag", re.I)


_STRING_OR_COMMENT = re.compile(r'("(?:\\.|[^"\\\n])*")|/\*.*?\*/|//[^\n]*', re.S)


def strip_comments(src: str) -> str:
    """Remove C comments, leaving string literals alone: a // inside a string
    such as SEC("uprobe//proc/self/exe:func") is part of the section name."""
    return _STRING_OR_COMMENT.sub(lambda m: m.group(1) or "", src)


def classify(path: Path) -> dict | None:
    raw = path.read_text(errors="replace")
    src = strip_comments(raw)
    secs = [s for s in SEC_RE.findall(src) if s not in ("license", ".maps", "version")]
    is_prog = bool(secs) and not INCLUDE_C.search(src)
    if not is_prog:
        return None  # wrapper shim, header-only fixture, or library file

    hard: set[str] = set()
    soft: set[str] = set()
    detail: dict[str, list[str]] = {}

    for label, kind, rx in PATTERNS:
        if re.search(rx, src, re.M):
            (hard if kind == "hard" else soft).add(label)

    maps = set(MAP_DECL.findall(src))
    bad_maps = sorted(m for m in maps if m not in SUPPORTED_MAP_TYPES)
    if bad_maps:
        hard.add("unsupported_map")
        detail["unsupported_map"] = bad_maps
    if re.search(r'SEC\s*\(\s*"\.maps"\s*\)', src) and not maps:
        # a map with no __uint(type) is a legacy bpf_map_def or an extern
        hard.add("legacy_map_def")

    helpers = set(HELPER_CALL.findall(src)) - NOT_HELPERS
    unsupported = sorted(
        h
        for h in helpers
        if h not in SUPPORTED_HELPERS
        and not h.startswith(("bpf_core_", "bpf_probe_read_user"))
    )
    if unsupported:
        hard.add("unsupported_helper")
        detail["unsupported_helper"] = unsupported

    # file-scope globals that scalar @bpfglobal cannot hold. Map declarations
    # are anonymous structs too, so take them out first.
    no_maps = re.sub(
        r"struct\s*\{[^}]*\}\s*\w+\s*SEC\s*\(\s*\"\.maps\"\s*\)\s*;",
        "",
        src,
        flags=re.S,
    )
    body_stripped = re.sub(r"\{[^{}]*\}", "{}", no_maps)  # crude: drop innermost bodies
    for _ in range(6):
        body_stripped = re.sub(r"\{[^{}]*\}", "{}", body_stripped)
    top = "\n".join(
        line
        for line in body_stripped.splitlines()
        if not line.lstrip().startswith(("#", "SEC", "}", "{"))
    )
    if ARRAY_GLOBAL.search(top) and not re.search(
        r"^char\s+_?_?license", top, re.M | re.I
    ):
        hard.add("array_global")
    elif ARRAY_GLOBAL.search(top):
        # licence/version aside, any other array is still a blocker
        others = [
            m.group(0)
            for m in ARRAY_GLOBAL.finditer(top)
            if "license" not in m.group(0).lower()
        ]
        if others:
            hard.add("array_global")
    if STRUCT_GLOBAL.search(top) or ANON_STRUCT_GLOBAL.search(top):
        hard.add("struct_global")

    # a global written from a static helper etc. is fine; a global at all is
    # informational now that scalars are supported
    if re.search(
        r"^(volatile\s+)?(const\s+)?(volatile\s+)?(__?[us]\d+|u\d+|s\d+|int|long|short|bool|unsigned\s+\w+|uintptr_t|size_t)\s+\w+\s*(=[^=]|;)",
        top,
        re.M,
    ):
        soft.add("scalar_global")

    return {
        "file": path.name,
        "bytes": len(raw),
        "sections": sorted(set(secs)),
        "hard": sorted(hard),
        "soft": sorted(soft),
        "detail": detail,
    }


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument(
        "progs", type=Path, help="tools/testing/selftests/bpf/progs checkout"
    )
    ap.add_argument(
        "--json", action="store_true", help="emit one JSON object per program"
    )
    ap.add_argument(
        "--histogram", action="store_true", help="print the blocker histogram"
    )
    ap.add_argument(
        "--all",
        action="store_true",
        help="list every program, not only the portable ones",
    )
    ap.add_argument(
        "--max-hard",
        type=int,
        default=0,
        help="list programs with at most this many hard blockers",
    )
    args = ap.parse_args()

    results = []
    skipped = 0
    for c in sorted(args.progs.glob("*.c")):
        r = classify(c)
        if r is None:
            skipped += 1
        else:
            results.append(r)

    if args.json:
        for r in results:
            print(json.dumps(r))
        return 0

    real = len(results)
    clean = [r for r in results if not r["hard"]]
    print(
        f"{real} real programs ({skipped} shims/fixtures skipped); {len(clean)} with no hard blocker\n"
    )

    if args.histogram:
        hist = Counter(b for r in results for b in r["hard"])
        for label, n in hist.most_common():
            print(f"  {label:28s} {n:4d}  {100 * n / real:4.0f}%")
        print()

    rows = (
        results if args.all else [r for r in results if len(r["hard"]) <= args.max_hard]
    )
    rows.sort(key=lambda r: (len(r["hard"]), r["bytes"]))
    for r in rows:
        flags = " ".join(r["hard"]) or "-"
        soft = " ".join(r["soft"]) or "-"
        extra = "; ".join(f"{k}={','.join(v)}" for k, v in r["detail"].items())
        print(
            f"{r['file']:44s} {r['bytes']:6d}  hard: {flags:30s} soft: {soft}  {extra}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())

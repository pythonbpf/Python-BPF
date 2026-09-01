# Porting kernel selftests: what the first spike found

Four programs from `tools/testing/selftests/bpf/progs/` were ported as an experiment,
to answer two questions before anyone commits to doing this at scale:

1. Is LLM-assisted porting of kernel selftests viable?
2. What must real global-variable support actually handle?

Short answers: **viable, with a caveat about what a passing port proves**; and
**four distinct global shapes showed up in four programs**, which is the more
actionable finding.

## The spike

| Port | Upstream | Section | Outcome |
|---|---|---|---|
| `tracing/tracepoint_sched_switch.py` | `test_tracepoint.c` | `tracepoint/sched/sched_switch` | passes |
| `tracing/get_cgroup_id.py` | `get_cgroup_id_kern.c` | `tracepoint/syscalls/sys_enter_nanosleep` | passes |
| `tracing/autoattach.py` | `test_autoattach.c` | `raw_tp/sys_enter`, `raw_tp/sys_exit` | passes |
| `vmlinux/perf_skip.py` | `test_perf_skip.c` | `perf_event` | strict xfail — nested ctx access |

## 1. Is it viable?

**Yes, for programs inside the envelope — three of four compiled and passed `llc` on the
first attempt.** The mechanical part of a port (decorators, ctypes annotations, map
declarations, helper names) is regular enough to be reliable.

The failure was not a translation error. `perf_skip` needs `ctx.regs.ip`, which PythonBPF
genuinely cannot express, and no amount of care in the port changes that. That is the
useful kind of failure: it converts into a roadmap test that documents the gap.

Two caveats that matter more than the pass rate:

**A passing port proves less than the test it came from.** A kernel selftest is two
halves — the BPF program, and a `prog_tests/` driver that loads it through a skeleton,
triggers it, and asserts on the result. Only the BPF half is portable here, because this
framework compiles and verifies but never runs. Everything ported becomes a compiler
assertion: *PythonBPF emits a loadable, verifiable object for this program type and
feature mix*. That is worth having — it is how the `raw_tp` and `perf_event` program types
came under test at all — but it is not what "we ported the kernel's selftests" sounds
like. Closing that gap needs a runtime test tier, which is a much larger piece of work.

**Selection is the expensive step, not translation.** Of 820 real programs, 28 are
portable today. Picking those out required scoring the whole corpus against the compiler's
actual envelope; guessing from filenames does not work. The classifier that did it is
worth keeping around and re-running after each feature lands.

**Recommendation: viable and worth continuing, in small increments tied to features.**
Port a handful, let them reveal the next gap, fix the gap, port more. Bulk porting ahead of
the features would just produce a large pile of xfails.

## 2. What real globals must support

Every port that touches a global currently substitutes a one-entry `HashMap`, tagged
`WORKAROUND(globals)`. Four programs produced four distinct shapes:

| Shape | Example | What globals must support |
|---|---|---|
| none | `tracepoint_sched_switch` | — (control case) |
| scalar in + scalar out | `get_cgroup_id` | read a global, write a different one |
| flags across programs | `autoattach` | two programs in one object sharing global state |
| scalar in, compared against ctx | `perf_skip` | read-only input set by userspace before attach |
| array + cursor *(next increment)* | `cgroup_preorder` | indexed writes and read-modify-write on a global |

The last row is not in this spike but is the recommended next port precisely because it is
the most demanding shape: `result[idx++] = N` needs an array global *and* a read-modify-write
cursor, which together constrain the design more than anything here does.

### A design note worth acting on

**libbpf implements global variables as single-element `BPF_MAP_TYPE_ARRAY` maps.**
`.bss`, `.data` and `.rodata` become internal array maps at load time. Two consequences:

- A one-element **`ArrayMap`** is the structurally faithful stand-in for a global, not a
  `HashMap`. `HashMap` is used here only because `ArrayMap` is still a placeholder that
  raises `NotImplementedError`. Landing `ArrayMap` first would make the eventual migration
  to real globals close to mechanical.
- **Most of the ELF work is already done.** `@bpfglobal` is vestigial — a metadata carrier
  for `LICENSE` — but the machinery behind it already emits globals that LLVM places into
  `.bss` and `.data` correctly, and that libbpf already recognises:

  ```
  libbpf: map 'g.bss'  (global data): at sec_idx 5, offset 0, flags 0.
  libbpf: map 'g.data' (global data): at sec_idx 6, offset 0, flags 0.
  ```

  What is missing is narrower than "implement global variables": name resolution in
  `expr_pass.get_operand_value` (which resolves against `local_sym_tab`, then vmlinux
  enums, then gives up), a Python-level surface for declaring one, and userspace access
  through `pylibbpf`.

## 3. Incidental findings

- **Nested struct field access fails with a misleading error.** `ctx.regs.ip` reports
  `SyntaxError: Undefined variable actual` — naming the assignment target rather than the
  nested access that caused it. `_allocate_for_attribute` declines to allocate when the
  attribute's base is not a plain `Name`, logging at debug level, and the expression pass
  then trips over the missing symbol. The diagnostic should name the real cause.
- **One level of nested-context access already works.** `ctx.sample_period` on
  `struct_bpf_perf_event_data` compiles and `llc`s cleanly, so `perf_event` contexts are
  usable today for anything that does not need `regs`.
- **`@section` really does accept anything.** `tc`, `socket`, `fentry/…`, `lsm/…`,
  `cgroup_skb/egress`, `netfilter` and `tp_btf/…` all compile and land in the ELF verbatim.
  Program type is not a constraint; the context type is.

## Re-running the corpus scoring

The audit behind this spike scored all 976 programs against the compiler's envelope. It is
worth re-running after each feature lands, to see what the change unlocked. The blocker
histogram at the time of writing, over 820 real programs: globals 52%, verifier-test
annotations 27%, typed program macros 26%, kfuncs 20%, inline asm 16%, loops 12%.

---
name: ir-first-feature
description: PythonBPF's development loop for implementing a new compiler feature — write a minimal C eBPF reference, compile it to LLVM IR and read that as the spec, stop for a human syntax decision, then implement against the reference. Use whenever adding or extending a PythonBPF language feature (new statement/expression support, map types, globals, helpers, program constructs).
---

# The IR-first feature loop

PythonBPF targets LLVM IR via llvmlite. For any new feature, clang's output for the
equivalent C is the specification — not documentation, not intuition. Follow the loop
in order; do not skip steps because the feature "looks simple".

## 1. Write the C reference

A minimal `.bpf.c` in `tests/c-form/` exercising **only** the target feature. Small
enough that every line of the resulting IR is attributable to the feature. Prefer no
includes (define `SEC` and the `__u*` typedefs by hand) so nothing else pollutes the IR.
Cover each variant of the feature in one file (e.g. for globals: zero-init, initialized,
const, const volatile).

## 2. Compile and read the IR — this is the spec

```bash
clang -target bpf -O2 -g -emit-llvm -S feature.bpf.c -o feature.ll
llc -march=bpf -filetype=obj feature.ll -o feature.o
bpftool btf dump file feature.o        # what must come out the far end
```

Read `feature.ll` and answer, in writing: What top-level symbols/globals appear? What
do loads/stores/calls look like in the body? What `!DI*` debug metadata exists, and
what BTF does llc manufacture from it? What did -O2 fold away, and does that folding
carry semantics (it did for `const` globals)?

Version discipline: llvmlite ≥0.49 emits LLVM 21/22-era attribute spellings
(`captures(none)`, not `nocapture`). Use a clang/llc generation that accepts them, and
compare against what `pythonbpf` + the CI's LLVM actually use.

## 3. Diff against current PythonBPF output

Compile the nearest thing PythonBPF can already express and diff the `.ll`s. The delta
is the actual work item — often smaller than expected (machinery like section placement
and BTF generation frequently comes free from llc).

## 4. HARD STOP — syntax is a human decision

Present 2–3 Pythonic syntax candidates with trade-offs (declaration site, usage site,
failure modes, precedents from FastAPI/typing/Triton-style DSLs). **Wait for a human to
choose. Never proceed on your own judgment, and never treat silence as consent.** The
maintainers own the language surface.

## 5. Implement against the reference

Emit IR through the existing passes (`globals_pass`, `expr_pass`, `assign_pass`,
`allocation_pass`, `debuginfo/`). Verify by **diffing your emitted `.ll` against the
clang reference for the same shapes** — "it compiles and llc accepts it" is not the
bar; llc accepts plenty of subtly wrong IR.

### House style: lower, don't desugar

Handlers walk the AST the user wrote and emit IR directly. **Do not synthesize new AST
nodes mid-compilation and feed them back through other handlers** — no
`ast.Assign(ast.BinOp(...))` conjured to make `x += v` reuse the assignment path.

The temptation is legitimate, so know the argument you are declining. Desugaring is a
standard compiler move (CPython itself lowers `x += v` this way), it guarantees semantic
agreement with the composed form, it is the smallest diff, and any later fix to the
composed path applies automatically. Those are real benefits.

They lose in this codebase for structural reasons: the passes communicate through the
source tree. Allocation runs before codegen and walks `Assign` — a synthetic `Assign`
created during codegen is invisible to it, so the two passes silently disagree about
what the function contains (it happened to be harmless for augmented assignment only
because that statement never needs a fresh slot; that is luck, not design). Synthetic
nodes carry no source location, so diagnostics point nowhere. And `ast.dump` in the logs
shows statements the user never typed, which turns every debugging session into an
archaeology exercise.

The resolution is to move sharing down a level: **equivalence should come from shared
value-level helpers, not shared AST.** When two constructs must agree, extract the common
logic into a helper both call — the way binary-op evaluation and augmented assignment
both use `apply_binop` for the operator table and `get_operand_value` for operands —
and let each handler resolve its own target and emit its own store. Two handlers calling
one helper is the idiom; one handler manufacturing input for another is not.

## 6. Test at the right tier

- Works now → `tests/passing_tests/<category>/`.
- Documents a gap → `tests/kernel_selftest_equivalent/` with a strict xfail in
  `tests/test_config.toml` (level `"ir"`, `"llc"`, or `"verifier"`).
- Wrong-input behaviour → `tests/failing_tests/` with a config entry.
- Kernel verifier level runs in CI; locally it needs the user's sudo — ask, don't
  assume.

## House guardrails (always)

- **Never read/cat/grep `vmlinux.py` or `vmlinux.h`** — generated, enormous, will
  exhaust context. Probe with one-liners:
  `.venv/bin/python -c "import vmlinux; print(vmlinux.struct_x._fields_[:3])"`
- Ask the dev which Python binary to use, and remember that for future. The original authors use `.venv/bin/python` as their system python has no llvmlite.
- Atomic commits, `Core:`/`Tests:` subject prefixes, one logical change each.

"""
Global variables: where the loads and stores go.

Levels 1 and 2 only prove that the passing_tests/globals cases compile. What
those cases are *about* is which storage a name resolves to: the @bpfglobal's
symbol, or a stack slot that shadows it. This test reads the IR of each BPF
function and checks exactly that, so the scoping rules are pinned rather than
inferred from "it compiled".

Storage is identified by the operand: `@"name"` is the global's symbol, and
`%"name"` is the alloca of a local of the same name.
"""

import re
from pathlib import Path

import pytest

from tests.framework.compiler import run_ir_generation

GLOBALS_DIR = Path(__file__).parent / "passing_tests" / "globals"


def _function_bodies(ir_text: str) -> dict[str, str]:
    """Map each defined function's name to the text of its body."""
    return {
        m.group(1): m.group(2)
        for m in re.finditer(r'define [^\n]*@"(\w+)"[^\n]*\n\{(.*?)\n\}', ir_text, re.S)
    }


def _stores_to(body: str, operand: str) -> int:
    return len(re.findall(rf"store i\d+ [^,]+, i\d+\* {re.escape(operand)}", body))


def _loads_from(body: str, operand: str) -> int:
    return len(re.findall(rf"load i\d+, i\d+\* {re.escape(operand)}", body))


# file -> {function: [(operand, expected stores, expected loads)]}
# Expectations are exact counts, so an accidental extra access is caught too.
CASES = {
    # `global counter` writes through: load, add, store on the symbol, no slot
    # (the second load is the print of the new value).
    "augassign_counter.py": {
        "tick": [('@"counter"', 1, 2), ('%"counter"', 0, 0)],
    },
    # `global cg_id` inside an if: the store still targets the symbol.
    "write_scalar.py": {
        "trace": [('@"cg_id"', 1, 0), ('%"cg_id"', 0, 0)],
    },
    # Reads need no declaration and resolve to the symbol.
    "copy_to_local.py": {
        "prog": [('@"threshold"', 0, 3), ('%"threshold"', 0, 0)],
    },
    # Python's scoping rule: without `global`, `counter = 1` binds a local for
    # the whole body of `tick`, so every access there is the stack slot and the
    # symbol is untouched; `read_back`, which assigns nothing, reads the symbol.
    "shadowing.py": {
        "tick": [('%"counter"', 2, 2), ('@"counter"', 0, 0)],
        "read_back": [('@"counter"', 0, 1), ('%"counter"', 0, 0)],
    },
}


@pytest.mark.parametrize("name", list(CASES))
def test_globals_ir_storage(name, tmp_path):
    ll_path = tmp_path / name.replace(".py", ".ll")
    run_ir_generation(GLOBALS_DIR / name, ll_path)
    bodies = _function_bodies(ll_path.read_text())

    for func, expectations in CASES[name].items():
        assert func in bodies, f"{name}: no function '{func}' in the IR"
        body = bodies[func]
        for operand, stores, loads in expectations:
            assert _stores_to(body, operand) == stores, (
                f"{name}::{func}: expected {stores} store(s) to {operand}"
            )
            assert _loads_from(body, operand) == loads, (
                f"{name}::{func}: expected {loads} load(s) from {operand}"
            )

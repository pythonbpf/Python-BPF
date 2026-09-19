"""Semantic tests for `and` / `or` result values.

The generic IR-generation and llc tiers only check that compilation
succeeds, so a boolean operator that compiles cleanly but yields the wrong
*value* passes them both. `(prev or 0) + 1` did exactly that: the map
pointer was converted to i1 and sign-extended, so the expression added a
0/1 flag instead of the stored count.
"""

import re
from pathlib import Path

from tests.framework.compiler import run_ir_generation

SOURCE = Path(__file__).parent / "passing_tests" / "conditionals" / "map_or_default.py"


def _compile(tmp_path):
    ll_path = tmp_path / "output.ll"
    run_ir_generation(SOURCE, ll_path)
    return ll_path.read_text()


def test_or_result_is_not_a_truncated_bool(tmp_path):
    """`prev or 0` must not collapse to i1 before the addition."""
    ir = _compile(tmp_path)
    phi = re.search(r'%"or\.result" = phi\s+(\S+)', ir)
    assert phi, "no or.result phi in emitted IR"
    assert phi.group(1) != "i1", (
        "`or` produced an i1: the operand value is lost, so arithmetic on it "
        "adds a 0/1 flag instead of the stored value"
    )


def test_or_dereferences_the_map_lookup(tmp_path):
    """The stored value must be loaded, not just tested for NULL."""
    ir = _compile(tmp_path)
    assert re.search(r"load i64, i64\*", ir) or re.search(r"load i64, ptr", ir), (
        "map lookup result was never dereferenced; only its NULL-ness was used"
    )

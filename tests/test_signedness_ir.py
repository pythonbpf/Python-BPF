"""
Integer signedness: the shape of the IR.

The passing_tests/signedness cases mirror tests/c-form/signedness.bpf.c, and
the IR clang emits for that C file is the specification. Levels 1 and 2 only
prove these files compile; this test checks the operations themselves, which
is the whole point of the cases: zext vs sext on widening, udiv vs sdiv,
icmp ugt vs sgt, lshr vs ashr, and the trunc/zext pair that wraps u32 * u32.
"""

import re
from pathlib import Path

import pytest

from tests.framework.compiler import run_ir_generation

SIGNEDNESS_DIR = Path(__file__).parent / "passing_tests" / "signedness"

# file -> (patterns that must appear, patterns that must not)
CASES = {
    "widen_unsigned.py": (
        [r"zext i32 .* to i64"],
        [r"sext i32 .* to i64"],
    ),
    "widen_signed.py": (
        [r"sext i32 .* to i64"],
        [r"zext i32 .* to i64"],
    ),
    "mixed_division.py": (
        [r"\budiv i64", r"\burem i64", r"\bsdiv i64"],
        [r"\bsrem i64"],
    ),
    "unsigned_compare.py": (
        [r"icmp ugt i64", r"icmp sgt i64"],
        [],
    ),
    "narrow_wrap.py": (
        # the product is computed at 64 bits, cut to 32, then zero-extended
        [r"\bmul i64", r"trunc i64 .* to i32", r"zext i32 .* to i64"],
        [r"sext i32 .* to i64"],
    ),
    "right_shift.py": (
        [r"\blshr i64 .*, 4", r"\bashr i64 .*, 4"],
        [],
    ),
    "literal_rank.py": (
        [r"\budiv i64 .*, 4294967294"],
        [r"\bsdiv i64"],
    ),
}


@pytest.mark.parametrize("name", list(CASES))
def test_signedness_ir_shape(name, tmp_path):
    ll_path = tmp_path / name.replace(".py", ".ll")
    run_ir_generation(SIGNEDNESS_DIR / name, ll_path)
    ir_text = ll_path.read_text()

    expected, forbidden = CASES[name]
    for pattern in expected:
        assert re.search(pattern, ir_text), f"{name}: expected /{pattern}/ in the IR"
    for pattern in forbidden:
        assert not re.search(pattern, ir_text), f"{name}: /{pattern}/ must not appear"

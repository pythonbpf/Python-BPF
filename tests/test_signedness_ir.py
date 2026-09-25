"""
Integer signedness: the shape of the IR.

The passing_tests/signedness cases mirror tests/c-form/signedness.bpf.c, and
the IR clang emits for that C file is the specification. Levels 1 and 2 only
prove these files compile; this test checks the operations themselves, which
is the whole point of the cases: zext vs sext on widening, udiv vs sdiv,
icmp ugt vs sgt, lshr vs ashr, and the trunc/zext pair that wraps u32 * u32.
"""

import importlib.util
import re
from pathlib import Path

import pytest

from tests.framework.compiler import run_ir_generation

PASSING_DIR = Path(__file__).parent / "passing_tests"
HAVE_VMLINUX = importlib.util.find_spec("vmlinux") is not None

# path under passing_tests -> (patterns that must appear, patterns that must not)
CASES = {
    "signedness/widen_unsigned.py": (
        [r"zext i32 .* to i64"],
        [r"sext i32 .* to i64"],
    ),
    "signedness/widen_signed.py": (
        [r"sext i32 .* to i64"],
        [r"zext i32 .* to i64"],
    ),
    "signedness/mixed_division.py": (
        [r"\budiv i64", r"\burem i64", r"\bsdiv i64"],
        [r"\bsrem i64"],
    ),
    "signedness/unsigned_compare.py": (
        [r"icmp ugt i64", r"icmp sgt i64"],
        [],
    ),
    "signedness/narrow_wrap.py": (
        # the product is computed at 64 bits, cut to 32, then zero-extended
        [r"\bmul i64", r"trunc i64 .* to i32", r"zext i32 .* to i64"],
        [r"sext i32 .* to i64"],
    ),
    "signedness/right_shift.py": (
        [r"\blshr i64 .*, 4", r"\bashr i64 .*, 4"],
        [],
    ),
    "signedness/literal_rank.py": (
        [r"\budiv i64 .*, 4294967294"],
        [r"\bsdiv i64"],
    ),
    "signedness/augassign_unsigned.py": (
        [r"\blshr i64", r"\budiv i64", r"\burem i64"],
        [r"\bashr i64", r"\bsdiv i64", r"\bsrem i64"],
    ),
    "signedness/helper_results.py": (
        [r"\blshr i64", r"\budiv i64"],
        [r"\bashr i64", r"\bsdiv i64"],
    ),
    "signedness/map_value_sign.py": (
        [r"\blshr i64 [^,]*, 63"],
        [r"\bashr i64"],
    ),
    # u32 - int is a u32 operation: the result is cut to 32 bits and
    # zero-extended; ranked as 64-bit there would be no trunc at all.
    "vmlinux/ctx_field_rank.py": (
        [r"\bsub i64", r"trunc i64 .* to i32", r"zext i32 .* to i64"],
        [],
    ),
    # A bool widens with zext and an integer narrows to it by != 0, never by
    # trunc; sext of an i1 would return -1 for True.
    "signedness/bool_int.py": (
        [r"zext i1 .* to i(32|64)", r"icmp ne i64 .*, 0"],
        [r"sext i1 ", r"trunc i64 .* to i1"],
    ),
    # An enum constant is a C `int`, so `XDP_PASS - k` with k a c_uint32 is a
    # u32 operation: the result is cut to 32 bits and zero-extended. Ranked
    # as i64 it would be a signed 64-bit subtraction with no trunc at all.
    "vmlinux/enum_rank.py": (
        [r"trunc i64 .* to i32", r"zext i32 .* to i64"],
        [r"sext i32 .* to i64"],
    ),
    # A field of a struct map value is written through the lookup pointer,
    # behind a null check, never by indexing into the local's own slot.
    "assign/struct_map_value_field.py": (
        [r"field_count_not_null", r"field_flags_not_null", r"store i32 .*, i32\* %"],
        [r"getelementptr inbounds i64\*, i64\*\*"],
    ),
    # `return p` on a map lookup dereferences through a null check and returns
    # the i64, never the pointer.
    "return/map_value.py": (
        [r"deref_0_not_null", r"ret i64 %"],
        [r"ret i64\*"],
    ),
}


@pytest.mark.parametrize("name", list(CASES))
def test_signedness_ir_shape(name, tmp_path):
    if name.startswith("vmlinux/") and not HAVE_VMLINUX:
        pytest.skip("vmlinux.py not importable")
    ll_path = tmp_path / Path(name).name.replace(".py", ".ll")
    run_ir_generation(PASSING_DIR / name, ll_path)
    ir_text = ll_path.read_text()

    expected, forbidden = CASES[name]
    for pattern in expected:
        assert re.search(pattern, ir_text), f"{name}: expected /{pattern}/ in the IR"
    for pattern in forbidden:
        assert not re.search(pattern, ir_text), f"{name}: /{pattern}/ must not appear"

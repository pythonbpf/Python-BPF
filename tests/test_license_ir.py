"""
The license section: a program without LICENSE gets "GPL", with a warning,
and an explicit LICENSE is emitted as written, with no warning.
"""

import logging
from pathlib import Path

from tests.framework.compiler import run_ir_generation

TESTS_DIR = Path(__file__).parent


def _license_global(text):
    """The LICENSE global as compile_to_ir emits it: NUL-terminated bytes."""
    data = text.encode() + b"\x00"
    elems = ", ".join(f"i8 {b}" for b in data)
    return (
        f'@"LICENSE" = dso_local global [{len(data)} x i8] [{elems}], section "license"'
    )


def _license_ir(name, tmp_path, caplog):
    ll_path = tmp_path / "output.ll"
    with caplog.at_level(logging.WARNING, logger="pythonbpf.license_pass"):
        run_ir_generation(TESTS_DIR / name, ll_path)
    warnings = [
        r.getMessage() for r in caplog.records if r.name == "pythonbpf.license_pass"
    ]
    return ll_path.read_text(), warnings


def test_missing_license_defaults_to_gpl(tmp_path, caplog):
    ir, warnings = _license_ir("passing_tests/license_default.py", tmp_path, caplog)
    assert _license_global("GPL") in ir
    assert any('defaulting to "GPL"' in w for w in warnings), warnings


def test_explicit_license_is_kept(tmp_path, caplog):
    ir, warnings = _license_ir("failing_tests/license_non_gpl.py", tmp_path, caplog)
    assert _license_global("Proprietary") in ir
    assert not warnings, warnings

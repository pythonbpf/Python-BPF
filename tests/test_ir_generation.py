"""
Level 1 — IR Generation tests.

For every BPF test file, calls compile_to_ir() and asserts:
  1. No exception is raised by the pythonbpf compiler.
  2. No logging.ERROR records are emitted during compilation.
  3. A .ll file is produced.

Tests in failing_tests/ are marked xfail (strict=True) by conftest.py —
they must raise an exception or produce an ERROR log to pass the suite.
"""

import logging
from pathlib import Path


from tests.framework.compiler import run_ir_generation


def test_ir_generation(bpf_test_file: Path, tmp_path, caplog):
    ll_path = tmp_path / "output.ll"

    run_ir_generation(bpf_test_file, ll_path)

    error_records = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert not error_records, "IR generation produced ERROR log(s):\n" + "\n".join(
        f"  [{r.name}] {r.getMessage()}" for r in error_records
    )
    assert ll_path.exists(), "compile_to_ir() returned without writing a .ll file"

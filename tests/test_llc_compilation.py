"""
Level 2 — LLC compilation tests.

For every BPF test file, runs the full compile_to_ir() + _run_llc() pipeline
and asserts a non-empty .o file is produced.

Tests in failing_tests/ are marked xfail (strict=True) by conftest.py.
"""

import logging
from pathlib import Path


from tests.framework.compiler import run_ir_generation, run_llc


def test_llc_compilation(bpf_test_file: Path, tmp_path, caplog):
    ll_path = tmp_path / "output.ll"
    obj_path = tmp_path / "output.o"

    run_ir_generation(bpf_test_file, ll_path)

    error_records = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert not error_records, "IR generation produced ERROR log(s):\n" + "\n".join(
        f"  [{r.name}] {r.getMessage()}" for r in error_records
    )

    run_llc(ll_path, obj_path)

    assert obj_path.exists() and obj_path.stat().st_size > 0, (
        "llc did not produce a non-empty .o file"
    )

"""
Level 3 — Kernel verifier tests.

For every passing BPF test file, compiles to a .o and runs:
    sudo bpftool prog load -d <file.o> /sys/fs/bpf/bpf_prog_test_<id>

These tests are opt-in: they require sudo and kernel access, and are gated
behind the `verifier` pytest mark. Run with:

    pytest tests/test_verifier.py -m verifier -v

Note: uses the venv Python binary for any in-process calls, but bpftool
itself is invoked via subprocess with sudo. Ensure bpftool is installed
and the user can sudo.
"""

import logging
from pathlib import Path

import pytest

from tests.framework.collector import collect_all_test_files
from tests.framework.compiler import run_ir_generation, run_llc
from tests.framework.verifier import verify_object


def _passing_test_files():
    return [
        c.path
        for c in collect_all_test_files()
        if not c.is_expected_fail and not c.needs_vmlinux
    ]


def _passing_test_ids():
    return [
        c.rel_path
        for c in collect_all_test_files()
        if not c.is_expected_fail and not c.needs_vmlinux
    ]


@pytest.mark.verifier
@pytest.mark.parametrize(
    "verifier_test_file",
    _passing_test_files(),
    ids=_passing_test_ids(),
)
def test_kernel_verifier(verifier_test_file: Path, tmp_path, caplog):
    """Compile the BPF test and verify it passes the kernel verifier."""
    ll_path = tmp_path / "output.ll"
    obj_path = tmp_path / "output.o"

    run_ir_generation(verifier_test_file, ll_path)

    error_records = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert not error_records, "IR generation produced ERROR log(s):\n" + "\n".join(
        f"  [{r.name}] {r.getMessage()}" for r in error_records
    )

    run_llc(ll_path, obj_path)
    assert obj_path.exists() and obj_path.stat().st_size > 0

    ok, output = verify_object(obj_path)
    assert ok, f"Kernel verifier rejected {verifier_test_file.name}:\n{output}"

"""
pytest configuration for the PythonBPF test suite.

Test discovery:
  All .py files under tests/passing_tests/ and tests/failing_tests/ are
  collected as parametrized BPF test cases.

Markers applied automatically from test_config.toml:
  - xfail (strict=True): failing_tests/ entries that are expected to fail
  - skip:               vmlinux tests when vmlinux.py is not importable

Run the suite:
  pytest tests/ -v -m "not verifier"          # IR + LLC only (no sudo)
  pytest tests/ -v --cov=pythonbpf            # with coverage
  pytest tests/test_verifier.py -m verifier   # kernel verifier (sudo required)
"""

import logging

import pytest

from tests.framework.collector import collect_all_test_files

# ── vmlinux availability ────────────────────────────────────────────────────

try:
    import vmlinux  # noqa: F401

    VMLINUX_AVAILABLE = True
except ImportError:
    VMLINUX_AVAILABLE = False


# ── pytest_generate_tests: parametrize on bpf_test_file ───────────────────


def pytest_generate_tests(metafunc):
    if "bpf_test_file" in metafunc.fixturenames:
        cases = collect_all_test_files()
        metafunc.parametrize(
            "bpf_test_file",
            [c.path for c in cases],
            ids=[c.rel_path for c in cases],
        )


# ── pytest_collection_modifyitems: apply xfail / skip markers ─────────────


def pytest_collection_modifyitems(items):
    case_map = {c.rel_path: c for c in collect_all_test_files()}

    for item in items:
        # Resolve the test case from the parametrize ID embedded in the node id.
        # Node id format: tests/test_foo.py::test_bar[passing_tests/helpers/pid.py]
        case = None
        for bracket in (item.callspec.id,) if hasattr(item, "callspec") else ():
            case = case_map.get(bracket)
            break

        if case is None:
            continue

        # vmlinux skip
        if case.needs_vmlinux and not VMLINUX_AVAILABLE:
            item.add_marker(
                pytest.mark.skip(reason="vmlinux.py not available for current kernel")
            )
            continue

        # xfail (strict: XPASS counts as a test failure, alerting us to fixed bugs)
        if case.is_expected_fail:
            # Level "ir" → fails at IR generation: xfail both IR and LLC tests
            # Level "llc" → IR succeeds but LLC fails: only xfail the LLC test
            is_llc_test = item.nodeid.startswith("tests/test_llc_compilation.py")

            apply_xfail = (case.xfail_level == "ir") or (
                case.xfail_level == "llc" and is_llc_test
            )
            if apply_xfail:
                item.add_marker(
                    pytest.mark.xfail(
                        reason=case.xfail_reason,
                        strict=True,
                        raises=Exception,
                    )
                )


# ── caplog level fixture: capture ERROR+ from pythonbpf ───────────────────


@pytest.fixture(autouse=True)
def set_log_level(caplog):
    with caplog.at_level(logging.ERROR, logger="pythonbpf"):
        yield

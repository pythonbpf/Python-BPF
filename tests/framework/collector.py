from pathlib import Path

import tomllib

from tests.framework.bpf_test_case import BpfTestCase

TESTS_DIR = Path(__file__).parent.parent
CONFIG_FILE = TESTS_DIR / "test_config.toml"

VMLINUX_TEST_DIRS_PASSING = {
    "passing_tests/vmlinux",
    "kernel_selftest_equivalent/vmlinux",
}
VMLINUX_TEST_DIRS_FAILING = {
    "failing_tests/vmlinux",
    "failing_tests/xdp",
}


def _is_vmlinux_test(rel_path: str) -> bool:
    for prefix in VMLINUX_TEST_DIRS_PASSING | VMLINUX_TEST_DIRS_FAILING:
        if rel_path.startswith(prefix):
            return True
    return False


def _load_config() -> dict:
    if not CONFIG_FILE.exists():
        return {}
    with open(CONFIG_FILE, "rb") as f:
        return tomllib.load(f)


def collect_all_test_files() -> list[BpfTestCase]:
    config = _load_config()
    xfail_map: dict = config.get("xfail", {})

    cases = []
    for subdir in ("passing_tests", "failing_tests", "kernel_selftest_equivalent"):
        for py_file in sorted((TESTS_DIR / subdir).rglob("*.py")):
            if py_file.name == "vmlinux.py":
                # Not a test case: the per-directory symlink to the master
                # vmlinux fixture module, kept alongside tests that import it.
                continue
            rel = str(py_file.relative_to(TESTS_DIR))
            needs_vmlinux = _is_vmlinux_test(rel)

            xfail_entry = xfail_map.get(rel)
            is_expected_fail = xfail_entry is not None
            xfail_reason = xfail_entry.get("reason", "") if xfail_entry else ""
            xfail_level = xfail_entry.get("level", "ir") if xfail_entry else "ir"

            cases.append(
                BpfTestCase(
                    path=py_file,
                    rel_path=rel,
                    is_expected_fail=is_expected_fail,
                    xfail_reason=xfail_reason,
                    xfail_level=xfail_level,
                    needs_vmlinux=needs_vmlinux,
                )
            )
    return cases

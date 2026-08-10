from dataclasses import dataclass
from pathlib import Path

# The three test levels, in pipeline order. A test declared as failing at one
# level is also expected to fail at every later level: a program that cannot
# generate IR cannot reach llc, and one that llc rejects never reaches the
# kernel. Used by conftest to decide which items to mark xfail.
LEVELS = ("ir", "llc", "verifier")


def level_index(level: str) -> int:
    """Position of a level in the pipeline. Unknown levels sort first ("ir")."""
    try:
        return LEVELS.index(level)
    except ValueError:
        return 0


@dataclass
class BpfTestCase:
    path: Path
    rel_path: str
    is_expected_fail: bool = False
    xfail_reason: str = ""
    xfail_level: str = "ir"  # one of LEVELS
    needs_vmlinux: bool = False
    skip_reason: str = ""

    @property
    def test_id(self) -> str:
        return self.rel_path.replace("/", "::")

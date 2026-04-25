from dataclasses import dataclass
from pathlib import Path


@dataclass
class BpfTestCase:
    path: Path
    rel_path: str
    is_expected_fail: bool = False
    xfail_reason: str = ""
    xfail_level: str = "ir"  # "ir" or "llc"
    needs_vmlinux: bool = False
    skip_reason: str = ""

    @property
    def test_id(self) -> str:
        return self.rel_path.replace("/", "::")

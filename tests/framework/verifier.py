import subprocess
import uuid
from pathlib import Path


def verify_object(obj_path: Path) -> tuple[bool, str]:
    """Run bpftool prog load -d to verify a BPF object file against the kernel verifier.

    Pins the program temporarily at /sys/fs/bpf/bpf_prog_test_<uuid>, then removes it.
    Returns (success, combined_output). Requires sudo / root.
    """
    pin_path = f"/sys/fs/bpf/bpf_prog_test_{uuid.uuid4().hex[:8]}"
    try:
        result = subprocess.run(
            ["sudo", "bpftool", "prog", "load", "-d", str(obj_path), pin_path],
            capture_output=True,
            text=True,
            timeout=30,
        )
        output = result.stdout + result.stderr
        return result.returncode == 0, output
    except subprocess.TimeoutExpired:
        return False, "bpftool timed out after 30s"
    finally:
        subprocess.run(["sudo", "rm", "-f", pin_path], check=False, capture_output=True)

import subprocess
import uuid
from collections import namedtuple
from pathlib import Path

Output = namedtuple("Output", ["stdout", "stderr"])


def verify_object(obj_path: Path) -> tuple[bool, Output]:
    """Run bpftool prog load to verify a BPF object file against the kernel verifier.

    Pins the program temporarily at /sys/fs/bpf/bpf_prog_test_<uuid>, then removes it.
    Returns (success, Output(stdout, stderr)). Requires sudo / root.

    No -d: it asks the kernel for the full instruction-level log (log level
    1+2+4) on every load. For a program that makes the verifier walk a loop that
    log outgrows libbpf's buffer, the kernel then fails the load with ENOSPC, and
    libbpf doubles the buffer and verifies the whole program again, until the
    load takes longer than the timeout. A rejection still comes with its log:
    libbpf retries a failed load at log level 1 and prints the log as a warning.
    """
    pin_path = f"/sys/fs/bpf/bpf_prog_test_{uuid.uuid4().hex[:8]}"
    try:
        result = subprocess.run(
            ["sudo", "bpftool", "prog", "load", str(obj_path), pin_path],
            capture_output=True,
            text=True,
            timeout=30,
        )
        return result.returncode == 0, Output(
            stdout=result.stdout, stderr=result.stderr
        )
    except subprocess.TimeoutExpired:
        return False, Output(stdout="", stderr="bpftool timed out after 30s")
    finally:
        subprocess.run(["sudo", "rm", "-f", pin_path], check=False, capture_output=True)

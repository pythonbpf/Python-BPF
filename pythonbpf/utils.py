import subprocess
import re

TRACE_PATTERN = re.compile(
    rb"^(.{1,16}?)-(\d+)\s+\[(\d+)\]\s+([a-zA-Z.]+)\s+([0-9.]+):\s+.*?:\s+(.*)$"
)


def trace_pipe():
    """Util to read from the trace pipe."""
    try:
        subprocess.run(["cat", "/sys/kernel/tracing/trace_pipe"])
    except KeyboardInterrupt:
        print("Tracing stopped.")


def trace_fields():
    """Parse one line from trace_pipe into fields."""
    with open("/sys/kernel/tracing/trace_pipe", "rb", buffering=0) as f:
        while True:
            line = f.readline().rstrip()

            if not line or line.startswith(b"CPU:"):
                continue

            match = TRACE_PATTERN.match(line)
            if not match:
                raise ValueError("Cannot parse trace line")

            task, pid, cpu, flags, ts, msg = match.groups()
            return (task.strip(), int(pid), int(cpu), flags, float(ts), msg)

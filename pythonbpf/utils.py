import subprocess


def trace_pipe():
    """Util to read from the trace pipe."""
    try:
        subprocess.run(["cat", "/sys/kernel/tracing/trace_pipe"])
    except KeyboardInterrupt:
        print("Tracing stopped.")

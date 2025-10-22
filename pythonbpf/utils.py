import subprocess


def trace_pipe():
    """Util to read from the trace pipe."""
    try:
        subprocess.run(["cat", "/sys/kernel/tracing/trace_pipe"])
    except KeyboardInterrupt:
        print("Tracing stopped.")
    except (FileNotFoundError, PermissionError) as e:
        print(f"Error accessing trace_pipe: {e}. Try running as root.")


def trace_fields():
    """Parse one line from trace_pipe into fields."""
    with open("/sys/kernel/tracing/trace_pipe", "rb", buffering=0) as f:
        while True:
            line = f.readline().rstrip()

            if not line:
                continue

            # Skip lost event lines
            if line.startswith(b"CPU:"):
                continue

            # Parse BCC-style: first 16 bytes = task
            task = line[:16].lstrip().decode("utf-8")
            line = line[17:]  # Skip past task field and space

            # Find the colon that ends "pid cpu flags timestamp"
            ts_end = line.find(b":")
            if ts_end == -1:
                raise ValueError("Cannot parse trace line")

            # Split "pid [cpu] flags timestamp"
            try:
                parts = line[:ts_end].split()
                if len(parts) < 4:
                    raise ValueError("Not enough fields")

                pid = int(parts[0])
                cpu = parts[1][1:-1]  # Remove brackets from [cpu]
                cpu = int(cpu)
                flags = parts[2]
                ts = float(parts[3])
            except (ValueError, IndexError):
                raise ValueError("Cannot parse trace line")

            # Get message: skip ": symbol:" part
            line = line[ts_end + 1 :]  # Skip first ":"
            sym_end = line.find(b":")
            if sym_end != -1:
                msg = line[sym_end + 2 :].decode("utf-8")  # Skip ": " after symbol
            else:
                msg = line.lstrip().decode("utf-8")

            return (task, pid, cpu, flags, ts, msg)

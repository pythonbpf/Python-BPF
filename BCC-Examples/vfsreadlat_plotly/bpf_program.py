"""BPF program for tracing VFS read latency."""

from pythonbpf import bpf, map, struct, section, bpfglobal, BPF
from pythonbpf.helper import ktime, pid
from pythonbpf.maps import HashMap, PerfEventArray
from ctypes import c_void_p, c_uint64
import argparse
from data_collector import LatencyCollector
from dashboard import LatencyDashboard


@bpf
@struct
class latency_event:
    pid: c_uint64
    delta_us: c_uint64


@bpf
@map
def start() -> HashMap:
    """Map to store start timestamps by PID."""
    return HashMap(key=c_uint64, value=c_uint64, max_entries=10240)


@bpf
@map
def events() -> PerfEventArray:
    """Perf event array for sending latency events to userspace."""
    return PerfEventArray(key_size=c_uint64, value_size=c_uint64)


@bpf
@section("kprobe/vfs_read")
def do_entry(ctx: c_void_p) -> c_uint64:
    """Record start time when vfs_read is called."""
    p, ts = pid(), ktime()
    start.update(p, ts)
    return 0  # type: ignore [return-value]


@bpf
@section("kretprobe/vfs_read")
def do_return(ctx: c_void_p) -> c_uint64:
    """Calculate and record latency when vfs_read returns."""
    p = pid()
    tsp = start.lookup(p)

    if tsp:
        delta_ns = ktime() - tsp

        # Only track latencies > 1 microsecond
        if delta_ns > 1000:
            evt = latency_event()
            evt.pid, evt.delta_us = p, delta_ns // 1000
            events.output(evt)

        start.delete(p)

    return 0  # type: ignore [return-value]


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Monitor VFS read latency with live dashboard"
    )
    parser.add_argument(
        "--host", default="0.0.0.0", help="Dashboard host (default: 0.0.0.0)"
    )
    parser.add_argument(
        "--port", type=int, default=8050, help="Dashboard port (default: 8050)"
    )
    parser.add_argument(
        "--buffer", type=int, default=10000, help="Recent data buffer size"
    )
    return parser.parse_args()


args = parse_args()

# Load BPF program
print("Loading BPF program...")
b = BPF()
b.load()
b.attach_all()
print("✅ BPF program loaded and attached")

# Setup data collector
collector = LatencyCollector(b, buffer_size=args.buffer)
collector.start()

# Create and run dashboard
dashboard = LatencyDashboard(collector)
dashboard.run(host=args.host, port=args.port)

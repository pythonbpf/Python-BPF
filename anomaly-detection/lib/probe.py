"""
PythonBPF eBPF Probe for Syscall Histogram Collection
"""

from vmlinux import struct_trace_event_raw_sys_enter
from pythonbpf import bpf, map, section, bpfglobal, BPF
from pythonbpf.helper import pid
from pythonbpf.maps import HashMap
from ctypes import c_int64
from lib import MAX_SYSCALLS, comm_for_pid


@bpf
@map
def histogram() -> HashMap:
    return HashMap(key=c_int64, value=c_int64, max_entries=1024)


@bpf
@map
def target_pid_map() -> HashMap:
    return HashMap(key=c_int64, value=c_int64, max_entries=1)


@bpf
@section("tracepoint/raw_syscalls/sys_enter")
def trace_syscall(ctx: struct_trace_event_raw_sys_enter) -> c_int64:
    syscall_id = ctx.id
    current_pid = pid()
    target = target_pid_map.lookup(0)
    if target:
        if current_pid != target:
            return 0  # type: ignore
    if syscall_id < 0 or syscall_id >= 548:
        return 0  # type: ignore
    count = histogram.lookup(syscall_id)
    if count:
        histogram.update(syscall_id, count + 1)
    else:
        histogram.update(syscall_id, 1)
    return 0  # type: ignore


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


ebpf_prog = BPF()


class Probe:
    """
    Syscall histogram probe for a target process.

    Usage:
        probe = Probe(target_pid=1234)
        probe.start()
        histogram = probe.get_histogram()
    """

    def __init__(self, target_pid: int, max_syscalls: int = MAX_SYSCALLS):
        self.target_pid = target_pid
        self.max_syscalls = max_syscalls
        self.comm = comm_for_pid(target_pid)

        if self.comm is None:
            raise ValueError(f"Cannot find process with PID {target_pid}")

        self._bpf = None
        self._histogram_map = None
        self._target_map = None

    def start(self):
        """Compile, load, and attach the BPF probe."""
        # Compile and load
        self._bpf = ebpf_prog
        self._bpf.load()
        self._bpf.attach_all()

        # Get map references
        self._histogram_map = self._bpf["histogram"]
        self._target_map = self._bpf["target_pid_map"]

        # Set target PID in the map
        self._target_map.update(0, self.target_pid)

        return self

    def get_histogram(self) -> list:
        """Read current histogram values as a list."""
        if self._histogram_map is None:
            raise RuntimeError("Probe not started.  Call start() first.")

        result = [0] * self.max_syscalls

        for syscall_id in range(self.max_syscalls):
            try:
                count = self._histogram_map.lookup(syscall_id)
                if count is not None:
                    result[syscall_id] = int(count)
            except Exception:
                pass

        return result

    def __getitem__(self, syscall_id: int) -> int:
        """Allow indexing: probe[syscall_id]"""
        if self._histogram_map is None:
            raise RuntimeError("Probe not started")

        try:
            count = self._histogram_map.lookup(syscall_id)
            return int(count) if count is not None else 0
        except Exception:
            return 0

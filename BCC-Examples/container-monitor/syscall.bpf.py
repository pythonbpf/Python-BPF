import time
import os
from pathlib import Path
from pythonbpf import bpf, map, section, bpfglobal, BPF
from pythonbpf.maps import HashMap
from pythonbpf.helper import get_current_cgroup_id
from ctypes import c_void_p, c_int32, c_uint64


@bpf
@map
def syscall_count() -> HashMap:
    """Map tracking syscall count by cgroup ID"""
    return HashMap(key=c_uint64, value=c_uint64, max_entries=1024)


@bpf
@section("tracepoint/raw_syscalls/sys_enter")
def count_syscalls(ctx: c_void_p) -> c_int32:
    """
    Increment syscall counter for the current cgroup. 
    Attached to raw_syscalls/sys_enter tracepoint to catch all syscalls.
    """
    cgroup_id = get_current_cgroup_id()

    # Lookup current count
    count_ptr = syscall_count.lookup(cgroup_id)

    if count_ptr:
        # Increment existing count
        new_count = count_ptr + c_uint64(1)
        syscall_count.update(cgroup_id, new_count)
    else:
        # First syscall for this cgroup
        syscall_count.update(cgroup_id, c_uint64(1))

    return c_int32(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


# Load and attach BPF program
b = BPF()
b.load()
b.attach_all()

# Get map reference
syscall_count_ref = b["syscall_count"]


def get_cgroup_ids():
    """Get all cgroup IDs from the system"""
    cgroup_ids = set()

    # Get cgroup IDs from running processes
    for proc_dir in Path("/proc").glob("[0-9]*"):
        try:
            cgroup_file = proc_dir / "cgroup"
            if cgroup_file.exists():
                with open(cgroup_file) as f:
                    for line in f:
                        # Parse cgroup path and get inode
                        parts = line.strip().split(":")
                        if len(parts) >= 3:
                            cgroup_path = parts[2]
                            # Try to get the cgroup inode which is used as ID
                            cgroup_mount = f"/sys/fs/cgroup{cgroup_path}"
                            if os.path.exists(cgroup_mount):
                                stat_info = os.stat(cgroup_mount)
                                cgroup_ids.add(stat_info.st_ino)
        except (PermissionError, FileNotFoundError, OSError):
            continue

    return cgroup_ids


# Display function
def display_stats():
    """Read and display syscall statistics from BPF maps"""
    print("\n" + "=" * 60)
    print(f"{'CGROUP ID':<20} {'SYSCALL COUNT':<20}")
    print("=" * 60)

    # Get cgroup IDs from the system
    cgroup_ids = get_cgroup_ids()

    if not cgroup_ids:
        print("No cgroups found...")
        print("=" * 60)
        return

    # Initialize totals
    total_syscalls = 0

    # Track which cgroups have data
    cgroups_with_data = []

    # Display stats for each cgroup
    for cgroup_id in sorted(cgroup_ids):
        # Get syscall count using lookup
        syscall_cnt = 0

        count = syscall_count_ref.lookup(cgroup_id)
        if count is not None:
            syscall_cnt = int(count)
            total_syscalls += syscall_cnt

            print(f"{cgroup_id:<20} {syscall_cnt:<20}")
            cgroups_with_data.append(cgroup_id)

    if not cgroups_with_data:
        print("No data collected yet...")

    print("=" * 60)
    print(f"{'TOTAL':<20} {total_syscalls:<20}")
    print()


# Main loop
if __name__ == "__main__":
    print("Tracing syscalls per cgroup...   Press Ctrl+C to exit\n")

    try:
        while True:
            time.sleep(5)  # Update every 5 seconds
            display_stats()
    except KeyboardInterrupt:
        print("\nStopped")

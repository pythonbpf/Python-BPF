import logging
import time
import os
from pathlib import Path
from pythonbpf import bpf, map, section, bpfglobal, struct, compile, BPF
from pythonbpf.maps import HashMap
from pythonbpf.helper import get_current_cgroup_id
from ctypes import c_int32, c_uint64
from vmlinux import struct_pt_regs


@bpf
@struct
class read_stats:
    bytes: c_uint64
    ops: c_uint64


@bpf
@struct
class write_stats:
    bytes: c_uint64
    ops: c_uint64


@bpf
@map
def read_map() -> HashMap:
    return HashMap(key=c_uint64, value=read_stats, max_entries=1024)


@bpf
@map
def write_map() -> HashMap:
    return HashMap(key=c_uint64, value=write_stats, max_entries=1024)


@bpf
@section("kprobe/vfs_read")
def trace_read(ctx: struct_pt_regs) -> c_int32:
    cg = get_current_cgroup_id()
    count = c_uint64(ctx.dx)
    ptr = read_map.lookup(cg)
    if ptr:
        s = read_stats()
        s.bytes = ptr.bytes + count
        s.ops = ptr.ops + 1
        read_map.update(cg, s)
    else:
        s = read_stats()
        s.bytes = count
        s.ops = c_uint64(1)
        read_map.update(cg, s)

    return c_int32(0)


@bpf
@section("kprobe/vfs_write")
def trace_write(ctx1: struct_pt_regs) -> c_int32:
    cg = get_current_cgroup_id()
    count = c_uint64(ctx1.dx)
    ptr = write_map.lookup(cg)

    if ptr:
        s = write_stats()
        s.bytes = ptr.bytes + count
        s.ops = ptr.ops + 1
        write_map.update(cg, s)
    else:
        s = write_stats()
        s.bytes = count
        s.ops = c_uint64(1)
        write_map.update(cg, s)

    return c_int32(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


# Load and attach BPF program
b = BPF()
b.load()
b.attach_all()

# Get map references and enable struct deserialization
read_map_ref = b["read_map"]
write_map_ref = b["write_map"]
read_map_ref.set_value_struct("read_stats")
write_map_ref.set_value_struct("write_stats")


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
    """Read and display file I/O statistics from BPF maps"""
    print("\n" + "=" * 80)
    print(f"{'CGROUP ID':<20} {'READ OPS':<15} {'READ BYTES':<20} {'WRITE OPS':<15} {'WRITE BYTES':<20}")
    print("=" * 80)

    # Get cgroup IDs from the system
    cgroup_ids = get_cgroup_ids()

    if not cgroup_ids:
        print("No cgroups found...")
        print("=" * 80)
        return

    # Initialize totals
    total_read_ops = 0
    total_read_bytes = 0
    total_write_ops = 0
    total_write_bytes = 0

    # Track which cgroups have data
    cgroups_with_data = []

    # Display stats for each cgroup
    for cgroup_id in sorted(cgroup_ids):
        # Get read stats using lookup
        read_ops = 0
        read_bytes = 0
        read_stat = read_map_ref.lookup(cgroup_id)
        if read_stat:
            read_ops = int(read_stat.ops)
            read_bytes = int(read_stat.bytes)
            total_read_ops += read_ops
            total_read_bytes += read_bytes

        # Get write stats using lookup
        write_ops = 0
        write_bytes = 0
        write_stat = write_map_ref.lookup(cgroup_id)
        if write_stat:
            write_ops = int(write_stat.ops)
            write_bytes = int(write_stat.bytes)
            total_write_ops += write_ops
            total_write_bytes += write_bytes

        # Only print if there's data for this cgroup
        if read_stat or write_stat:
            print(f"{cgroup_id:<20} {read_ops:<15} {read_bytes:<20} {write_ops:<15} {write_bytes:<20}")
            cgroups_with_data.append(cgroup_id)

    if not cgroups_with_data:
        print("No data collected yet...")

    print("=" * 80)
    print(f"{'TOTAL':<20} {total_read_ops:<15} {total_read_bytes:<20} {total_write_ops:<15} {total_write_bytes:<20}")
    print()


# Main loop
if __name__ == "__main__":
    print("Tracing file I/O operations...   Press Ctrl+C to exit\n")

    try:
        while True:
            time.sleep(5)  # Update every 5 seconds
            display_stats()
    except KeyboardInterrupt:
        print("\nStopped")

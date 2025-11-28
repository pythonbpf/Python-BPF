import logging
import time
import os
from pathlib import Path
from pythonbpf import bpf, map, section, bpfglobal, struct, compile, BPF
from pythonbpf.maps import HashMap
from pythonbpf.helper import get_current_cgroup_id
from ctypes import c_int32, c_uint64, c_void_p, c_uint32
from vmlinux import struct_sk_buff, struct_pt_regs


@bpf
@struct
class net_stats:
    rx_packets: c_uint64
    tx_packets: c_uint64
    rx_bytes: c_uint64
    tx_bytes: c_uint64


@bpf
@map
def net_stats_map() -> HashMap:
    return HashMap(key=c_uint64, value=net_stats, max_entries=1024)


@bpf
@section("kprobe/__netif_receive_skb")
def trace_netif_rx(ctx: struct_pt_regs) -> c_int32:
    cgroup_id = get_current_cgroup_id()

    # Read skb pointer from first argument (PT_REGS_PARM1)
    skb = struct_sk_buff(ctx.di)  # x86_64: first arg in rdi

    # Read skb->len
    pkt_len = c_uint64(skb.len)


    stats_ptr = net_stats_map.lookup(cgroup_id)

    if stats_ptr:
        stats = net_stats()
        stats.rx_packets = stats_ptr.rx_packets + 1
        stats.tx_packets = stats_ptr.tx_packets
        stats.rx_bytes = stats_ptr.rx_bytes + pkt_len
        stats.tx_bytes = stats_ptr.tx_bytes
        net_stats_map.update(cgroup_id, stats)
    else:
        stats = net_stats()
        stats.rx_packets = c_uint64(1)
        stats.tx_packets = c_uint64(0)
        stats.rx_bytes = pkt_len
        stats.tx_bytes = c_uint64(0)
        net_stats_map.update(cgroup_id, stats)

    return c_int32(0)

@bpf
@section("kprobe/__dev_queue_xmit")
def trace_dev_xmit(ctx1: struct_pt_regs) -> c_int32:
    cgroup_id = get_current_cgroup_id()

    # Read skb pointer from first argument
    skb = struct_sk_buff(ctx1.di)
    pkt_len = c_uint64(skb.len)

    stats_ptr = net_stats_map.lookup(cgroup_id)

    if stats_ptr:
        stats = net_stats()
        stats.rx_packets = stats_ptr.rx_packets
        stats.tx_packets = stats_ptr.tx_packets + 1
        stats.rx_bytes = stats_ptr.rx_bytes
        stats.tx_bytes = stats_ptr.tx_bytes + pkt_len
        net_stats_map.update(cgroup_id, stats)
    else:
        stats = net_stats()
        stats.rx_packets = c_uint64(0)
        stats.tx_packets = c_uint64(1)
        stats.rx_bytes = c_uint64(0)
        stats.tx_bytes = pkt_len
        net_stats_map.update(cgroup_id, stats)

    return c_int32(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"

# Load and attach BPF program
b = BPF()
b.load()
b.attach_all()

# Get map reference and enable struct deserialization
net_stats_map_ref = b["net_stats_map"]
net_stats_map_ref.set_value_struct("net_stats")


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
    """Read and display network I/O statistics from BPF maps"""
    print("\n" + "=" * 100)
    print(f"{'CGROUP ID':<20} {'RX PACKETS':<15} {'RX BYTES':<20} {'TX PACKETS':<15} {'TX BYTES':<20}")
    print("=" * 100)

    # Get cgroup IDs from the system
    cgroup_ids = get_cgroup_ids()

    if not cgroup_ids:
        print("No cgroups found...")
        print("=" * 100)
        return

    # Initialize totals
    total_rx_packets = 0
    total_rx_bytes = 0
    total_tx_packets = 0
    total_tx_bytes = 0

    # Track which cgroups have data
    cgroups_with_data = []

    # Display stats for each cgroup
    for cgroup_id in sorted(cgroup_ids):
        # Get network stats using lookup
        rx_packets = 0
        rx_bytes = 0
        tx_packets = 0
        tx_bytes = 0

        net_stat = net_stats_map_ref.lookup(cgroup_id)
        if net_stat:
            rx_packets = int(net_stat.rx_packets)
            rx_bytes = int(net_stat.rx_bytes)
            tx_packets = int(net_stat.tx_packets)
            tx_bytes = int(net_stat.tx_bytes)

            total_rx_packets += rx_packets
            total_rx_bytes += rx_bytes
            total_tx_packets += tx_packets
            total_tx_bytes += tx_bytes

            print(f"{cgroup_id:<20} {rx_packets:<15} {rx_bytes:<20} {tx_packets:<15} {tx_bytes:<20}")
            cgroups_with_data.append(cgroup_id)

    if not cgroups_with_data:
        print("No data collected yet...")

    print("=" * 100)
    print(f"{'TOTAL':<20} {total_rx_packets:<15} {total_rx_bytes:<20} {total_tx_packets:<15} {total_tx_bytes:<20}")
    print()


# Main loop
if __name__ == "__main__":
    print("Tracing network I/O operations...    Press Ctrl+C to exit\n")

    try:
        while True:
            time.sleep(5)  # Update every 5 seconds
            display_stats()
    except KeyboardInterrupt:
        print("\nStopped")

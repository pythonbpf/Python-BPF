"""Container Monitor - TUI-based cgroup monitoring combining syscall, file I/O, and network tracking."""

import time
import os
from pathlib import Path
from pythonbpf import bpf, map, section, bpfglobal, struct, BPF
from pythonbpf.maps import HashMap
from pythonbpf.helper import get_current_cgroup_id
from ctypes import c_int32, c_uint64, c_void_p
from vmlinux import struct_pt_regs, struct_sk_buff

from data_collector import ContainerDataCollector
from tui import ContainerMonitorTUI


# ==================== BPF Structs ====================

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
@struct
class net_stats:
    rx_packets: c_uint64
    tx_packets: c_uint64
    rx_bytes: c_uint64
    tx_bytes: c_uint64


# ==================== BPF Maps ====================

@bpf
@map
def read_map() -> HashMap:
    return HashMap(key=c_uint64, value=read_stats, max_entries=1024)


@bpf
@map
def write_map() -> HashMap:
    return HashMap(key=c_uint64, value=write_stats, max_entries=1024)


@bpf
@map
def net_stats_map() -> HashMap:
    return HashMap(key=c_uint64, value=net_stats, max_entries=1024)


@bpf
@map
def syscall_count() -> HashMap:
    return HashMap(key=c_uint64, value=c_uint64, max_entries=1024)


# ==================== File I/O Tracing ====================

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


# ==================== Network I/O Tracing ====================

@bpf
@section("kprobe/__netif_receive_skb")
def trace_netif_rx(ctx2: struct_pt_regs) -> c_int32:
    cgroup_id = get_current_cgroup_id()
    skb = struct_sk_buff(ctx2.di)
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
def trace_dev_xmit(ctx3: struct_pt_regs) -> c_int32:
    cgroup_id = get_current_cgroup_id()
    skb = struct_sk_buff(ctx3.di)
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


# ==================== Syscall Tracing ====================

@bpf
@section("tracepoint/raw_syscalls/sys_enter")
def count_syscalls(ctx: c_void_p) -> c_int32:
    cgroup_id = get_current_cgroup_id()
    count_ptr = syscall_count.lookup(cgroup_id)

    if count_ptr:
        new_count = count_ptr + c_uint64(1)
        syscall_count.update(cgroup_id, new_count)
    else:
        syscall_count.update(cgroup_id, c_uint64(1))

    return c_int32(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


# ==================== Main ====================

if __name__ == "__main__":
    print("🔥 Loading BPF programs...")
    
    # Load and attach BPF program
    b = BPF()
    b.load()
    b.attach_all()
    
    # Get map references and enable struct deserialization
    read_map_ref = b["read_map"]
    write_map_ref = b["write_map"]
    net_stats_map_ref = b["net_stats_map"]
    syscall_count_ref = b["syscall_count"]
    
    read_map_ref.set_value_struct("read_stats")
    write_map_ref.set_value_struct("write_stats")
    net_stats_map_ref.set_value_struct("net_stats")
    
    print("✅ BPF programs loaded and attached")
    
    # Setup data collector
    collector = ContainerDataCollector(
        read_map_ref,
        write_map_ref,
        net_stats_map_ref,
        syscall_count_ref
    )
    
    # Create and run TUI
    tui = ContainerMonitorTUI(collector)
    tui.run()

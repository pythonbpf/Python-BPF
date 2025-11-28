import logging

from pythonbpf import bpf, map, section, bpfglobal, struct, compile
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


#
# READ PROBE
#
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
        read_map.update(cg, ptr)
    else:
        print("read init")
        s = read_stats()
        s.bytes = count
        s.ops = c_uint64(1)
        read_map.update(cg, s)

    return c_int32(0)


#
# WRITE PROBE
#
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
        print("write init")
        s = write_stats()
        s.bytes = count
        s.ops = c_uint64(1)
        write_map.update(cg, s)

    return c_int32(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile(loglevel=logging.INFO)

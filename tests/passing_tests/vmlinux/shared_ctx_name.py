# Two programs whose context parameters share a name and a vmlinux type. Their
# debug info used to share one cached DILocalVariable, scoped to both
# functions, and llvmlite recursed forever hashing the resulting cycle.
from ctypes import c_int64
from pythonbpf import bpf, section, bpfglobal, compile
from vmlinux import struct_pt_regs


@bpf
@section("kprobe/do_unlinkat")
def first(ctx: struct_pt_regs) -> c_int64:
    return c_int64(0)


@bpf
@section("kprobe/do_rmdir")
def second(ctx: struct_pt_regs) -> c_int64:
    return c_int64(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()

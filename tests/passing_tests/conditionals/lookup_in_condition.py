# A helper call that needs a scratch temp (the literal key has to be spilled
# to the stack for bpf_map_lookup_elem) appearing only in an `if` condition.
# The temp count used to skip conditions, so this failed with "Scratch pool
# exhausted" while the same lookup on a line of its own compiled.
from pythonbpf import bpf, map, section, bpfglobal, compile
from pythonbpf.maps import HashMap
from ctypes import c_void_p, c_int64, c_uint32, c_uint64


@bpf
@map
def m() -> HashMap:
    return HashMap(key=c_uint32, value=c_uint64, max_entries=4)


@bpf
@section("tracepoint/raw_syscalls/sys_enter")
def prog(ctx: c_void_p) -> c_int64:
    if m.lookup(5):
        return c_int64(1)
    elif m.lookup(6):
        return c_int64(2)
    return c_int64(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()

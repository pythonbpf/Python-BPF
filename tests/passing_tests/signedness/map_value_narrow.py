# Map values narrower than 64 bits are read and written at their own width:
# the verifier rejects an 8-byte access to a 4-byte value. Each value is then
# widened per its declared sign -- zext for c_uint32 and c_uint8, sext for
# c_int32 -- in arithmetic, comparisons and printing alike, and a c_uint8
# value prints as a number, not as a string.
from pythonbpf import bpf, map, section, bpfglobal, compile
from pythonbpf.maps import HashMap
from ctypes import c_void_p, c_int64, c_uint32, c_int32, c_uint8


@bpf
@map
def u32s() -> HashMap:
    return HashMap(key=c_uint32, value=c_uint32, max_entries=4)


@bpf
@map
def i32s() -> HashMap:
    return HashMap(key=c_uint32, value=c_int32, max_entries=4)


@bpf
@map
def u8s() -> HashMap:
    return HashMap(key=c_uint32, value=c_uint8, max_entries=4)


@bpf
@section("tracepoint/raw_syscalls/sys_enter")
def prog(ctx: c_void_p) -> c_int64:
    k = c_uint32(0)
    u = u32s.lookup(k)
    i = i32s.lookup(k)
    b = u8s.lookup(k)
    if u:
        if u == 3:
            print(f"u {u}")
        u32s.update(k, u + 1)
    if i:
        n = i - 1
        print(f"i {i} n {n}")
    if b:
        print(f"b {b}")
        b = b + 2
        return b
    return c_int64(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()

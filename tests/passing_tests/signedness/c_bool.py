# c_bool is C's _Bool: a value narrows to it by comparing with zero (5 is
# true), and it widens to 0 or 1 (zero-extended, never sign-extended), as a
# local, a struct field, a map value and a global. In BTF it is a one-byte
# _Bool, so the map's value size is 1.
from ctypes import c_bool, c_int64, c_uint32, c_void_p
from pythonbpf import bpf, map, struct, section, bpfglobal, compile
from pythonbpf.maps import HashMap


@bpf
@struct
class flags:
    on: c_bool
    n: c_uint32


@bpf
@map
def seen() -> HashMap:
    return HashMap(key=c_uint32, value=c_bool, max_entries=4)


@bpf
@bpfglobal
def armed() -> c_bool:
    return c_bool(1)


@bpf
@section("tracepoint/raw_syscalls/sys_enter")
def prog(ctx: c_void_p) -> c_int64:
    global armed
    b = c_bool(5)
    f = flags()
    f.on = 2
    k = c_uint32(1)
    seen.update(k, c_bool(1))
    armed = 7
    print(f"{b} {f.on} {armed}")
    return c_int64(b)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()

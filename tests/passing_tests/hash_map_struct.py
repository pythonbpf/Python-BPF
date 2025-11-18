from pythonbpf import bpf, section, struct, bpfglobal, compile, map
from pythonbpf.maps import HashMap
from pythonbpf.helper import pid
from ctypes import c_void_p, c_int64


@bpf
@struct
class val_type:
    counter: c_int64
    shizzle: c_int64


@bpf
@map
def last() -> HashMap:
    return HashMap(key=val_type, value=c_int64, max_entries=16)


@bpf
@section("tracepoint/syscalls/sys_enter_clone")
def hello_world(ctx: c_void_p) -> c_int64:
    obj = val_type()
    obj.counter, obj.shizzle = 42, 96
    t = last.lookup(obj)
    if t:
        print(f"Found existing entry: counter={obj.counter}, pid={t}")
        last.delete(obj)
        return 0  # type: ignore [return-value]
    val = pid()
    last.update(obj, val)
    print(f"Map updated!, {obj.counter}, {obj.shizzle}, {val}")
    return 0  # type: ignore [return-value]


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()

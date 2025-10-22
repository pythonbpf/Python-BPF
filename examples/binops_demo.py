from pythonbpf import bpf, map, section, bpfglobal, compile
from pythonbpf.helper import ktime
from pythonbpf.maps import HashMap

from ctypes import c_void_p, c_int64, c_uint64

# Instructions to how to run this program
# 1. Install PythonBPF: pip install pythonbpf
# 2. Run the program: python examples/binops_demo.py
# 3. Run the program with sudo: sudo tools/check.sh run examples/binops_demo.py
# 4. Start up any program and watch the output


@bpf
@map
def last() -> HashMap:
    return HashMap(key=c_uint64, value=c_uint64, max_entries=3)


@bpf
@section("tracepoint/syscalls/sys_enter_execve")
def do_trace(ctx: c_void_p) -> c_int64:
    key = 0
    tsp = last.lookup(key)
    if tsp:
        kt = ktime()
        delta = kt - tsp
        if delta < 1000000000:
            time_ms = delta // 1000000
            print(f"Execve syscall entered within last second, last {time_ms} ms ago")
        last.delete(key)
    else:
        kt = ktime()
        last.update(key, kt)
    return c_int64(0)


@bpf
@section("tracepoint/syscalls/sys_exit_execve")
def do_exit(ctx: c_void_p) -> c_int64:
    va = 8
    nm = 5 ^ va
    al = 6 & 3
    ru = nm + al
    print(f"this is a variable {ru}")
    return c_int64(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()

from pythonbpf import bpf, map, section, bpfglobal, compile, compile_to_ir
from pythonbpf.maps import HashMap
from vmlinux import struct_xdp_md, XDP_PASS
from ctypes import c_int64

# Instructions to how to run this program
# 1. Install PythonBPF: pip install pythonbpf
# 2. Run the program: python examples/xdp_pass.py
# 3. Run the program with sudo: sudo tools/check.sh run examples/xdp_pass.o
# 4. Attach object file to any network device with something like ./check.sh xdp examples/xdp_pass.o tailscale0
# 5. send traffic through the device and observe effects


@bpf
@map
def count() -> HashMap:
    return HashMap(key=c_int64, value=c_int64, max_entries=1)


@bpf
@section("xdp")
def hello_world(ctx: struct_xdp_md) -> c_int64:
    key = 0
    one = 1
    prev = count().lookup(key)
    if prev:
        prevval = prev + 1
        print(f"count: {prevval}")
        count().update(key, prevval)
        return XDP_PASS
    else:
        count().update(key, one)

    return XDP_PASS


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"

compile_to_ir("xdp_pass.py", "xdp_pass.ll")
compile()

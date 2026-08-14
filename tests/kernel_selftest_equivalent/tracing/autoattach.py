# Ported from Linux tools/testing/selftests/bpf/progs/test_autoattach.c
#
# Two programs on different raw tracepoints, each recording that it ran. The
# upstream test asserts both fired after bpf_object__attach_skeleton().
#
# WORKAROUND(globals): upstream uses `bool prog1_called` / `bool prog2_called`.
# PythonBPF has no global variable support yet, so both live in one HashMap
# keyed by program number. Replace with real globals once they land.

from pythonbpf import bpf, map, section, bpfglobal, compile
from pythonbpf.maps import HashMap
from ctypes import c_void_p, c_int64, c_int32, c_uint64


# WORKAROUND(globals): key 1 -> prog1_called, key 2 -> prog2_called
@bpf
@map
def called() -> HashMap:
    return HashMap(key=c_int32, value=c_uint64, max_entries=2)


@bpf
@section("raw_tp/sys_enter")
def prog1(ctx: c_void_p) -> c_int64:
    called.update(1, 1)
    return c_int64(0)


@bpf
@section("raw_tp/sys_exit")
def prog2(ctx: c_void_p) -> c_int64:
    called.update(2, 1)
    return c_int64(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()

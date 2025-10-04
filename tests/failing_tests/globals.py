import logging

from pythonbpf import compile, bpf, section, bpfglobal, compile_to_ir
from ctypes import c_void_p, c_int64, c_int32

@bpf
@bpfglobal
def somevalue() -> c_int32:
    return c_int32(42)

@bpf
@bpfglobal
def somevalue2() -> c_int64:
    return c_int64(69)

@bpf
@bpfglobal
def somevalue1() -> c_int32:
    return c_int32(42)


# --- Passing examples ---

# Simple constant return
@bpf
@bpfglobal
def g1() -> c_int64:
    return 42

# Constructor with one constant argument
@bpf
@bpfglobal
def g2() -> c_int64:
    return c_int64(69)


# --- Failing examples ---

# No return annotation
# @bpf
# @bpfglobal
# def g3():
#     return 42

# Return annotation is complex
# @bpf
# @bpfglobal
# def g4() -> List[int]:
#     return []

# # Return is missing
# @bpf
# @bpfglobal
# def g5() -> c_int64:
#     pass

# # Return is a variable reference
# #TODO: maybe fix this sometime later. It defaults to 0
CONST = 5
@bpf
@bpfglobal
def g6() -> c_int64:
    return c_int64(CONST)

# Constructor with multiple args
#TODO: this is not working. should it work ?
@bpf
@bpfglobal
def g7() -> c_int64:
    return c_int64(1, 2)

# Dataclass call
#TODO: fails with dataclass
# @dataclass
# class Point:
#     x: c_int64
#     y: c_int64

# @bpf
# @bpfglobal
# def g8() -> Point:
#     return Point(1, 2)


@bpf
@section("tracepoint/syscalls/sys_enter_execve")
def sometag(ctx: c_void_p) -> c_int64:
    print("test")
    return c_int64(1)

@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile_to_ir("globals.py", "globals.ll", loglevel=logging.INFO)
compile()

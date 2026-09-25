# A context field stored into a slot of any integer width: the field is loaded
# at its declared width, zero-extended (all of these are unsigned), then cut to
# the slot's width, as C's `__u8 x = skb->len` does. Covers locals declared
# with every width and struct fields of every width.
from ctypes import c_int8, c_uint16, c_int32, c_uint64, c_uint8, c_uint32, c_int64
from pythonbpf import bpf, struct, section, bpfglobal, compile
from vmlinux import struct___sk_buff


@bpf
@struct
class rec:
    f8: c_uint8
    f16: c_uint16
    f32: c_uint32
    f64: c_uint64


@bpf
@section("tc")
def prog(ctx: struct___sk_buff) -> c_int64:
    a8 = c_int8(0)
    a8 = ctx.len  # u32 -> i8
    b16 = c_uint16(0)
    b16 = ctx.len  # u32 -> u16
    c32 = c_int32(0)
    c32 = ctx.tstamp  # u64 -> i32
    d64 = c_uint64(0)
    d64 = ctx.tstamp_type  # u8 -> u64
    e = ctx.len  # undeclared: a 64-bit slot
    r = rec()
    r.f8 = ctx.len
    r.f16 = ctx.tstamp
    r.f32 = ctx.tstamp
    r.f64 = ctx.tstamp_type
    print(f"{a8} {b16} {c32}")
    print(f"{d64} {e}")
    return c_int64(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()

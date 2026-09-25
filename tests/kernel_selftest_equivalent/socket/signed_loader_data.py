# Ported from Linux tools/testing/selftests/bpf/progs/test_signed_loader_data.c
#
# The signed-loader fixture with one initialised global, so the object has a
# .data map that the loader must seed. Upstream checks that a signed loader
# keeps the attested initial value:
#
#     __u64 magic = 0x5eed1234abad1deaULL;
#
#     SEC("socket")
#     int probe(void *ctx)
#     {
#             return (int)magic;
#     }

from pythonbpf import bpf, section, bpfglobal, compile
from ctypes import c_void_p, c_int32, c_uint64


@bpf
@bpfglobal
def magic() -> c_uint64:
    return c_uint64(0x5EED1234ABAD1DEA)


@bpf
@section("socket")
def probe(ctx: c_void_p) -> c_int32:
    return c_int32(magic)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()

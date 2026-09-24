# Ported from Linux tools/testing/selftests/bpf/progs/test_signed_loader.c
#
# A minimal, map-less socket filter. Upstream drives it through libbpf's
# light-skeleton loader to test signed-program loading; a socket filter
# needs no attach resolution and no maps keeps the loader trivial.

from pythonbpf import bpf, section, bpfglobal, compile
from ctypes import c_void_p, c_int64


@bpf
@section("socket")
def probe(ctx: c_void_p) -> c_int64:
    return c_int64(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()

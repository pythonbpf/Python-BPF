from pythonbpf import bpf, struct, section, bpfglobal, compile
from pythonbpf.helper import comm

from ctypes import c_void_p, c_int64


@bpf
@struct
class data_t:
    comm: str(16)  # type: ignore [valid-type]
    copp: str(16)  # type: ignore [valid-type]


@bpf
@section("tracepoint/syscalls/sys_enter_clone")
def hello(ctx: c_void_p) -> c_int64:
    dataobj = data_t()
    comm(dataobj.comm)
    strobj = dataobj.comm
    dataobj.copp = strobj
    print(f"clone called by comm {dataobj.copp}")
    return 0


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()

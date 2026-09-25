"""Run a BPF function's IR on the host, to check what it computes.

Only for helper-free programs: the IR is retargeted to the host and JIT
compiled, and the function is called with a NULL ctx. A helper call is an
inttoptr to a BPF helper id, which on the host would jump to a bogus address.

Run as a script (`python -m tests.framework.host_jit file.ll func`), so the
caller can put a timeout on a program that never terminates.
"""

import ctypes
import re
import subprocess
import sys
from pathlib import Path

import llvmlite.binding as llvm


def run_function(ll_text: str, func_name: str) -> int:
    ll_text = re.sub(r'^target (triple|datalayout) = ".*"$', "", ll_text, flags=re.M)
    llvm.initialize_native_target()
    llvm.initialize_native_asmprinter()
    mod = llvm.parse_assembly(ll_text)
    mod.verify()
    tm = llvm.Target.from_default_triple().create_target_machine()
    engine = llvm.create_mcjit_compiler(mod, tm)
    engine.finalize_object()

    ret = re.search(rf'define [^\n]*?\bi(\d+) @"?{re.escape(func_name)}"?\(', ll_text)
    ret_ty = {64: ctypes.c_int64, 32: ctypes.c_int32}[int(ret.group(1))]
    func = ctypes.CFUNCTYPE(ret_ty, ctypes.c_void_p)(
        engine.get_function_address(func_name)
    )
    return func(None)


def run_in_subprocess(ll_path, func_name: str, timeout: float) -> int:
    """Return value of func_name(NULL). Raises subprocess.TimeoutExpired if it
    does not return within timeout, CalledProcessError if it fails to run."""
    out = subprocess.run(
        [sys.executable, "-m", "tests.framework.host_jit", str(ll_path), func_name],
        cwd=Path(__file__).parents[2],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=True,
    )
    return int(out.stdout.strip())


if __name__ == "__main__":
    with open(sys.argv[1]) as f:
        print(run_function(f.read(), sys.argv[2]))

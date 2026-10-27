"""
Compile a generated Program both ways, run both on the host, and compare.

PythonBPF's IR is JIT compiled on the host (tests/framework/host_jit.py); the
C reference is compiled by clang, with -fwrapv, to a native object file that
the same JIT loads and links. Native code rather than `-target bpf` IR: the
IR a newer clang emits need not parse with llvmlite's LLVM, while an ELF
object always loads, and a fixed-width integer computation means the same on
BPF and on an LP64 host. (An object, not a shared library: linking was 60 of
the 90 ms an example took.)

Both run in a worker process. The model only rules out undefined behaviour
for the *correct* types, so a miscompile can still trap (SIGFPE on a signed
division PythonBPF should not have emitted) or abort inside LLVM; in the
pytest process that would end the whole run.
"""

import atexit
import ctypes
import itertools
import logging
import multiprocessing
import shutil
import subprocess
import tempfile
from concurrent.futures import ProcessPoolExecutor
from concurrent.futures.process import BrokenProcessPool
from pathlib import Path

import llvmlite.binding as llvm
from hypothesis import assume, note
from hypothesis.control import currently_in_test_context

from pythonbpf.codegen import compile_to_ir
from tests.framework.host_jit import run_function
from tests.property.cints import IntType, UndefinedBehaviour
from tests.property.programs import Program

CLANG = shutil.which("clang")
WORKDIR = Path(tempfile.mkdtemp(prefix="pythonbpf-pbt-"))
atexit.register(shutil.rmtree, WORKDIR, ignore_errors=True)
_names = itertools.count()


class PythonBPFCompileError(Exception):
    pass


class WorkerCrashed(Exception):
    pass


# ── worker side ─────────────────────────────────────────────────────────────


def _run_ir(ll_text: str, restype_name: str) -> int:
    return run_function(ll_text, "prog", getattr(ctypes, restype_name))


def _run_object(path: str, restype_name: str) -> int:
    llvm.initialize_native_target()
    llvm.initialize_native_asmprinter()
    tm = llvm.Target.from_default_triple().create_target_machine()
    engine = llvm.create_mcjit_compiler(llvm.parse_assembly(""), tm)
    engine.add_object_file(path)
    engine.finalize_object()
    func = ctypes.CFUNCTYPE(getattr(ctypes, restype_name), ctypes.c_void_p)(
        engine.get_function_address("prog")
    )
    return int(func(None))


_pool = None


def _in_worker(fn, *args):
    global _pool
    if _pool is None:
        _pool = ProcessPoolExecutor(
            max_workers=1, mp_context=multiprocessing.get_context("forkserver")
        )
    try:
        return _pool.submit(fn, *args).result(timeout=60)
    except BrokenProcessPool:
        _pool = None
        raise WorkerCrashed from None


@atexit.register
def _shutdown():
    if _pool is not None:
        _pool.shutdown(cancel_futures=True)


# ── compile ─────────────────────────────────────────────────────────────────


class _Errors(logging.Handler):
    """compile_to_ir can log an ERROR and carry on; that is a failure too."""

    def __init__(self):
        super().__init__(logging.ERROR)
        self.messages = []

    def emit(self, record):
        self.messages.append(record.getMessage())


def compile_pythonbpf(source: str) -> str:
    stem = WORKDIR / f"p{next(_names)}"
    py, ll = stem.with_suffix(".py"), stem.with_suffix(".ll")
    py.write_text(source)
    errors = _Errors()
    logger = logging.getLogger("pythonbpf")
    logger.addHandler(errors)
    try:
        compile_to_ir(str(py), str(ll), loglevel=logging.WARNING)
    except Exception as e:
        raise PythonBPFCompileError(f"{type(e).__name__}: {e}") from e
    finally:
        logger.removeHandler(errors)
    if errors.messages:
        raise PythonBPFCompileError("; ".join(errors.messages))
    return ll.read_text()


def compile_c(source: str) -> Path:
    stem = WORKDIR / f"c{next(_names)}"
    c, obj = stem.with_suffix(".c"), stem.with_suffix(".o")
    c.write_text(source)
    subprocess.run(
        [CLANG, "-O0", "-fwrapv", "-w", "-c", "-fPIC", str(c), "-o", str(obj)],
        check=True,
        capture_output=True,
        text=True,
    )
    return obj


# ── the property ────────────────────────────────────────────────────────────


def check_against_clang(program: Program, expected) -> None:
    """Assert PythonBPF computes what clang computes for `program`.

    `expected` is a zero-argument callable returning the model's value; if it
    raises UndefinedBehaviour the example is discarded before anything runs.
    """
    in_hypothesis = currently_in_test_context()
    try:
        model = expected()
    except UndefinedBehaviour:
        if not in_hypothesis:
            raise
        assume(False)
    py_source, c_source = program.py_source(), program.c_source()
    # Shown with every failure: by note() under Hypothesis (which prints the
    # shrunk example's notes), and in the message for a plain test.
    shown = (
        f"\n\nPythonBPF source:\n{py_source}\nC reference:\n{c_source}\nmodel: {model}"
    )
    if in_hypothesis:
        note(shown)
        shown = ""
    ret: IntType = program.ret

    reference = _in_worker(_run_object, str(compile_c(c_source)), ret.name)
    assert reference == model, (
        f"the model in tests/property/cints.py says {model}, clang says "
        f"{reference}: the model is wrong, not PythonBPF{shown}"
    )

    try:
        ll_text = compile_pythonbpf(py_source)
    except PythonBPFCompileError as e:
        raise AssertionError(
            f"PythonBPF failed to compile the program: {e}{shown}"
        ) from None
    try:
        got = _in_worker(_run_ir, ll_text, ret.name)
    except WorkerCrashed:
        raise AssertionError(
            "PythonBPF's code crashed the host JIT (a trap or an LLVM abort); "
            f"clang returns {reference}{shown}"
        ) from None
    assert got == reference, (
        f"PythonBPF returns {got}, clang returns {reference}{shown}"
    )

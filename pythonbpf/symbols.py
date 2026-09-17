"""Symbols: what a name in a BPF program resolves to.

Every symbol table in the compiler maps a name to one of these. The base class
carries what all of them share -- the storage behind the name and its IR type;
subclasses add what each kind of name needs on top.
"""

from dataclasses import dataclass
from typing import Any

import llvmlite.ir as ir


@dataclass
class Symbol:
    """The storage a name resolves to, and the type of what is stored there.

    `var` is a pointer to that storage: an alloca for a local, a GlobalVariable
    for a BPF global or a map, or None for the context parameter (which arrives
    as func.args[0] rather than living in a slot).
    """

    var: ir.Value | None
    ir_type: ir.Type | None


@dataclass
class LocalSymbol(Symbol):
    """One name visible in a BPF function's scope.

    `declared_global` marks a name bound by a `global` statement: its var is
    the @bpfglobal's GlobalVariable rather than an alloca.

    `shadows_global_from` is set when this local's name is also the name of a
    @bpfglobal and the function did not declare it `global`: Python makes such
    a name a local for the whole body, shadowing the global, and the value is
    the line where its first binding ends.
    """

    metadata: Any = None
    declared_global: bool = False
    shadows_global_from: int | None = None

    def check_bound_at(self, name: str, lineno: int) -> None:
        """Raise if `name` is read at `lineno` before its first binding.

        Python's scoping is function-wide and static: assigning a name anywhere
        in a body makes it local everywhere in that body, so a read above the
        assignment is an UnboundLocalError rather than a read of the global.
        There is no runtime in which to raise that, so a program in this shape
        is rejected at compile time. The check applies only to locals that
        shadow a @bpfglobal, where staying silent would otherwise load an
        uninitialised slot from a name the author expected to be the global.
        """
        if self.shadows_global_from is None or lineno > self.shadows_global_from:
            return
        raise SyntaxError(
            f"local variable '{name}' referenced before assignment: the "
            f"assignment on line {self.shadows_global_from} makes '{name}' a "
            f"local that shadows the @bpfglobal of the same name (Python "
            f"raises UnboundLocalError here). Add 'global {name}' if you meant "
            f"the global."
        )

    def __iter__(self):
        # Three fields on purpose: several call sites tuple-unpack a symbol.
        yield self.var
        yield self.ir_type
        yield self.metadata


@dataclass
class BpfGlobalSymbol(Symbol):
    """A mutable BPF global variable declared with @bpfglobal.

    Lands in .bss (zero initializer) or .data (non-zero); libbpf exposes the
    section to userspace as a global-data map.
    """

    ctype_name: str = ""

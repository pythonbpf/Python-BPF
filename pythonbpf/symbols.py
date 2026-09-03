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
    """

    metadata: Any = None
    declared_global: bool = False

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

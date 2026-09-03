import llvmlite.ir as ir
from dataclasses import dataclass
from typing import Any


@dataclass
class LocalSymbol:
    """One name visible in a BPF function's scope.

    `var` is the storage the name resolves to: an alloca for locals, the
    GlobalVariable for a name brought in by a `global` statement, or None for
    the context parameter (which arrives as func.args[0], not a slot).
    """

    var: ir.AllocaInstr | ir.GlobalVariable | None
    ir_type: ir.Type
    metadata: Any = None
    declared_global: bool = False

    def __iter__(self):
        # Three fields on purpose: several call sites tuple-unpack a symbol.
        yield self.var
        yield self.ir_type
        yield self.metadata

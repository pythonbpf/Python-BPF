from llvmlite import ir
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pythonbpf.structs.struct_type import StructType
    from pythonbpf.maps.maps_utils import MapSymbol

logger = logging.getLogger(__name__)


class ScratchPoolManager:
    """Manage the temporary helper variables in local_sym_tab"""

    def __init__(self):
        self._counters = {}

    @property
    def counter(self):
        return sum(self._counters.values())

    def reset(self):
        self._counters.clear()
        logger.debug("Scratch pool counter reset to 0")

    def _get_type_name(self, ir_type):
        if isinstance(ir_type, ir.PointerType):
            return "ptr"
        elif isinstance(ir_type, ir.IntType):
            return f"i{ir_type.width}"
        elif isinstance(ir_type, ir.ArrayType):
            return f"[{ir_type.count}x{self._get_type_name(ir_type.element)}]"
        else:
            return str(ir_type).replace(" ", "")

    def get_next_temp(self, local_sym_tab, expected_type=None):
        # Default to i64 if no expected type provided
        type_name = self._get_type_name(expected_type) if expected_type else "i64"
        if type_name not in self._counters:
            self._counters[type_name] = 0

        counter = self._counters[type_name]
        temp_name = f"__helper_temp_{type_name}_{counter}"
        self._counters[type_name] += 1

        if temp_name not in local_sym_tab:
            raise ValueError(
                f"Scratch pool exhausted or inadequate: {temp_name}. "
                f"Type: {type_name} Counter: {counter}"
            )

        logger.debug(f"Using {temp_name} for type {type_name}")
        return local_sym_tab[temp_name].var, temp_name


class CompilationContext:
    """
    Holds the state for a single compilation run.
    This replaces global mutable state modules.
    """

    def __init__(self, module: ir.Module):
        self.module = module

        # Symbol tables
        self.global_sym_tab: list[ir.GlobalVariable] = []
        self.structs_sym_tab: dict[str, "StructType"] = {}
        self.map_sym_tab: dict[str, "MapSymbol"] = {}

        # Helper management
        self.scratch_pool = ScratchPoolManager()

        # Vmlinux handling (optional, specialized)
        self.vmlinux_handler = None  # Can be VmlinuxHandler instance

        # Current function context (optional, if needed globally during function processing)
        self.current_func = None

    def reset(self):
        """Reset state between functions if necessary, though new context per compile is preferred."""
        self.scratch_pool.reset()
        self.current_func = None

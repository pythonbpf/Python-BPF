import ast
import logging

from llvmlite import ir
from dataclasses import dataclass
from typing import Any
from pythonbpf.helper import HelperHandlerRegistry
from .expr import VmlinuxHandlerRegistry
from pythonbpf.type_deducer import ctypes_to_ir

logger = logging.getLogger(__name__)


@dataclass
class LocalSymbol:
    var: ir.AllocaInstr
    ir_type: ir.Type
    metadata: Any = None

    def __iter__(self):
        yield self.var
        yield self.ir_type
        yield self.metadata


def create_targets_and_rvals(stmt):
    """Create lists of targets and right-hand values from an assignment statement."""
    if isinstance(stmt.targets[0], ast.Tuple):
        if not isinstance(stmt.value, ast.Tuple):
            logger.warning("Mismatched multi-target assignment, skipping allocation")
            return [], []
        targets, rvals = stmt.targets[0].elts, stmt.value.elts
        if len(targets) != len(rvals):
            logger.warning("length of LHS != length of RHS, skipping allocation")
            return [], []
        return targets, rvals
    return stmt.targets, [stmt.value]


def handle_assign_allocation(builder, stmt, local_sym_tab, structs_sym_tab):
    """Handle memory allocation for assignment statements."""

    logger.info(f"Handling assignment for allocation: {ast.dump(stmt)}")

    # NOTE: Support multi-target assignments (e.g.: a, b = 1, 2)
    targets, rvals = create_targets_and_rvals(stmt)

    for target, rval in zip(targets, rvals):
        # Skip non-name targets (e.g., struct field assignments)
        if isinstance(target, ast.Attribute):
            logger.debug(
                f"Struct field assignment to {target.attr}, no allocation needed"
            )
            continue

        if not isinstance(target, ast.Name):
            logger.warning(
                f"Unsupported assignment target type: {type(target).__name__}"
            )
            continue

        var_name = target.id

        # Skip if already allocated
        if var_name in local_sym_tab:
            logger.debug(f"Variable {var_name} already allocated, skipping")
            continue

        # When allocating a variable, check if it's a vmlinux struct type
        if isinstance(
            stmt.value, ast.Name
        ) and VmlinuxHandlerRegistry.is_vmlinux_struct(stmt.value.id):
            # Handle vmlinux struct allocation
            # This requires more implementation
            print(stmt.value)
            pass

        # Determine type and allocate based on rval
        if isinstance(rval, ast.Call):
            _allocate_for_call(builder, var_name, rval, local_sym_tab, structs_sym_tab)
        elif isinstance(rval, ast.Constant):
            _allocate_for_constant(builder, var_name, rval, local_sym_tab)
        elif isinstance(rval, ast.BinOp):
            _allocate_for_binop(builder, var_name, local_sym_tab)
        elif isinstance(rval, ast.Name):
            # Variable-to-variable assignment (b = a)
            _allocate_for_name(builder, var_name, rval, local_sym_tab)
        elif isinstance(rval, ast.Attribute):
            # Struct field-to-variable assignment (a = dat.fld)
            _allocate_for_attribute(
                builder, var_name, rval, local_sym_tab, structs_sym_tab
            )
        else:
            logger.warning(
                f"Unsupported assignment value type for {var_name}: {type(rval).__name__}"
            )


def _allocate_for_call(builder, var_name, rval, local_sym_tab, structs_sym_tab):
    """Allocate memory for variable assigned from a call."""

    if isinstance(rval.func, ast.Name):
        call_type = rval.func.id

        # C type constructors
        if call_type in ("c_int32", "c_int64", "c_uint32", "c_uint64"):
            ir_type = ctypes_to_ir(call_type)
            var = builder.alloca(ir_type, name=var_name)
            var.align = ir_type.width // 8
            local_sym_tab[var_name] = LocalSymbol(var, ir_type)
            logger.info(f"Pre-allocated {var_name} as {call_type}")

        # Helper functions
        elif HelperHandlerRegistry.has_handler(call_type):
            ir_type = ir.IntType(64)  # Assume i64 return type
            var = builder.alloca(ir_type, name=var_name)
            var.align = 8
            local_sym_tab[var_name] = LocalSymbol(var, ir_type)
            logger.info(f"Pre-allocated {var_name} for helper {call_type}")

        # Deref function
        elif call_type == "deref":
            ir_type = ir.IntType(64)  # Assume i64 return type
            var = builder.alloca(ir_type, name=var_name)
            var.align = 8
            local_sym_tab[var_name] = LocalSymbol(var, ir_type)
            logger.info(f"Pre-allocated {var_name} for deref")

        # Struct constructors
        elif call_type in structs_sym_tab:
            struct_info = structs_sym_tab[call_type]
            var = builder.alloca(struct_info.ir_type, name=var_name)
            local_sym_tab[var_name] = LocalSymbol(var, struct_info.ir_type, call_type)
            logger.info(f"Pre-allocated {var_name} for struct {call_type}")

        else:
            logger.warning(f"Unknown call type for allocation: {call_type}")

    elif isinstance(rval.func, ast.Attribute):
        # Map method calls - need double allocation for ptr handling
        _allocate_for_map_method(builder, var_name, local_sym_tab)

    else:
        logger.warning(f"Unsupported call function type for {var_name}")


def _allocate_for_map_method(builder, var_name, local_sym_tab):
    """Allocate memory for variable assigned from map method (double alloc)."""

    # Main variable (pointer to pointer)
    ir_type = ir.PointerType(ir.IntType(64))
    var = builder.alloca(ir_type, name=var_name)
    local_sym_tab[var_name] = LocalSymbol(var, ir_type)

    # Temporary variable for computed values
    tmp_ir_type = ir.IntType(64)
    var_tmp = builder.alloca(tmp_ir_type, name=f"{var_name}_tmp")
    local_sym_tab[f"{var_name}_tmp"] = LocalSymbol(var_tmp, tmp_ir_type)

    logger.info(f"Pre-allocated {var_name} and {var_name}_tmp for map method")


def _allocate_for_constant(builder, var_name, rval, local_sym_tab):
    """Allocate memory for variable assigned from a constant."""

    if isinstance(rval.value, bool):
        ir_type = ir.IntType(1)
        var = builder.alloca(ir_type, name=var_name)
        var.align = 1
        local_sym_tab[var_name] = LocalSymbol(var, ir_type)
        logger.info(f"Pre-allocated {var_name} as bool")

    elif isinstance(rval.value, int):
        ir_type = ir.IntType(64)
        var = builder.alloca(ir_type, name=var_name)
        var.align = 8
        local_sym_tab[var_name] = LocalSymbol(var, ir_type)
        logger.info(f"Pre-allocated {var_name} as i64")

    elif isinstance(rval.value, str):
        ir_type = ir.PointerType(ir.IntType(8))
        var = builder.alloca(ir_type, name=var_name)
        var.align = 8
        local_sym_tab[var_name] = LocalSymbol(var, ir_type)
        logger.info(f"Pre-allocated {var_name} as string")

    else:
        logger.warning(
            f"Unsupported constant type for {var_name}: {type(rval.value).__name__}"
        )


def _allocate_for_binop(builder, var_name, local_sym_tab):
    """Allocate memory for variable assigned from a binary operation."""
    ir_type = ir.IntType(64)  # Assume i64 result
    var = builder.alloca(ir_type, name=var_name)
    var.align = 8
    local_sym_tab[var_name] = LocalSymbol(var, ir_type)
    logger.info(f"Pre-allocated {var_name} for binop result")


def allocate_temp_pool(builder, max_temps, local_sym_tab):
    """Allocate the temporary scratch space pool for helper arguments."""
    if max_temps == 0:
        return

    logger.info(f"Allocating temp pool of {max_temps} variables")
    for i in range(max_temps):
        temp_name = f"__helper_temp_{i}"
        temp_var = builder.alloca(ir.IntType(64), name=temp_name)
        temp_var.align = 8
        local_sym_tab[temp_name] = LocalSymbol(temp_var, ir.IntType(64))


def _allocate_for_name(builder, var_name, rval, local_sym_tab):
    """Allocate memory for variable-to-variable assignment (b = a)."""
    source_var = rval.id

    if source_var not in local_sym_tab:
        logger.error(f"Source variable '{source_var}' not found in symbol table")
        return

    # Get type and metadata from source variable
    source_symbol = local_sym_tab[source_var]

    # Allocate with same type and alignment
    var = _allocate_with_type(builder, var_name, source_symbol.ir_type)
    local_sym_tab[var_name] = LocalSymbol(
        var, source_symbol.ir_type, source_symbol.metadata
    )

    logger.info(
        f"Pre-allocated {var_name} from {source_var} with type {source_symbol.ir_type}"
    )


def _allocate_for_attribute(builder, var_name, rval, local_sym_tab, structs_sym_tab):
    """Allocate memory for struct field-to-variable assignment (a = dat.fld)."""
    if not isinstance(rval.value, ast.Name):
        logger.warning(f"Complex attribute access not supported for {var_name}")
        return

    struct_var = rval.value.id
    field_name = rval.attr

    # Validate struct and field
    if struct_var not in local_sym_tab:
        logger.error(f"Struct variable '{struct_var}' not found")
        return

    struct_type = local_sym_tab[struct_var].metadata
    if not struct_type or struct_type not in structs_sym_tab:
        logger.error(f"Struct type '{struct_type}' not found")
        return

    struct_info = structs_sym_tab[struct_type]
    if field_name not in struct_info.fields:
        logger.error(f"Field '{field_name}' not found in struct '{struct_type}'")
        return

    # Get field type
    field_type = struct_info.field_type(field_name)

    # Special case: char array -> allocate as i8* pointer instead
    if (
        isinstance(field_type, ir.ArrayType)
        and isinstance(field_type.element, ir.IntType)
        and field_type.element.width == 8
    ):
        alloc_type = ir.PointerType(ir.IntType(8))
        logger.info(f"Allocating {var_name} as i8* (pointer to char array)")
    else:
        alloc_type = field_type

    var = _allocate_with_type(builder, var_name, alloc_type)
    local_sym_tab[var_name] = LocalSymbol(var, alloc_type)

    logger.info(
        f"Pre-allocated {var_name} from {struct_var}.{field_name} with type {alloc_type}"
    )


def _allocate_with_type(builder, var_name, ir_type):
    """Allocate variable with appropriate alignment for type."""
    var = builder.alloca(ir_type, name=var_name)
    var.align = _get_alignment(ir_type)
    return var


def _get_alignment(ir_type):
    """Get appropriate alignment for IR type."""
    if isinstance(ir_type, ir.IntType):
        return ir_type.width // 8
    elif isinstance(ir_type, ir.ArrayType) and isinstance(ir_type.element, ir.IntType):
        return ir_type.element.width // 8
    else:
        return 8  # Default: pointer size

import ast
import logging
import ctypes
from llvmlite import ir
from .symbols import LocalSymbol
from pythonbpf.helper import HelperHandlerRegistry
from pythonbpf.vmlinux_parser.dependency_node import Field
from .expr import VmlinuxHandlerRegistry
from pythonbpf.type_deducer import ctypes_to_ir, is_ctypes, IntTy, signedness, byte_size
from pythonbpf.expr.type_inference import infer_int_type
from pythonbpf.expr.operators import usual_arithmetic_conversions
from pythonbpf.maps import BPFMapType

logger = logging.getLogger(__name__)


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


def handle_assign_allocation(compilation_context, builder, stmt, local_sym_tab):
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

        _bind_name(
            compilation_context,
            stmt,
            target,
            local_sym_tab,
            lambda var_name: _allocate_for_value(
                builder, var_name, rval, local_sym_tab, compilation_context
            ),
        )


def handle_ann_assign_allocation(compilation_context, builder, stmt, local_sym_tab):
    """Handle memory allocation for annotated assignment (`x: c_int32 = 0`).

    The annotation, not the value, types the slot: `x: c_int32 = 0` is an i32
    even though the literal alone would give an i64. With no value
    (`x: c_int64`) the slot is still made, and the name stays unbound until
    something assigns it, as in Python.
    """
    logger.info(f"Handling annotated assignment for allocation: {ast.dump(stmt)}")

    if not isinstance(stmt.target, ast.Name):
        raise SyntaxError(
            f"annotated assignment on line {stmt.lineno} must target a plain "
            f"name, got {type(stmt.target).__name__}"
        )

    ir_type = annotation_to_ir(stmt.annotation, stmt.lineno)
    _bind_name(
        compilation_context,
        stmt,
        stmt.target,
        local_sym_tab,
        lambda var_name: local_sym_tab.__setitem__(
            var_name,
            LocalSymbol(_allocate_with_type(builder, var_name, ir_type), ir_type),
        ),
    )


def handle_for_allocation(compilation_context, builder, stmt, local_sym_tab):
    """Handle memory allocation for `for <name> in range(...)`.

    Two slots, both in the entry block so a loop never grows the stack: the
    loop variable, and a hidden induction counter the loop actually steps.
    Keeping them apart is what makes rebinding the loop variable in the body
    leave the trip count alone, as in Python -- and a counter the body cannot
    touch is what keeps the loop visibly bounded for the verifier.
    """
    start, stop, step = parse_range(stmt)

    # range() yields Python ints; like any undeclared local they are 64-bit,
    # signed unless the bounds make C's arithmetic unsigned.
    bound_types = [
        infer_int_type(bound, local_sym_tab, compilation_context)
        for bound in (start, stop)
        if bound is not None
    ]
    signed = True
    if all(ty is not None for ty in bound_types):
        common = bound_types[0]
        for ty in bound_types[1:]:
            common = usual_arithmetic_conversions(common, ty)
        signed = signedness(common)
    if not signed and step < 0:
        raise SyntaxError(
            f"range() on line {stmt.lineno} counts down over unsigned bounds; "
            f"the counter would wrap instead of stopping"
        )
    loop_ty = IntTy(64, signed)

    counter = range_counter_name(stmt)
    local_sym_tab[counter] = LocalSymbol(
        _allocate_with_type(builder, counter, loop_ty), loop_ty
    )
    _bind_name(
        compilation_context,
        stmt,
        stmt.target,
        local_sym_tab,
        lambda var_name: local_sym_tab.__setitem__(
            var_name,
            LocalSymbol(_allocate_with_type(builder, var_name, loop_ty), loop_ty),
        ),
    )


def range_counter_name(stmt):
    """Symbol-table name of a range loop's hidden induction counter, unique per
    loop so nested loops each get their own."""
    return f"__range_idx_{stmt.lineno}_{stmt.col_offset}"


def parse_range(stmt):
    """Split `for <name> in range(...)` into (start, stop, step): start is an
    expression or None (meaning 0), stop an expression, step a nonzero int.

    step has to be known at compile time, because its sign decides whether the
    loop runs while the counter is below stop or above it.
    """
    it = stmt.iter
    if not (
        isinstance(it, ast.Call)
        and isinstance(it.func, ast.Name)
        and it.func.id == "range"
    ):
        raise NotImplementedError(
            f"for loop on line {stmt.lineno}: only range(...) can be iterated "
            f"so far, got {ast.unparse(it)}"
        )
    if not isinstance(stmt.target, ast.Name):
        raise NotImplementedError(
            f"for loop on line {stmt.lineno}: only a plain name can be the loop "
            f"variable, got {ast.unparse(stmt.target)}"
        )
    if it.keywords or not 1 <= len(it.args) <= 3:
        raise SyntaxError(
            f"range() on line {stmt.lineno} takes 1 to 3 positional arguments"
        )

    if len(it.args) == 1:
        return None, it.args[0], 1
    start, stop = it.args[0], it.args[1]
    if len(it.args) == 2:
        return start, stop, 1

    step_node = it.args[2]
    negate = isinstance(step_node, ast.UnaryOp) and isinstance(step_node.op, ast.USub)
    literal = step_node.operand if negate else step_node
    if not (
        isinstance(literal, ast.Constant)
        and isinstance(literal.value, int)
        and not isinstance(literal.value, bool)
    ):
        raise SyntaxError(
            f"range() step on line {stmt.lineno} must be an integer literal, "
            f"got {ast.unparse(step_node)}"
        )
    step = -literal.value if negate else literal.value
    if step == 0:
        raise ValueError(f"range() arg 3 must not be zero (line {stmt.lineno})")
    return start, stop, step


def annotation_to_ir(annotation, lineno):
    """IR type for a ctypes annotation, written `c_int32` or `ctypes.c_int32`."""
    if isinstance(annotation, ast.Name):
        name = annotation.id
    elif isinstance(annotation, ast.Attribute):
        name = annotation.attr
    else:
        name = None
    if name is None or not is_ctypes(name):
        raise SyntaxError(
            f"unsupported annotation on line {lineno}: {ast.unparse(annotation)} "
            f"(annotate locals with a ctypes integer type such as c_int64)"
        )
    return ctypes_to_ir(name)


def _bind_name(compilation_context, stmt, target, local_sym_tab, allocate):
    """What every statement that binds a bare name shares, around the
    statement-specific `allocate(var_name)` that makes the slot.

    A name already bound needs no new slot. A name that is also a @bpfglobal
    but was not declared `global` becomes a local shadowing it, and records
    where its binding ends so a read above it is reported as Python would.
    """
    var_name = target.id

    # Already bound in this scope: a parameter, an earlier assignment, or a
    # `global` declaration (whose slot is the GlobalVariable). No slot needed.
    if var_name in local_sym_tab:
        logger.debug(f"'{var_name}' already bound, no allocation needed")
        return

    # Not declared `global`, yet named like one: Python creates a local
    # that shadows the global for the whole function body, and leaves the
    # global untouched. Do the same.
    shadows_global = var_name in compilation_context.bpf_globals
    if shadows_global:
        logger.info(
            f"'{var_name}' is assigned without a 'global' declaration, so it "
            f"is a local shadowing the @bpfglobal of the same name"
        )

    allocate(var_name)

    if shadows_global and var_name in local_sym_tab:
        # Where the binding ends, so that a read above it is reported the
        # way Python reports it. end_lineno, not lineno, so a read on a
        # continuation line of a multi-line binding counts as above it too.
        local_sym_tab[var_name].shadows_global_from = (
            getattr(stmt, "end_lineno", None) or target.lineno
        )


def _allocate_for_value(builder, var_name, rval, local_sym_tab, compilation_context):
    """Allocate a slot for `var_name = rval`, typed from the value."""
    if isinstance(rval, ast.Call):
        _allocate_for_call(builder, var_name, rval, local_sym_tab, compilation_context)
    elif isinstance(rval, ast.Constant):
        _allocate_for_constant(builder, var_name, rval, local_sym_tab)
    elif isinstance(rval, ast.BinOp):
        _allocate_for_binop(builder, var_name, rval, local_sym_tab, compilation_context)
    elif isinstance(rval, ast.Name):
        # Variable-to-variable assignment (b = a)
        _allocate_for_name(builder, var_name, rval, local_sym_tab, compilation_context)
    elif isinstance(rval, ast.Attribute):
        # Struct field-to-variable assignment (a = dat.fld)
        _allocate_for_attribute(
            builder, var_name, rval, local_sym_tab, compilation_context
        )
    else:
        logger.warning(
            f"Unsupported assignment value type for {var_name}: {type(rval).__name__}"
        )


def _allocate_for_call(builder, var_name, rval, local_sym_tab, compilation_context):
    """Allocate memory for variable assigned from a call."""
    structs_sym_tab = compilation_context.structs_sym_tab

    if isinstance(rval.func, ast.Name):
        call_type = rval.func.id

        # C type constructors
        if is_ctypes(call_type) and isinstance(ctypes_to_ir(call_type), ir.IntType):
            # Any integer ctypes constructor, c_uint16 included, declares a
            # slot of that width; the value is converted into it at the store.
            ir_type = ctypes_to_ir(call_type)
            var = builder.alloca(ir_type, name=var_name)
            var.align = byte_size(ir_type)
            local_sym_tab[var_name] = LocalSymbol(var, ir_type)
            logger.info(f"Pre-allocated {var_name} as {call_type}")

        # Helper functions
        elif HelperHandlerRegistry.has_handler(call_type):
            # Undeclared locals are 64-bit; the sign comes from the helper.
            ret = HelperHandlerRegistry.get_return_type(call_type)
            ir_type = IntTy(
                64, signedness(ret) if isinstance(ret, ir.IntType) else True
            )
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
            if len(rval.args) == 0:
                # Zero-arg constructor: allocate the struct itself
                var = builder.alloca(struct_info.ir_type, name=var_name)
                local_sym_tab[var_name] = LocalSymbol(
                    var, struct_info.ir_type, call_type
                )
                logger.info(f"Pre-allocated {var_name} for struct {call_type}")
            else:
                # Pointer cast: allocate as pointer to struct
                ptr_type = ir.PointerType(struct_info.ir_type)
                var = builder.alloca(ptr_type, name=var_name)
                var.align = 8
                local_sym_tab[var_name] = LocalSymbol(var, ptr_type, call_type)
                logger.info(
                    f"Pre-allocated {var_name} for struct pointer cast to {call_type}"
                )

        elif VmlinuxHandlerRegistry.is_vmlinux_struct(call_type):
            # When calling struct_name(pointer), we're doing a cast, not construction
            # So we allocate as a pointer (i64) not as the actual struct
            var = builder.alloca(ir.IntType(64), name=var_name)
            var.align = 8
            local_sym_tab[var_name] = LocalSymbol(
                var, ir.IntType(64), VmlinuxHandlerRegistry.get_struct_type(call_type)
            )
            logger.info(
                f"Pre-allocated {var_name} for vmlinux struct pointer cast to {call_type}"
            )

        else:
            logger.warning(f"Unknown call type for allocation: {call_type}")

    elif isinstance(rval.func, ast.Attribute):
        # Map method calls - need double allocation for ptr handling
        _allocate_for_map_method(
            builder, var_name, rval, local_sym_tab, compilation_context
        )

    else:
        logger.warning(f"Unsupported call function type for {var_name}")


def _allocate_for_map_method(
    builder, var_name, rval, local_sym_tab, compilation_context
):
    """Allocate memory for variable assigned from map method (double alloc)."""
    map_sym_tab = compilation_context.map_sym_tab
    structs_sym_tab = compilation_context.structs_sym_tab

    map_name = rval.func.value.id
    method_name = rval.func.attr

    # NOTE: We will have to special case HashMap.lookup which returns a pointer to value type
    # The value type can be a struct as well, so we need to handle that properly
    # This special casing is not ideal, as over time other map methods may need similar handling
    # But for now, we will just handle lookup specifically
    if map_name not in map_sym_tab:
        logger.error(f"Map '{map_name}' not found for allocation")
        return

    if method_name != "lookup":
        # Fallback allocation for other map methods
        _allocate_for_map_method_fallback(builder, var_name, local_sym_tab)
        return

    map_params = map_sym_tab[map_name].params
    if map_params["type"] not in (BPFMapType.HASH, BPFMapType.ARRAY):
        logger.warning(
            "Map method lookup used on non-hash map, using fallback allocation"
        )
        _allocate_for_map_method_fallback(builder, var_name, local_sym_tab)
        return

    value_type = map_params["value"]
    # Determine IR type for value
    if isinstance(value_type, str) and value_type in structs_sym_tab:
        struct_info = structs_sym_tab[value_type]
        value_ir_type = struct_info.ir_type
    else:
        value_ir_type = ctypes_to_ir(value_type)

    if value_ir_type is None:
        logger.warning(
            f"Could not determine IR type for map value '{value_type}', using fallback allocation"
        )
        _allocate_for_map_method_fallback(builder, var_name, local_sym_tab)
        return

    # Main variable (pointer to pointer)
    ir_type = ir.PointerType(ir.IntType(64))
    var = builder.alloca(ir_type, name=var_name)
    local_sym_tab[var_name] = LocalSymbol(var, ir_type, value_type)
    # Temporary variable for computed values
    tmp_ir_type = value_ir_type
    var_tmp = builder.alloca(tmp_ir_type, name=f"{var_name}_tmp")
    local_sym_tab[f"{var_name}_tmp"] = LocalSymbol(var_tmp, tmp_ir_type)
    logger.info(
        f"Pre-allocated {var_name} and {var_name}_tmp for map method lookup of type {value_ir_type}"
    )


def _allocate_for_map_method_fallback(builder, var_name, local_sym_tab):
    """Fallback allocation for map method variable (i64* and i64**)."""

    # Main variable (pointer to pointer)
    ir_type = ir.PointerType(ir.IntType(64))
    var = builder.alloca(ir_type, name=var_name)
    local_sym_tab[var_name] = LocalSymbol(var, ir_type)

    # Temporary variable for computed values
    tmp_ir_type = ir.IntType(64)
    var_tmp = builder.alloca(tmp_ir_type, name=f"{var_name}_tmp")
    local_sym_tab[f"{var_name}_tmp"] = LocalSymbol(var_tmp, tmp_ir_type)

    logger.info(
        f"Pre-allocated {var_name} and {var_name}_tmp for map method (fallback)"
    )


def _allocate_for_constant(builder, var_name, rval, local_sym_tab):
    """Allocate memory for variable assigned from a constant."""

    if isinstance(rval.value, bool):
        ir_type = IntTy(1, False)  # a bool widens to 0 or 1, never sign-extends
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


def _allocate_for_binop(builder, var_name, rval, local_sym_tab, compilation_context):
    """Allocate memory for variable assigned from a binary operation.

    Undeclared locals are 64-bit; the sign is that of the expression's C type,
    inferred statically. Falls back to signed when the expression involves
    something the inference does not know.
    """
    inferred = infer_int_type(rval, local_sym_tab, compilation_context)
    if inferred is None:
        logger.debug(f"Could not infer a type for {var_name}, assuming signed i64")
    ir_type = IntTy(64, signedness(inferred) if inferred is not None else True)
    var = builder.alloca(ir_type, name=var_name)
    var.align = 8
    local_sym_tab[var_name] = LocalSymbol(var, ir_type)
    logger.info(f"Pre-allocated {var_name} for binop result")


def _get_type_name(ir_type):
    """Get a string representation of an IR type."""
    if isinstance(ir_type, ir.IntType):
        return f"i{ir_type.width}"
    elif isinstance(ir_type, ir.PointerType):
        return "ptr"
    elif isinstance(ir_type, ir.ArrayType):
        return f"[{ir_type.count}x{_get_type_name(ir_type.element)}]"
    else:
        return str(ir_type).replace(" ", "")


def allocate_temp_pool(builder, max_temps, local_sym_tab):
    """Allocate the temporary scratch space pool for helper arguments."""
    if not max_temps:
        logger.info("No temp pool allocation needed")
        return

    for tmp_type, cnt in max_temps.items():
        type_name = _get_type_name(tmp_type)
        logger.info(f"Allocating temp pool of {cnt} variables of type {type_name}")
        for i in range(cnt):
            temp_name = f"__helper_temp_{type_name}_{i}"
            temp_var = builder.alloca(tmp_type, name=temp_name)
            temp_var.align = _get_alignment(tmp_type)
            local_sym_tab[temp_name] = LocalSymbol(temp_var, tmp_type)
            logger.debug(f"Allocated temp variable: {temp_name}")


def _allocate_for_name(builder, var_name, rval, local_sym_tab, compilation_context):
    """Allocate memory for variable-to-variable assignment (b = a)."""
    source_var = rval.id

    # Same resolution order as every other read of a bare name: local, then
    # BPF global, then vmlinux enum constant. A variable source gives the copy
    # its type; an enum constant is an immediate with no storage, so the copy
    # gets the i64 slot a literal gets.
    if source_var in local_sym_tab:
        source_symbol = local_sym_tab[source_var]
    elif source_var in compilation_context.bpf_globals:
        source_symbol = compilation_context.bpf_globals[source_var]
    elif VmlinuxHandlerRegistry.handle_name(source_var) is not None:
        var = _allocate_with_type(builder, var_name, ir.IntType(64))
        local_sym_tab[var_name] = LocalSymbol(var, ir.IntType(64))
        logger.info(f"Pre-allocated {var_name} from enum constant {source_var}")
        return
    else:
        logger.error(f"Source variable '{source_var}' not found in symbol table")
        return

    # Allocate with same type and alignment
    var = _allocate_with_type(builder, var_name, source_symbol.ir_type)
    local_sym_tab[var_name] = LocalSymbol(
        var, source_symbol.ir_type, getattr(source_symbol, "metadata", None)
    )

    logger.info(
        f"Pre-allocated {var_name} from {source_var} with type {source_symbol.ir_type}"
    )


def _allocate_for_attribute(
    builder, var_name, rval, local_sym_tab, compilation_context
):
    """Allocate memory for struct field-to-variable assignment (a = dat.fld)."""
    structs_sym_tab = compilation_context.structs_sym_tab

    if not isinstance(rval.value, ast.Name):
        logger.warning(f"Complex attribute access not supported for {var_name}")
        return

    struct_var = rval.value.id
    field_name = rval.attr

    # Validate struct and field
    if struct_var not in local_sym_tab:
        logger.error(f"Struct variable '{struct_var}' not found")
        return

    struct_type: type = local_sym_tab[struct_var].metadata
    if not struct_type or struct_type not in structs_sym_tab:
        # `metadata` only names a struct for struct-typed symbols. For anything
        # else (None, an IR type, or a plain ctypes class such as a `c_void_p`
        # context parameter) there is no vmlinux struct name to look up, so guard
        # the attribute access instead of blowing up with an AttributeError.
        vmlinux_struct_name = getattr(struct_type, "__name__", None)
        if vmlinux_struct_name and VmlinuxHandlerRegistry.is_vmlinux_struct(
            vmlinux_struct_name
        ):
            # Handle vmlinux struct field access
            # Same discriminator handle_vmlinux_struct_field uses: a context
            # argument has no alloca of its own.
            is_context_field = local_sym_tab[struct_var].var is None
            if not VmlinuxHandlerRegistry.has_field(vmlinux_struct_name, field_name):
                logger.error(
                    f"Field '{field_name}' not found in vmlinux struct '{vmlinux_struct_name}'"
                )
                return

            field_type: tuple[ir.GlobalVariable, Field] = (
                VmlinuxHandlerRegistry.get_field_type(vmlinux_struct_name, field_name)
            )
            field_ir, field = field_type

            # Determine the actual IR type based on the field's type
            actual_ir_type = None

            # Check if it's a ctypes primitive
            if field.type.__module__ == ctypes.__name__:
                try:
                    field_size_bytes = ctypes.sizeof(field.type)
                    field_size_bits = field_size_bytes * 8

                    if field_size_bits in [8, 16, 32, 64]:
                        # Sub-register-width context fields allocate as i64,
                        # because load_ctx_field zero-extends them to i64.
                        # Non-context fields go through load_struct_field, which
                        # keeps them at their natural width.
                        if is_context_field and field_size_bits < 64:
                            actual_ir_type = ir.IntType(64)
                            logger.info(
                                f"Allocating {var_name} as i64 for i{field_size_bits} field from "
                                f"{vmlinux_struct_name}.{field_name} (will be zero-extended during load)"
                            )
                        else:
                            actual_ir_type = ir.IntType(field_size_bits)
                    else:
                        logger.warning(
                            f"Unusual field size {field_size_bits} bits for {field_name}"
                        )
                        actual_ir_type = ir.IntType(64)
                except Exception as e:
                    logger.warning(
                        f"Could not determine size for ctypes field {field_name}: {e}"
                    )
                    actual_ir_type = ir.IntType(64)
                    field_size_bits = 64

            # Check if it's a nested vmlinux struct or complex type
            elif field.type.__module__ == "vmlinux":
                # For pointers to structs, use pointer type (64-bit)
                if field.ctype_complex_type is not None and issubclass(
                    field.ctype_complex_type, ctypes._Pointer
                ):
                    actual_ir_type = ir.IntType(64)  # Pointer is always 64-bit
                    field_size_bits = 64
                # For embedded structs, this is more complex - might need different handling
                else:
                    logger.warning(
                        f"Field {field_name} is a nested vmlinux struct, using i64 for now"
                    )
                    actual_ir_type = ir.IntType(64)
                    field_size_bits = 64
            else:
                logger.warning(
                    f"Unknown field type module {field.type.__module__} for {field_name}"
                )
                actual_ir_type = ir.IntType(64)
                field_size_bits = 64

            # Pre-allocate the tmp storage used by load_struct_field (so we don't alloca inside handler)
            tmp_name = f"{struct_var}_{field_name}_tmp"
            tmp_ir_type = ir.IntType(field_size_bits)
            tmp_var = builder.alloca(tmp_ir_type, name=tmp_name)
            tmp_var.align = byte_size(tmp_ir_type)
            local_sym_tab[tmp_name] = LocalSymbol(tmp_var, tmp_ir_type)
            logger.info(
                f"Pre-allocated temp {tmp_name} (i{field_size_bits}) for vmlinux field read {vmlinux_struct_name}.{field_name}"
            )

            # Allocate with the actual IR type for the destination var
            var = _allocate_with_type(builder, var_name, actual_ir_type)
            local_sym_tab[var_name] = LocalSymbol(var, actual_ir_type, field)

            logger.info(
                f"Pre-allocated {var_name} as {actual_ir_type} from vmlinux struct {vmlinux_struct_name}.{field_name}"
            )
            return
        else:
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
        return byte_size(ir_type)
    elif isinstance(ir_type, ir.ArrayType) and isinstance(ir_type.element, ir.IntType):
        return byte_size(ir_type.element)
    else:
        return 8  # Default: pointer size

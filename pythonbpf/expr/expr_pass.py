import ast
from llvmlite import ir
from logging import Logger
import logging
from typing import Dict

from pythonbpf.type_deducer import ctypes_to_ir, is_ctypes
from .call_registry import CallHandlerRegistry
from .ir_ops import deref_to_depth, access_struct_field
from .operators import apply_binop, UNARY_OPS, BOOL_OPS
from .type_normalization import (
    convert_to_bool,
    handle_comparator,
    get_base_type_and_depth,
)
from .vmlinux_registry import VmlinuxHandlerRegistry
from ..vmlinux_parser.dependency_node import Field

logger: Logger = logging.getLogger(__name__)

# ============================================================================
# Leaf Handlers (No Recursive eval_expr calls)
# ============================================================================


def _handle_name_expr(
    expr: ast.Name, compilation_context, local_sym_tab: Dict, builder: ir.IRBuilder
):
    """Handle ast.Name expressions."""
    if expr.id in local_sym_tab:
        var = local_sym_tab[expr.id].var
        val = builder.load(var)
        return val, local_sym_tab[expr.id].ir_type
    elif expr.id in compilation_context.bpf_globals:
        # A @bpfglobal
        sym = compilation_context.bpf_globals[expr.id]
        val = builder.load(sym.var)
        return val, sym.ir_type
    else:
        # Check if it's a vmlinux enum/constant
        vmlinux_result = VmlinuxHandlerRegistry.handle_name(expr.id)
        if vmlinux_result is not None:
            return vmlinux_result

        raise SyntaxError(f"Undefined variable {expr.id}")


def _handle_constant_expr(compilation_context, builder, expr: ast.Constant):
    """Handle ast.Constant expressions."""
    if isinstance(expr.value, int) or isinstance(expr.value, bool):
        return ir.Constant(ir.IntType(64), int(expr.value)), ir.IntType(64)
    elif isinstance(expr.value, str):
        str_name = f".str.{id(expr)}"
        str_bytes = expr.value.encode("utf-8") + b"\x00"
        str_type = ir.ArrayType(ir.IntType(8), len(str_bytes))
        str_constant = ir.Constant(str_type, bytearray(str_bytes))

        # Create global variable
        global_str = ir.GlobalVariable(
            compilation_context.module, str_type, name=str_name
        )
        global_str.linkage = "internal"
        global_str.global_constant = True
        global_str.initializer = str_constant

        str_ptr = builder.bitcast(global_str, ir.PointerType(ir.IntType(8)))
        return str_ptr, ir.PointerType(ir.IntType(8))
    else:
        logger.error(f"Unsupported constant type {ast.dump(expr)}")
        return None


def _handle_attribute_expr(
    func,
    expr: ast.Attribute,
    local_sym_tab: Dict,
    compilation_context,
    builder: ir.IRBuilder,
):
    """Handle ast.Attribute expressions for struct field access."""
    structs_sym_tab = compilation_context.structs_sym_tab
    if isinstance(expr.value, ast.Name):
        var_name = expr.value.id
        attr_name = expr.attr
        if var_name in local_sym_tab:
            var_ptr, var_type, var_metadata = local_sym_tab[var_name]
            logger.info(f"Loading attribute {attr_name} from variable {var_name}")
            logger.info(
                f"Variable type: {var_type}, Variable ptr: {
                    var_ptr
                }, Variable Metadata: {var_metadata}"
            )
            if (
                hasattr(var_metadata, "__module__")
                and var_metadata.__module__ == "vmlinux"
            ):
                # Try vmlinux handler when var_metadata is not a string, but has a module attribute.
                # This has been done to keep everything separate in vmlinux struct handling.
                vmlinux_result = VmlinuxHandlerRegistry.handle_attribute(
                    expr, local_sym_tab, None, builder
                )
                if vmlinux_result is not None:
                    return vmlinux_result
                else:
                    raise RuntimeError("Vmlinux struct did not process successfully")

            elif isinstance(var_metadata, Field):
                logger.error(
                    f"Cannot access field '{attr_name}' on already-loaded field value '{
                        var_name
                    }'"
                )
                return None

            if var_metadata in structs_sym_tab:
                return access_struct_field(
                    builder,
                    var_ptr,
                    var_type,
                    var_metadata,
                    expr.attr,
                    structs_sym_tab,
                    func,
                )
            else:
                logger.error(f"Struct metadata for '{var_name}' not found")
        else:
            logger.error(f"Undefined variable '{var_name}' for attribute access")
    else:
        logger.error("Unsupported attribute base expression type")

    return None


def _handle_deref_call(expr: ast.Call, local_sym_tab: Dict, builder: ir.IRBuilder):
    """Handle deref function calls."""
    logger.info(f"Handling deref {ast.dump(expr)}")
    if len(expr.args) != 1:
        logger.info("deref takes exactly one argument")
        return None

    arg = expr.args[0]
    if (
        isinstance(arg, ast.Call)
        and isinstance(arg.func, ast.Name)
        and arg.func.id == "deref"
    ):
        logger.info("Multiple deref not supported")
        return None

    if isinstance(arg, ast.Name):
        if arg.id in local_sym_tab:
            arg_ptr = local_sym_tab[arg.id].var
        else:
            logger.info(f"Undefined variable {arg.id}")
            return None
    else:
        logger.info("Unsupported argument type for deref")
        return None

    if arg_ptr is None:
        logger.info("Failed to evaluate deref argument")
        return None

    # Load the value from pointer
    val = builder.load(arg_ptr)
    return val, local_sym_tab[arg.id].ir_type


# ============================================================================
# Binary Operations
# ============================================================================


def get_operand_value(func, compilation_context, operand, builder, local_sym_tab):
    """Extract the value from an operand, handling variables and constants."""
    logger.info(f"Getting operand value for: {ast.dump(operand)}")
    if isinstance(operand, ast.Name):
        if operand.id in local_sym_tab:
            var = local_sym_tab[operand.id].var
            var_type = var.type
            base_type, depth = get_base_type_and_depth(var_type)
            logger.info(f"var is {var}, base_type is {base_type}, depth is {depth}")
            if depth == 1:
                val = builder.load(var)
                return val
            else:
                val = deref_to_depth(func, builder, var, depth)
            return val
        elif operand.id in compilation_context.bpf_globals:
            # A @bpfglobal: plain load off the global symbol.
            return builder.load(compilation_context.bpf_globals[operand.id].var)
        else:
            # Check if it's a vmlinux enum/constant
            vmlinux_result = VmlinuxHandlerRegistry.handle_name(operand.id)
            if vmlinux_result is not None:
                val, _ = vmlinux_result
                return val
    elif isinstance(operand, ast.Constant):
        if isinstance(operand.value, int):
            cst = ir.Constant(ir.IntType(64), int(operand.value))
            return cst
        raise TypeError(f"Unsupported constant type: {type(operand.value)}")
    elif isinstance(operand, ast.BinOp):
        res = _handle_binary_op_impl(
            func, compilation_context, operand, builder, local_sym_tab
        )
        return res
    else:
        res = eval_expr(func, compilation_context, builder, operand, local_sym_tab)
        if res is None:
            raise ValueError(f"Failed to evaluate call expression: {operand}")
        val, _ = res
        logger.info(f"Evaluated expr to {val} of type {val.type}")
        base_type, depth = get_base_type_and_depth(val.type)
        if depth > 0:
            val = deref_to_depth(func, builder, val, depth)
        return val
    raise TypeError(f"Unsupported operand type: {type(operand)}")


def _handle_binary_op_impl(func, compilation_context, rval, builder, local_sym_tab):
    op = rval.op
    left = get_operand_value(
        func, compilation_context, rval.left, builder, local_sym_tab
    )
    right = get_operand_value(
        func, compilation_context, rval.right, builder, local_sym_tab
    )
    logger.info(f"left is {left}, right is {right}, op is {op}")

    # NOTE: Before doing the operation, if the operands are integers
    # we always extend them to i64. The assignment to LHS will take
    # care of truncation if needed.
    if isinstance(left.type, ir.IntType) and left.type.width < 64:
        left = builder.sext(left, ir.IntType(64))
    if isinstance(right.type, ir.IntType) and right.type.width < 64:
        right = builder.sext(right, ir.IntType(64))

    # Map AST operation nodes to LLVM IR builder methods
    return apply_binop(builder, op, left, right)


def _handle_binary_op(
    func,
    compilation_context,
    rval,
    builder,
    var_name,
    local_sym_tab,
):
    result = _handle_binary_op_impl(
        func, compilation_context, rval, builder, local_sym_tab
    )
    if var_name and var_name in local_sym_tab:
        logger.info(
            f"Storing result {result} into variable {local_sym_tab[var_name].var}"
        )
        builder.store(result, local_sym_tab[var_name].var)
    return result, result.type


# ============================================================================
# Comparison and Unary Operations
# ============================================================================


def _handle_ctypes_call(
    func,
    compilation_context,
    builder,
    expr,
    local_sym_tab,
):
    """Handle ctypes type constructor calls."""
    if len(expr.args) != 1:
        logger.info("ctypes constructor takes exactly one argument")
        return None

    arg = expr.args[0]
    val = eval_expr(
        func,
        compilation_context,
        builder,
        arg,
        local_sym_tab,
    )
    if val is None:
        logger.info("Failed to evaluate argument to ctypes constructor")
        return None
    call_type = expr.func.id
    expected_type = ctypes_to_ir(call_type)

    # Extract the actual IR value and type
    # val could be (value, ir_type) or (value, Field)
    value, val_type = val

    # If val_type is a Field object (from vmlinux struct), get the actual IR type of the value
    if isinstance(val_type, Field):
        # The value is already the correct IR value (potentially zero-extended)
        # Get the IR type from the value itself
        actual_ir_type = value.type
        logger.info(
            f"Converting vmlinux field {val_type.name} (IR type: {actual_ir_type}) to {
                call_type
            }"
        )
    else:
        actual_ir_type = val_type

    if actual_ir_type != expected_type:
        # NOTE: We are only considering casting to and from int types for now
        if isinstance(actual_ir_type, ir.IntType) and isinstance(
            expected_type, ir.IntType
        ):
            if actual_ir_type.width < expected_type.width:
                value = builder.sext(value, expected_type)
                logger.info(
                    f"Sign-extended from i{actual_ir_type.width} to i{
                        expected_type.width
                    }"
                )
            elif actual_ir_type.width > expected_type.width:
                value = builder.trunc(value, expected_type)
                logger.info(
                    f"Truncated from i{actual_ir_type.width} to i{expected_type.width}"
                )
            else:
                # Same width, just use as-is (e.g., both i64)
                pass
        else:
            raise ValueError(
                f"Type mismatch: expected {expected_type}, got {
                    actual_ir_type
                } (original type: {val_type})"
            )

    return value, expected_type


def _handle_compare(func, compilation_context, builder, cond, local_sym_tab):
    """Handle ast.Compare expressions."""

    if len(cond.ops) != 1 or len(cond.comparators) != 1:
        logger.error("Only single comparisons are supported")
        return None
    lhs = eval_expr(
        func,
        compilation_context,
        builder,
        cond.left,
        local_sym_tab,
    )
    rhs = eval_expr(
        func,
        compilation_context,
        builder,
        cond.comparators[0],
        local_sym_tab,
    )

    if lhs is None or rhs is None:
        logger.error("Failed to evaluate comparison operands")
        return None

    lhs, _ = lhs
    rhs, _ = rhs
    return handle_comparator(func, builder, cond.ops[0], lhs, rhs)


def _handle_unary_op(
    func,
    compilation_context,
    builder,
    expr: ast.UnaryOp,
    local_sym_tab,
):
    """Handle ast.UnaryOp expressions."""
    if not isinstance(expr.op, UNARY_OPS):
        logger.error("Only 'not' and '-' unary operators are supported")
        return None

    operand = get_operand_value(
        func, compilation_context, expr.operand, builder, local_sym_tab
    )
    if operand is None:
        logger.error("Failed to evaluate operand for unary operation")
        return None

    if isinstance(expr.op, ast.Not):
        true_const = ir.Constant(ir.IntType(1), 1)
        result = builder.xor(convert_to_bool(builder, operand), true_const)
        return result, ir.IntType(1)
    elif isinstance(expr.op, ast.USub):
        # Multiply by -1
        neg_one = ir.Constant(ir.IntType(64), -1)
        result = builder.mul(operand, neg_one)
        return result, ir.IntType(64)
    return None


# ============================================================================
# Boolean Operations
# ============================================================================


def _handle_and_op(func, builder, expr, local_sym_tab, compilation_context):
    """Handle `and` boolean operations."""

    logger.debug(f"Handling 'and' operator with {len(expr.values)} operands")

    merge_block = func.append_basic_block(name="and.merge")
    false_block = func.append_basic_block(name="and.false")

    incoming_values = []

    for i, value in enumerate(expr.values):
        is_last = i == len(expr.values) - 1

        # Evaluate current operand
        operand_result = eval_expr(
            func, compilation_context, builder, value, local_sym_tab
        )
        if operand_result is None:
            logger.error(f"Failed to evaluate operand {i} in 'and' expression")
            return None

        operand_val, operand_type = operand_result

        # Convert to boolean if needed
        operand_bool = convert_to_bool(builder, operand_val)
        current_block = builder.block

        if is_last:
            # Last operand: result is this value
            builder.branch(merge_block)
            incoming_values.append((operand_bool, current_block))
        else:
            # Not last: check if true, continue or short-circuit
            next_check = func.append_basic_block(name=f"and.check_{i + 1}")
            builder.cbranch(operand_bool, next_check, false_block)
            builder.position_at_end(next_check)

    # False block: short-circuit with false
    builder.position_at_end(false_block)
    builder.branch(merge_block)
    false_value = ir.Constant(ir.IntType(1), 0)
    incoming_values.append((false_value, false_block))

    # Merge block: phi node
    builder.position_at_end(merge_block)
    phi = builder.phi(ir.IntType(1), name="and.result")
    for val, block in incoming_values:
        phi.add_incoming(val, block)

    logger.debug(f"Generated 'and' with {len(incoming_values)} incoming values")
    return phi, ir.IntType(1)


def _handle_or_op(func, builder, expr, local_sym_tab, compilation_context):
    """Handle `or` boolean operations."""

    logger.debug(f"Handling 'or' operator with {len(expr.values)} operands")

    merge_block = func.append_basic_block(name="or.merge")
    true_block = func.append_basic_block(name="or.true")

    incoming_values = []

    for i, value in enumerate(expr.values):
        is_last = i == len(expr.values) - 1

        # Evaluate current operand
        operand_result = eval_expr(
            func, compilation_context, builder, value, local_sym_tab
        )
        if operand_result is None:
            logger.error(f"Failed to evaluate operand {i} in 'or' expression")
            return None

        operand_val, operand_type = operand_result

        # Convert to boolean if needed
        operand_bool = convert_to_bool(builder, operand_val)
        current_block = builder.block

        if is_last:
            # Last operand: result is this value
            builder.branch(merge_block)
            incoming_values.append((operand_bool, current_block))
        else:
            # Not last: check if false, continue or short-circuit
            next_check = func.append_basic_block(name=f"or.check_{i + 1}")
            builder.cbranch(operand_bool, true_block, next_check)
            builder.position_at_end(next_check)

    # True block: short-circuit with true
    builder.position_at_end(true_block)
    builder.branch(merge_block)
    true_value = ir.Constant(ir.IntType(1), 1)
    incoming_values.append((true_value, true_block))

    # Merge block: phi node
    builder.position_at_end(merge_block)
    phi = builder.phi(ir.IntType(1), name="or.result")
    for val, block in incoming_values:
        phi.add_incoming(val, block)

    logger.debug(f"Generated 'or' with {len(incoming_values)} incoming values")
    return phi, ir.IntType(1)


def _handle_boolean_op(
    func,
    compilation_context,
    builder,
    expr: ast.BoolOp,
    local_sym_tab,
):
    """Handle `and` and `or` boolean operations."""

    if not isinstance(expr.op, BOOL_OPS):
        logger.error(f"Unsupported boolean operator: {type(expr.op).__name__}")
        return None
    if isinstance(expr.op, ast.And):
        return _handle_and_op(func, builder, expr, local_sym_tab, compilation_context)
    elif isinstance(expr.op, ast.Or):
        return _handle_or_op(func, builder, expr, local_sym_tab, compilation_context)
    else:
        logger.error(f"Unsupported boolean operator: {type(expr.op).__name__}")
        return None


# ============================================================================
# Struct casting (including vmlinux struct casting)
# ============================================================================


def _handle_vmlinux_cast(
    func,
    compilation_context,
    builder,
    expr,
    local_sym_tab,
):
    # handle expressions such as struct_request(ctx.di) where struct_request is a vmlinux
    # struct and ctx.di is a pointer to a struct but is actually represented as a c_uint64
    # which needs to be cast to a pointer. This is also a field of another vmlinux struct
    """Handle vmlinux struct cast expressions like struct_request(ctx.di)."""
    if len(expr.args) != 1:
        logger.info("vmlinux struct cast takes exactly one argument")
        return None

    # Get the struct name
    struct_name = expr.func.id

    # Evaluate the argument (e.g., ctx.di which is a c_uint64)
    arg_result = eval_expr(
        func,
        compilation_context,
        builder,
        expr.args[0],
        local_sym_tab,
    )

    if arg_result is None:
        logger.info("Failed to evaluate argument to vmlinux struct cast")
        return None

    arg_val, arg_type = arg_result
    # Get the vmlinux struct type
    vmlinux_struct_type = VmlinuxHandlerRegistry.get_struct_type(struct_name)
    if vmlinux_struct_type is None:
        logger.error(f"Failed to get vmlinux struct type for {struct_name}")
        return None
    # Cast the integer/value to a pointer to the struct
    # If arg_val is an integer type, we need to inttoptr it
    ptr_type = ir.PointerType()
    # TODO: add a field value type check here
    # print(arg_type)
    if isinstance(arg_type, Field):
        if ctypes_to_ir(arg_type.type.__name__):
            # Cast integer to pointer
            casted_ptr = builder.inttoptr(arg_val, ptr_type)
        else:
            logger.error(f"Unsupported type for vmlinux cast: {arg_type}")
            return None
    else:
        casted_ptr = builder.inttoptr(arg_val, ptr_type)

    return casted_ptr, vmlinux_struct_type


def _handle_user_defined_struct_cast(
    func,
    compilation_context,
    builder,
    expr,
    local_sym_tab,
):
    """Handle user-defined struct cast expressions like iphdr(nh).

    This casts a pointer/integer value to a pointer to the user-defined struct,
    similar to how vmlinux struct casts work but for user-defined @struct types.
    """
    structs_sym_tab = compilation_context.structs_sym_tab
    if len(expr.args) != 1:
        logger.info("User-defined struct cast takes exactly one argument")
        return None

    # Get the struct name
    struct_name = expr.func.id

    if struct_name not in structs_sym_tab:
        logger.error(f"Struct {struct_name} not found in structs_sym_tab")
        return None

    struct_info = structs_sym_tab[struct_name]

    # Evaluate the argument (e.g.,
    # an address/pointer value)
    arg_result = eval_expr(
        func,
        compilation_context,
        builder,
        expr.args[0],
        local_sym_tab,
    )

    if arg_result is None:
        logger.info("Failed to evaluate argument to user-defined struct cast")
        return None

    arg_val, arg_type = arg_result

    # Cast the integer/pointer value to a pointer to the struct type
    # The struct pointer type is a pointer to the struct's IR type
    struct_ptr_type = ir.PointerType(struct_info.ir_type)

    # If arg_val is an integer type (like i64), convert to pointer using inttoptr
    if isinstance(arg_val.type, ir.IntType):
        casted_ptr = builder.inttoptr(arg_val, struct_ptr_type)
        logger.info(f"Cast integer to pointer for struct {struct_name}")
    elif isinstance(arg_val.type, ir.PointerType):
        # If already a pointer, bitcast to the struct pointer type
        casted_ptr = builder.bitcast(arg_val, struct_ptr_type)
        logger.info(f"Bitcast pointer to struct pointer for {struct_name}")
    else:
        logger.error(f"Unsupported type for user-defined struct cast: {arg_val.type}")
        return None

    return casted_ptr, struct_name


# ============================================================================
# Expression Dispatcher
# ============================================================================


def eval_expr(
    func,
    compilation_context,
    builder,
    expr,
    local_sym_tab,
):
    structs_sym_tab = compilation_context.structs_sym_tab

    logger.info(f"Evaluating expression: {ast.dump(expr)}")
    if isinstance(expr, ast.Name):
        return _handle_name_expr(expr, compilation_context, local_sym_tab, builder)
    elif isinstance(expr, ast.Constant):
        return _handle_constant_expr(compilation_context, builder, expr)
    elif isinstance(expr, ast.Call):
        if isinstance(expr.func, ast.Name) and VmlinuxHandlerRegistry.is_vmlinux_struct(
            expr.func.id
        ):
            return _handle_vmlinux_cast(
                func,
                compilation_context,
                builder,
                expr,
                local_sym_tab,
            )
        if isinstance(expr.func, ast.Name) and expr.func.id == "deref":
            return _handle_deref_call(expr, local_sym_tab, builder)

        if isinstance(expr.func, ast.Name) and is_ctypes(expr.func.id):
            return _handle_ctypes_call(
                func,
                compilation_context,
                builder,
                expr,
                local_sym_tab,
            )
        if isinstance(expr.func, ast.Name) and (expr.func.id in structs_sym_tab):
            return _handle_user_defined_struct_cast(
                func,
                compilation_context,
                builder,
                expr,
                local_sym_tab,
            )

        # NOTE: Updated handle_call signature
        result = CallHandlerRegistry.handle_call(
            expr, compilation_context, builder, func, local_sym_tab
        )
        if result is not None:
            return result

        logger.warning(f"Unknown call: {ast.dump(expr)}")
        return None
    elif isinstance(expr, ast.Attribute):
        return _handle_attribute_expr(
            func, expr, local_sym_tab, compilation_context, builder
        )
    elif isinstance(expr, ast.BinOp):
        return _handle_binary_op(
            func,
            compilation_context,
            expr,
            builder,
            None,
            local_sym_tab,
        )
    elif isinstance(expr, ast.Compare):
        return _handle_compare(func, compilation_context, builder, expr, local_sym_tab)
    elif isinstance(expr, ast.UnaryOp):
        return _handle_unary_op(func, compilation_context, builder, expr, local_sym_tab)
    elif isinstance(expr, ast.BoolOp):
        return _handle_boolean_op(
            func, compilation_context, builder, expr, local_sym_tab
        )
    logger.info("Unsupported expression evaluation")
    return None


def handle_expr(
    func,
    compilation_context,
    builder,
    expr,
    local_sym_tab,
):
    """Handle expression statements in the function body."""
    logger.info(f"Handling expression: {ast.dump(expr)}")
    call = expr.value
    if isinstance(call, ast.Call):
        eval_expr(
            func,
            compilation_context,
            builder,
            call,
            local_sym_tab,
        )
    else:
        logger.info("Unsupported expression type")

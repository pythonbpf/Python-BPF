import ast
from llvmlite import ir
from logging import Logger
import logging
from typing import Dict

from pythonbpf.type_deducer import ctypes_to_ir, is_ctypes
from .call_registry import CallHandlerRegistry
from .type_normalization import (
    convert_to_bool,
    handle_comparator,
    get_base_type_and_depth,
    deref_to_depth,
)
from .vmlinux_registry import VmlinuxHandlerRegistry

logger: Logger = logging.getLogger(__name__)

# ============================================================================
# Leaf Handlers (No Recursive eval_expr calls)
# ============================================================================


def _handle_name_expr(expr: ast.Name, local_sym_tab: Dict, builder: ir.IRBuilder):
    """Handle ast.Name expressions."""
    if expr.id in local_sym_tab:
        var = local_sym_tab[expr.id].var
        val = builder.load(var)
        return val, local_sym_tab[expr.id].ir_type
    else:
        # Check if it's a vmlinux enum/constant
        vmlinux_result = VmlinuxHandlerRegistry.handle_name(expr.id)
        if vmlinux_result is not None:
            return vmlinux_result

        raise SyntaxError(f"Undefined variable {expr.id}")


def _handle_constant_expr(module, builder, expr: ast.Constant):
    """Handle ast.Constant expressions."""
    if isinstance(expr.value, int) or isinstance(expr.value, bool):
        return ir.Constant(ir.IntType(64), int(expr.value)), ir.IntType(64)
    elif isinstance(expr.value, str):
        str_name = f".str.{id(expr)}"
        str_bytes = expr.value.encode("utf-8") + b"\x00"
        str_type = ir.ArrayType(ir.IntType(8), len(str_bytes))
        str_constant = ir.Constant(str_type, bytearray(str_bytes))

        # Create global variable
        global_str = ir.GlobalVariable(module, str_type, name=str_name)
        global_str.linkage = "internal"
        global_str.global_constant = True
        global_str.initializer = str_constant

        str_ptr = builder.bitcast(global_str, ir.PointerType(ir.IntType(8)))
        return str_ptr, ir.PointerType(ir.IntType(8))
    else:
        logger.error(f"Unsupported constant type {ast.dump(expr)}")
        return None


def _handle_attribute_expr(
    expr: ast.Attribute,
    local_sym_tab: Dict,
    structs_sym_tab: Dict,
    builder: ir.IRBuilder,
):
    """Handle ast.Attribute expressions for struct field access."""
    if isinstance(expr.value, ast.Name):
        var_name = expr.value.id
        attr_name = expr.attr
        if var_name in local_sym_tab:
            var_ptr, var_type, var_metadata = local_sym_tab[var_name]
            logger.info(f"Loading attribute {attr_name} from variable {var_name}")
            logger.info(f"Variable type: {var_type}, Variable ptr: {var_ptr}")
            metadata = structs_sym_tab[var_metadata]
            if attr_name in metadata.fields:
                gep = metadata.gep(builder, var_ptr, attr_name)
                val = builder.load(gep)
                field_type = metadata.field_type(attr_name)
                return val, field_type

        # Try vmlinux handler as fallback
        vmlinux_result = VmlinuxHandlerRegistry.handle_attribute(
            expr, local_sym_tab, None, builder
        )
        if vmlinux_result is not None:
            return vmlinux_result
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


def get_operand_value(
    func, module, operand, builder, local_sym_tab, map_sym_tab, structs_sym_tab=None
):
    """Extract the value from an operand, handling variables and constants."""
    logger.info(f"Getting operand value for: {ast.dump(operand)}")
    if isinstance(operand, ast.Name):
        if operand.id in local_sym_tab:
            var = local_sym_tab[operand.id].var
            var_type = var.type
            base_type, depth = get_base_type_and_depth(var_type)
            logger.info(f"var is {var}, base_type is {base_type}, depth is {depth}")
            val = deref_to_depth(func, builder, var, depth)
            return val
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
            func, module, operand, builder, local_sym_tab, map_sym_tab, structs_sym_tab
        )
        return res
    else:
        res = eval_expr(
            func, module, builder, operand, local_sym_tab, map_sym_tab, structs_sym_tab
        )
        if res is None:
            raise ValueError(f"Failed to evaluate call expression: {operand}")
        val, _ = res
        logger.info(f"Evaluated expr to {val} of type {val.type}")
        base_type, depth = get_base_type_and_depth(val.type)
        if depth > 0:
            val = deref_to_depth(func, builder, val, depth)
        return val
    raise TypeError(f"Unsupported operand type: {type(operand)}")


def _handle_binary_op_impl(
    func, module, rval, builder, local_sym_tab, map_sym_tab, structs_sym_tab=None
):
    op = rval.op
    left = get_operand_value(
        func, module, rval.left, builder, local_sym_tab, map_sym_tab, structs_sym_tab
    )
    right = get_operand_value(
        func, module, rval.right, builder, local_sym_tab, map_sym_tab, structs_sym_tab
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
    op_map = {
        ast.Add: builder.add,
        ast.Sub: builder.sub,
        ast.Mult: builder.mul,
        ast.Div: builder.sdiv,
        ast.Mod: builder.srem,
        ast.LShift: builder.shl,
        ast.RShift: builder.lshr,
        ast.BitOr: builder.or_,
        ast.BitXor: builder.xor,
        ast.BitAnd: builder.and_,
        ast.FloorDiv: builder.udiv,
    }

    if type(op) in op_map:
        result = op_map[type(op)](left, right)
        return result
    else:
        raise SyntaxError("Unsupported binary operation")


def _handle_binary_op(
    func,
    module,
    rval,
    builder,
    var_name,
    local_sym_tab,
    map_sym_tab,
    structs_sym_tab=None,
):
    result = _handle_binary_op_impl(
        func, module, rval, builder, local_sym_tab, map_sym_tab, structs_sym_tab
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
    module,
    builder,
    expr,
    local_sym_tab,
    map_sym_tab,
    structs_sym_tab=None,
):
    """Handle ctypes type constructor calls."""
    if len(expr.args) != 1:
        logger.info("ctypes constructor takes exactly one argument")
        return None

    arg = expr.args[0]
    val = eval_expr(
        func,
        module,
        builder,
        arg,
        local_sym_tab,
        map_sym_tab,
        structs_sym_tab,
    )
    if val is None:
        logger.info("Failed to evaluate argument to ctypes constructor")
        return None
    call_type = expr.func.id
    expected_type = ctypes_to_ir(call_type)

    if val[1] != expected_type:
        # NOTE: We are only considering casting to and from int types for now
        if isinstance(val[1], ir.IntType) and isinstance(expected_type, ir.IntType):
            if val[1].width < expected_type.width:
                val = (builder.sext(val[0], expected_type), expected_type)
            else:
                val = (builder.trunc(val[0], expected_type), expected_type)
        else:
            raise ValueError(f"Type mismatch: expected {expected_type}, got {val[1]}")
    return val


def _handle_compare(
    func, module, builder, cond, local_sym_tab, map_sym_tab, structs_sym_tab=None
):
    """Handle ast.Compare expressions."""

    if len(cond.ops) != 1 or len(cond.comparators) != 1:
        logger.error("Only single comparisons are supported")
        return None
    lhs = eval_expr(
        func,
        module,
        builder,
        cond.left,
        local_sym_tab,
        map_sym_tab,
        structs_sym_tab,
    )
    rhs = eval_expr(
        func,
        module,
        builder,
        cond.comparators[0],
        local_sym_tab,
        map_sym_tab,
        structs_sym_tab,
    )

    if lhs is None or rhs is None:
        logger.error("Failed to evaluate comparison operands")
        return None

    lhs, _ = lhs
    rhs, _ = rhs
    return handle_comparator(func, builder, cond.ops[0], lhs, rhs)


def _handle_unary_op(
    func,
    module,
    builder,
    expr: ast.UnaryOp,
    local_sym_tab,
    map_sym_tab,
    structs_sym_tab=None,
):
    """Handle ast.UnaryOp expressions."""
    if not isinstance(expr.op, ast.Not) and not isinstance(expr.op, ast.USub):
        logger.error("Only 'not' and '-' unary operators are supported")
        return None

    operand = get_operand_value(
        func, module, expr.operand, builder, local_sym_tab, map_sym_tab, structs_sym_tab
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


def _handle_and_op(func, builder, expr, local_sym_tab, map_sym_tab, structs_sym_tab):
    """Handle `and` boolean operations."""

    logger.debug(f"Handling 'and' operator with {len(expr.values)} operands")

    merge_block = func.append_basic_block(name="and.merge")
    false_block = func.append_basic_block(name="and.false")

    incoming_values = []

    for i, value in enumerate(expr.values):
        is_last = i == len(expr.values) - 1

        # Evaluate current operand
        operand_result = eval_expr(
            func, None, builder, value, local_sym_tab, map_sym_tab, structs_sym_tab
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


def _handle_or_op(func, builder, expr, local_sym_tab, map_sym_tab, structs_sym_tab):
    """Handle `or` boolean operations."""

    logger.debug(f"Handling 'or' operator with {len(expr.values)} operands")

    merge_block = func.append_basic_block(name="or.merge")
    true_block = func.append_basic_block(name="or.true")

    incoming_values = []

    for i, value in enumerate(expr.values):
        is_last = i == len(expr.values) - 1

        # Evaluate current operand
        operand_result = eval_expr(
            func, None, builder, value, local_sym_tab, map_sym_tab, structs_sym_tab
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
    module,
    builder,
    expr: ast.BoolOp,
    local_sym_tab,
    map_sym_tab,
    structs_sym_tab=None,
):
    """Handle `and` and `or` boolean operations."""

    if isinstance(expr.op, ast.And):
        return _handle_and_op(
            func, builder, expr, local_sym_tab, map_sym_tab, structs_sym_tab
        )
    elif isinstance(expr.op, ast.Or):
        return _handle_or_op(
            func, builder, expr, local_sym_tab, map_sym_tab, structs_sym_tab
        )
    else:
        logger.error(f"Unsupported boolean operator: {type(expr.op).__name__}")
        return None


# ============================================================================
# Expression Dispatcher
# ============================================================================


def eval_expr(
    func,
    module,
    builder,
    expr,
    local_sym_tab,
    map_sym_tab,
    structs_sym_tab=None,
):
    logger.info(f"Evaluating expression: {ast.dump(expr)}")
    if isinstance(expr, ast.Name):
        return _handle_name_expr(expr, local_sym_tab, builder)
    elif isinstance(expr, ast.Constant):
        return _handle_constant_expr(module, builder, expr)
    elif isinstance(expr, ast.Call):
        if isinstance(expr.func, ast.Name) and expr.func.id == "deref":
            return _handle_deref_call(expr, local_sym_tab, builder)

        if isinstance(expr.func, ast.Name) and is_ctypes(expr.func.id):
            return _handle_ctypes_call(
                func,
                module,
                builder,
                expr,
                local_sym_tab,
                map_sym_tab,
                structs_sym_tab,
            )

        result = CallHandlerRegistry.handle_call(
            expr, module, builder, func, local_sym_tab, map_sym_tab, structs_sym_tab
        )
        if result is not None:
            return result

        logger.warning(f"Unknown call: {ast.dump(expr)}")
        return None
    elif isinstance(expr, ast.Attribute):
        return _handle_attribute_expr(expr, local_sym_tab, structs_sym_tab, builder)
    elif isinstance(expr, ast.BinOp):
        return _handle_binary_op(
            func,
            module,
            expr,
            builder,
            None,
            local_sym_tab,
            map_sym_tab,
            structs_sym_tab,
        )
    elif isinstance(expr, ast.Compare):
        return _handle_compare(
            func, module, builder, expr, local_sym_tab, map_sym_tab, structs_sym_tab
        )
    elif isinstance(expr, ast.UnaryOp):
        return _handle_unary_op(
            func, module, builder, expr, local_sym_tab, map_sym_tab, structs_sym_tab
        )
    elif isinstance(expr, ast.BoolOp):
        return _handle_boolean_op(
            func, module, builder, expr, local_sym_tab, map_sym_tab, structs_sym_tab
        )
    logger.info("Unsupported expression evaluation")
    return None


def handle_expr(
    func,
    module,
    builder,
    expr,
    local_sym_tab,
    map_sym_tab,
    structs_sym_tab,
):
    """Handle expression statements in the function body."""
    logger.info(f"Handling expression: {ast.dump(expr)}")
    call = expr.value
    if isinstance(call, ast.Call):
        eval_expr(
            func,
            module,
            builder,
            call,
            local_sym_tab,
            map_sym_tab,
            structs_sym_tab,
        )
    else:
        logger.info("Unsupported expression type")

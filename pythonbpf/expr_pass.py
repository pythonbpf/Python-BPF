import ast
from llvmlite import ir
from logging import Logger
import logging
from typing import Dict

from .type_deducer import ctypes_to_ir, is_ctypes

logger: Logger = logging.getLogger(__name__)


def _handle_name_expr(expr: ast.Name, local_sym_tab: Dict, builder: ir.IRBuilder):
    """Handle ast.Name expressions."""
    if expr.id in local_sym_tab:
        var = local_sym_tab[expr.id].var
        val = builder.load(var)
        return val, local_sym_tab[expr.id].ir_type
    else:
        logger.info(f"Undefined variable {expr.id}")
        return None


def _handle_constant_expr(expr: ast.Constant):
    """Handle ast.Constant expressions."""
    if isinstance(expr.value, int) or isinstance(expr.value, bool):
        return ir.Constant(ir.IntType(64), int(expr.value)), ir.IntType(64)
    else:
        logger.error("Unsupported constant type")
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


def _get_base_type_and_depth(ir_type):
    """Get the base type for pointer types."""
    cur_type = ir_type
    depth = 0
    while isinstance(cur_type, ir.PointerType):
        depth += 1
        cur_type = cur_type.pointee
    return cur_type, depth


def _deref_to_depth(builder, val, target_depth):
    """Dereference a pointer to a certain depth."""

    cur_val = val
    for _ in range(target_depth):
        if not isinstance(val.type, ir.PointerType):
            logger.error("Cannot dereference further, non-pointer type")
            return None
        cur_val = builder.load(cur_val)
    return cur_val


def _normalize_types(builder, lhs, rhs):
    """Normalize types for comparison."""

    if isinstance(lhs.type, ir.IntType) and isinstance(rhs.type, ir.IntType):
        if lhs.type.width < rhs.type.width:
            lhs = builder.sext(lhs, rhs.type)
        else:
            rhs = builder.sext(rhs, lhs.type)
        return lhs, rhs

    logger.error(f"Type mismatch: {lhs.type} vs {rhs.type}")
    return None, None


def _handle_comparator(builder, op, lhs, rhs):
    """Handle comparison operations."""

    # NOTE: For now assume same types
    if lhs.type != rhs.type:
        lhs, rhs = _normalize_types(builder, lhs, rhs)

    if lhs is None or rhs is None:
        return None

    comparison_ops = {
        ast.Eq: "==",
        ast.NotEq: "!=",
        ast.Lt: "<",
        ast.LtE: "<=",
        ast.Gt: ">",
        ast.GtE: ">=",
    }

    if type(op) not in comparison_ops:
        logger.error(f"Unsupported comparison operator: {type(op)}")
        return None

    predicate = comparison_ops[type(op)]
    result = builder.icmp_signed(predicate, lhs, rhs)
    logger.debug(f"Comparison result: {result}")
    return result, ir.IntType(1)


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
    return _handle_comparator(builder, cond.ops[0], lhs, rhs)


def convert_to_bool(builder, val):
    if val.type == ir.IntType(1):
        return val
    if isinstance(val.type, ir.PointerType):
        zero = ir.Constant(val.type, None)
    else:
        zero = ir.Constant(val.type, 0)
    return builder.icmp_signed("!=", val, zero)


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
    if not isinstance(expr.op, ast.Not):
        logger.error("Only 'not' unary operator is supported")
        return None

    operand = eval_expr(
        func, module, builder, expr.operand, local_sym_tab, map_sym_tab, structs_sym_tab
    )
    if operand is None:
        logger.error("Failed to evaluate operand for unary operation")
        return None

    operand_val, operand_type = operand
    true_const = ir.Constant(ir.IntType(1), 1)
    result = builder.xor(convert_to_bool(builder, operand_val), true_const)
    return result, ir.IntType(1)


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
        return _handle_constant_expr(expr)
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

        # delayed import to avoid circular dependency
        from pythonbpf.helper import HelperHandlerRegistry, handle_helper_call

        if isinstance(expr.func, ast.Name) and HelperHandlerRegistry.has_handler(
            expr.func.id
        ):
            return handle_helper_call(
                expr,
                module,
                builder,
                func,
                local_sym_tab,
                map_sym_tab,
                structs_sym_tab,
            )
        elif isinstance(expr.func, ast.Attribute):
            logger.info(f"Handling method call: {ast.dump(expr.func)}")
            if isinstance(expr.func.value, ast.Call) and isinstance(
                expr.func.value.func, ast.Name
            ):
                method_name = expr.func.attr
                if HelperHandlerRegistry.has_handler(method_name):
                    return handle_helper_call(
                        expr,
                        module,
                        builder,
                        func,
                        local_sym_tab,
                        map_sym_tab,
                        structs_sym_tab,
                    )
            elif isinstance(expr.func.value, ast.Name):
                obj_name = expr.func.value.id
                method_name = expr.func.attr
                if obj_name in map_sym_tab:
                    if HelperHandlerRegistry.has_handler(method_name):
                        return handle_helper_call(
                            expr,
                            module,
                            builder,
                            func,
                            local_sym_tab,
                            map_sym_tab,
                            structs_sym_tab,
                        )
    elif isinstance(expr, ast.Attribute):
        return _handle_attribute_expr(expr, local_sym_tab, structs_sym_tab, builder)
    elif isinstance(expr, ast.BinOp):
        from pythonbpf.binary_ops import handle_binary_op

        return handle_binary_op(expr, builder, None, local_sym_tab)
    elif isinstance(expr, ast.Compare):
        return _handle_compare(
            func, module, builder, expr, local_sym_tab, map_sym_tab, structs_sym_tab
        )
    elif isinstance(expr, ast.UnaryOp):
        return _handle_unary_op(
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

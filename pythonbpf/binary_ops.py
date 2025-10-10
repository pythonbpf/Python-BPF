import ast
from llvmlite import ir
from logging import Logger
import logging

from pythonbpf.expr import get_base_type_and_depth, deref_to_depth, eval_expr

logger: Logger = logging.getLogger(__name__)


def get_operand_value(func, operand, builder, local_sym_tab):
    """Extract the value from an operand, handling variables and constants."""
    logger.info(f"Getting operand value for: {ast.dump(operand)}")
    if isinstance(operand, ast.Name):
        if operand.id in local_sym_tab:
            var = local_sym_tab[operand.id].var
            var_type = var.type
            base_type, depth = get_base_type_and_depth(var_type)
            logger.info(f"var is {var}, base_type is {base_type}, depth is {depth}")
            val = deref_to_depth(func, builder, var, depth)
            return val, [val], var
        raise ValueError(f"Undefined variable: {operand.id}")
    elif isinstance(operand, ast.Constant):
        if isinstance(operand.value, int):
            cst = ir.Constant(ir.IntType(64), int(operand.value))
            return cst, [cst], None
        raise TypeError(f"Unsupported constant type: {type(operand.value)}")
    elif isinstance(operand, ast.BinOp):
        res = handle_binary_op_impl(func, operand, builder, local_sym_tab)
        return res, [res], None
    elif isinstance(operand, ast.Call):
        res = eval_expr(func, None, builder, operand, local_sym_tab, {}, {})
        if res is None:
            raise ValueError(f"Failed to evaluate call expression: {operand}")
        val, val_type = res
        return val, [val], None
    raise TypeError(f"Unsupported operand type: {type(operand)}")


def store_through_chain(value, chain, builder):
    """Store a value through a pointer chain."""
    if not chain or len(chain) < 2:
        raise ValueError("Pointer chain must have at least two elements")

    for ptr in reversed(chain[1:]):
        builder.store(value, ptr)
        value = ptr


def handle_binary_op_impl(func, rval, builder, local_sym_tab):
    op = rval.op
    left, lchain, _ = get_operand_value(func, rval.left, builder, local_sym_tab)
    right, rchain, _ = get_operand_value(func, rval.right, builder, local_sym_tab)
    logger.info(f"left is {left}, right is {right}, op is {op}")

    logger.info(f"left chain: {lchain}, right chain: {rchain}")

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


def handle_binary_op(func, rval, builder, var_name, local_sym_tab):
    result = handle_binary_op_impl(func, rval, builder, local_sym_tab)
    if var_name and var_name in local_sym_tab:
        logger.info(
            f"Storing result {result} into variable {local_sym_tab[var_name].var}"
        )
        builder.store(result, local_sym_tab[var_name].var)
    return result, result.type

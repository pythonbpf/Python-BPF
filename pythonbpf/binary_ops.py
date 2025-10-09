import ast
from llvmlite import ir
from logging import Logger
import logging

logger: Logger = logging.getLogger(__name__)


def recursive_dereferencer(var, builder):
    """dereference until primitive type comes out"""
    # TODO: Not worrying about stack overflow for now
    logger.info(f"Dereferencing {var}, type is {var.type}")
    if isinstance(var.type, ir.PointerType):
        a = builder.load(var)
        return recursive_dereferencer(a, builder)
    elif isinstance(var.type, ir.IntType):
        return var
    else:
        raise TypeError(f"Unsupported type for dereferencing: {var.type}")


def deref_to_val(var, builder):
    """Dereference a variable to get its value and pointer chain."""
    logger.info(f"Dereferencing {var}, type is {var.type}")

    chain = [var]
    cur = var

    while isinstance(cur.type, ir.PointerType):
        cur = builder.load(cur)
        chain.append(cur)

    if isinstance(cur.type, ir.IntType):
        logger.info(f"dereference chain: {chain}")
        return cur, chain
    else:
        raise TypeError(f"Unsupported type for dereferencing: {cur.type}")


def get_operand_value(operand, builder, local_sym_tab):
    """Extract the value from an operand, handling variables and constants."""
    if isinstance(operand, ast.Name):
        if operand.id in local_sym_tab:
            var = local_sym_tab[operand.id].var
            val, chain = deref_to_val(var, builder)
            return val, chain, var
        raise ValueError(f"Undefined variable: {operand.id}")
    elif isinstance(operand, ast.Constant):
        if isinstance(operand.value, int):
            cst = ir.Constant(ir.IntType(64), operand.value)
            return cst, [cst], None
        raise TypeError(f"Unsupported constant type: {type(operand.value)}")
    elif isinstance(operand, ast.BinOp):
        res = handle_binary_op_impl(operand, builder, local_sym_tab)
        return res, [res], None
    raise TypeError(f"Unsupported operand type: {type(operand)}")


def handle_binary_op_impl(rval, builder, local_sym_tab):
    op = rval.op
    left = get_operand_value(rval.left, builder, local_sym_tab)
    right = get_operand_value(rval.right, builder, local_sym_tab)
    logger.info(f"left is {left}, right is {right}, op is {op}")

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


def handle_binary_op(rval, builder, var_name, local_sym_tab):
    result = handle_binary_op_impl(rval, builder, local_sym_tab)
    if var_name and var_name in local_sym_tab:
        logger.info(
            f"Storing result {result} into variable {local_sym_tab[var_name].var}"
        )
        builder.store(result, local_sym_tab[var_name].var)
    return result, result.type

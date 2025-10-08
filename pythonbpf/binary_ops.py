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


def get_operand_value(operand, builder, local_sym_tab):
    """Extract the value from an operand, handling variables and constants."""
    if isinstance(operand, ast.Name):
        if operand.id in local_sym_tab:
            return recursive_dereferencer(local_sym_tab[operand.id].var, builder)
        raise ValueError(f"Undefined variable: {operand.id}")
    elif isinstance(operand, ast.Constant):
        if isinstance(operand.value, int):
            return ir.Constant(ir.IntType(64), operand.value)
        raise TypeError(f"Unsupported constant type: {type(operand.value)}")
    elif isinstance(operand, ast.BinOp):
        return handle_binary_op_impl(operand, builder, local_sym_tab)
    raise TypeError(f"Unsupported operand type: {type(operand)}")


def handle_binary_op_impl(rval, builder, local_sym_tab):
    """
    Handle binary operations and emit corresponding LLVM IR instructions.
    
    Args:
        rval: The AST BinOp node representing the binary operation
        builder: LLVM IR builder for emitting instructions
        local_sym_tab: Symbol table mapping variable names to their IR representations
    
    Returns:
        The LLVM IR value representing the result of the binary operation
    """
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
    """
    Handle binary operations and optionally store the result to a variable.
    
    Args:
        rval: The AST BinOp node representing the binary operation
        builder: LLVM IR builder for emitting instructions
        var_name: Optional variable name to store the result
        local_sym_tab: Symbol table mapping variable names to their IR representations
    
    Returns:
        A tuple of (result_value, result_type)
    """
    result = handle_binary_op_impl(rval, builder, local_sym_tab)
    if var_name and var_name in local_sym_tab:
        logger.info(
            f"Storing result {result} into variable {local_sym_tab[var_name].var}"
        )
        builder.store(result, local_sym_tab[var_name].var)
    return result, result.type
